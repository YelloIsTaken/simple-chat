"""A link: one authenticated, encrypted TCP connection to one contact.

A link lives as long as both apps are running and the network holds. While
it's up, the contact shows as online. messenger.py keeps one link per online
contact, and decides who to trust and what to do with incoming messages; a
Link only speaks the protocol (PROTOCOL.md) and reports to `LinkEvents`.

Threads per link:
* the receive loop (`run`): reads and handles frames in order;
* the sender: sends queued frames one at a time, so callers never block;
* the keepalive: PINGs a quiet link and closes a dead one;
* one thread per outgoing file.

LinkEvents callbacks are called from these threads.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

from .channel import (
    T_ACK, T_BYE, T_FILE_ACCEPT, T_FILE_CANCEL, T_FILE_CHUNK, T_FILE_END, T_FILE_OFFER,
    T_FILE_REJECT, T_NICK, T_PING, T_PONG, T_READY, T_TEXT, ChannelError, SecureChannel,
)
from .framing import ConnectionClosed, FrameError
from .handshake import ROLE_INITIATOR, HandshakeError, perform_handshake
from .identity import Identity, fingerprint
from .textutil import clean_nick, clean_text, human_size, safe_filename, unique_path

HANDSHAKE_TIMEOUT = 20  # seconds
PING_AFTER = 20         # send a PING when nothing was sent for this long
DEAD_AFTER = 60         # close the link when nothing was received for this long
CHUNK_SIZE = 64 * 1024
MAX_MESSAGE = 16 * 1024


class WrongPeer(Exception):
    """We dialled a contact, but someone with a different key answered."""


@dataclass(frozen=True)
class FileOffer:
    name: str
    size: int


@dataclass(frozen=True)
class Transfer:
    """Progress of one file transfer, for progress bars."""
    id: str            # unique per link and direction, e.g. "in-3"
    name: str
    size: int
    done: int
    outgoing: bool


class LinkEvents(Protocol):
    def verify(self, link: Link) -> str | None:
        """Called before READY: None to accept the peer, or the reason to refuse."""

    def link_up(self, link: Link) -> None: ...

    def link_down(self, link: Link, reason: str | None) -> None: ...

    def text(self, link: Link, mid: str, sent: str, text: str) -> None:
        """Store the message; the link ACKs it after this returns."""

    def ack(self, link: Link, mid: str) -> None: ...

    def nick(self, link: Link, nick: str) -> None: ...

    def file_offer(self, link: Link, offer: FileOffer | None) -> None: ...

    def transfer(self, link: Link, progress: Transfer, finished: bool) -> None: ...

    def file_done(self, link: Link, text: str, ok: bool, saved: Path | None = None) -> None:
        """A transfer finished (ok) or failed; text describes it."""

    def notice(self, link: Link, text: str, level: str = "info") -> None: ...


@dataclass
class _Incoming:
    id: int
    name: str
    size: int
    accepted: bool = False
    final_path: Path | None = None
    part_path: Path | None = None
    handle: object = None
    received: int = 0
    hasher: object = field(default_factory=hashlib.sha256)
    last_report: float = 0.0

    def discard(self) -> None:
        if self.handle:
            self.handle.close()
            self.handle = None
        if self.part_path and self.part_path.exists():
            self.part_path.unlink()


@dataclass
class _Outgoing:
    id: int
    path: Path
    size: int
    cancelled: bool = False


class Link:
    def __init__(self, sock: socket.socket, role: bytes, address: str, identity: Identity,
                 expected_key: bytes | None, nick: str, listen_port: int, download_dir: Path,
                 events: LinkEvents, manual_host: str | None = None):
        self.sock = sock
        self.role = role
        self.address = address              # "ip:port" of the TCP connection
        self.identity = identity
        self.expected_key = expected_key    # set when we dialled a known contact
        self.manual_host = manual_host      # "host:port" the user typed, for the changed-key check
        self.nick = nick
        self.listen_port = listen_port
        self.download_dir = download_dir
        self.events = events

        self.channel: SecureChannel | None = None
        self.peer_public = b""
        self.peer_nick = "peer"
        self.peer_port: int | None = None   # where the peer listens (from READY)
        self.up = False
        self.closing = False
        self.ended = threading.Event()
        self._last_sent = self._last_received = time.monotonic()

        self._outbox: queue.Queue[Callable[[], None] | None] = queue.Queue()
        # Guards the file-transfer state. Rule: never call self.events while
        # holding it - a UI thread waiting for the lock would deadlock with us.
        self._lock = threading.Lock()
        self._incoming: _Incoming | None = None
        self._outgoing: dict[int, _Outgoing] = {}
        self._next_file_id = 1

    @property
    def peer_fingerprint(self) -> str:
        return fingerprint(self.peer_public) if self.peer_public else ""

    @property
    def initiator_key(self) -> bytes:
        """Identity key of the side that dialled; used to pick between duplicate links."""
        return self.identity.public_bytes if self.role == ROLE_INITIATOR else self.peer_public

    @property
    def peer_host(self) -> str:
        return self.address.rsplit(":", 1)[0]

    # ---- lifecycle ----------------------------------------------------------

    def run(self) -> None:
        """Set up the link and run it until it ends. Blocks; call on a background thread."""
        reason: str | None = None
        try:
            refusal = self._establish()
            if refusal is None:
                threading.Thread(target=self._sender_loop, name="link-send", daemon=True).start()
                threading.Thread(target=self._keepalive_loop, name="link-keepalive", daemon=True).start()
                self.up = True
                self.events.link_up(self)
                reason = self._receive_loop()
            else:
                reason = refusal or None
        except WrongPeer:
            reason = None  # an auto-dial reached someone else: nothing to tell the user
        except HandshakeError as e:
            reason = f"Security check failed: {e}"
        except (ChannelError, FrameError) as e:
            reason = f"Security error: {e}"
        except (ConnectionClosed, BrokenPipeError, ConnectionResetError):
            if self.closing:
                reason = None
            elif self.up:
                reason = f"{self.peer_nick} went offline"
            else:
                reason = "The other side closed the connection (or didn't trust your key)."
        except TimeoutError:
            if self.closing:
                reason = None
            elif self.up:
                reason = f"{self.peer_nick} went offline (no response)"
            else:
                reason = "The other side didn't respond."
        except OSError as e:
            reason = None if self.closing else f"Connection error: {e}"
        finally:
            self._cleanup()
        self.events.link_down(self, reason)

    def close(self, bye: bool = True) -> None:
        """End the link; with bye=True the peer is told we're leaving. Safe from any thread."""
        if self.closing:
            return
        self.closing = True

        def goodbye():
            if bye and self.up:
                self._try_send(T_BYE)
            self._shutdown_socket()

        if self.up:
            self._outbox.put(goodbye)
        else:
            self._shutdown_socket()

    def _shutdown_socket(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _cleanup(self) -> None:
        self.ended.set()
        self._outbox.put(None)  # stops the sender thread
        with self._lock:
            for o in self._outgoing.values():
                o.cancelled = True
            inc, self._incoming = self._incoming, None
        if inc:
            inc.discard()
            self.events.file_offer(self, None)
            if inc.accepted:
                self._report_transfer(inc, finished=True)
        self._shutdown_socket()
        self.sock.close()

    # ---- set-up -------------------------------------------------------------

    def _establish(self) -> str | None:
        """Returns None when the link is up, or why it isn't ("" = already reported)."""
        self.sock.settimeout(HANDSHAKE_TIMEOUT)
        result = perform_handshake(self.sock, self.identity.private_key, self.role)
        self.peer_public = result.peer_public
        if self.expected_key is not None and self.peer_public != self.expected_key:
            raise WrongPeer()
        self.channel = SecureChannel(self.sock, result.send_key, result.recv_key)

        # Everything from here on is encrypted.
        self.channel.send(T_NICK, self.nick.encode())
        msg_type, body = self.channel.recv()
        if msg_type != T_NICK:
            raise ChannelError("unexpected first message")
        self.peer_nick = clean_nick(body)

        # A trust question may wait for a human: no timeout while it's open.
        self.sock.settimeout(None)
        refusal = self.events.verify(self)
        if refusal is not None:
            return refusal

        self.channel.send(T_READY, json.dumps({"port": self.listen_port}).encode())
        msg_type, body = self.channel.recv()
        if msg_type != T_READY:
            raise ChannelError("unexpected message before READY")
        try:
            self.peer_port = int(json.loads(body)["port"])
        except (ValueError, KeyError, TypeError):
            self.peer_port = None
        self._last_received = time.monotonic()
        return None

    # ---- receiving ----------------------------------------------------------

    def _receive_loop(self) -> str:
        # A timeout on the socket lets the keepalive notice a dead peer even
        # though recv() would otherwise block forever.
        self.sock.settimeout(DEAD_AFTER)
        while True:
            msg_type, body = self.channel.recv()
            self._last_received = time.monotonic()
            if msg_type == T_BYE:
                return f"{self.peer_nick} went offline"
            try:
                self._handle_frame(msg_type, body)
            except (ValueError, KeyError, TypeError, struct.error):
                raise ChannelError("malformed message") from None

    def _handle_frame(self, msg_type: int, body: bytes) -> None:
        if msg_type == T_TEXT:
            info = json.loads(body)
            mid = str(info["id"])[:64]
            self.events.text(self, mid, str(info.get("sent", ""))[:32], clean_text(str(info["text"])))
            # ACK after the message is stored, so a crash in between means a re-send, not a loss.
            self._queue_send(T_ACK, {"id": mid})
        elif msg_type == T_ACK:
            self.events.ack(self, str(json.loads(body)["id"]))
        elif msg_type == T_PING:
            self._outbox.put(lambda: self._try_send(T_PONG))
        elif msg_type == T_PONG:
            pass  # receiving anything already counts as a sign of life
        elif msg_type == T_NICK:
            self.peer_nick = clean_nick(body)
            self.events.nick(self, self.peer_nick)
        elif msg_type == T_FILE_OFFER:
            self._on_offer(json.loads(body))
        elif msg_type == T_FILE_ACCEPT:
            with self._lock:
                o = self._outgoing.get(json.loads(body)["id"])
            if o:
                threading.Thread(target=self._send_file, args=(o,), daemon=True).start()
        elif msg_type == T_FILE_REJECT:
            with self._lock:
                o = self._outgoing.pop(json.loads(body)["id"], None)
            if o:
                self.events.notice(self, f"{self.peer_nick} declined '{o.path.name}'.")
        elif msg_type == T_FILE_CHUNK:
            self._on_chunk(body)
        elif msg_type == T_FILE_END:
            self._on_file_end(json.loads(body))
        elif msg_type == T_FILE_CANCEL:
            self._on_cancel(json.loads(body))
        # Unknown message types are ignored, for forward compatibility.

    # Receiving a file: OFFER -> user accepts -> we open "<name>.part" and send
    # ACCEPT -> CHUNKs -> END with the SHA-256 of the whole file -> we compare it
    # with the hash of what arrived, then rename or delete. Encryption already
    # protects each chunk; the hash catches a transfer that was cut short.

    def _on_offer(self, info: dict) -> None:
        fid, size = int(info["id"]), int(info["size"])
        name = safe_filename(str(info["name"]))
        with self._lock:
            busy = self._incoming is not None
            if not busy:
                self._incoming = _Incoming(fid, name, size)
        if busy:
            self._queue_send(T_FILE_REJECT, {"id": fid, "reason": "busy"})
        else:
            self.events.file_offer(self, FileOffer(name, size))

    def _on_chunk(self, body: bytes) -> None:
        (fid,) = struct.unpack(">I", body[:4])
        data = body[4:]
        reason = None
        with self._lock:
            inc = self._incoming
            if not inc or not inc.accepted or inc.id != fid:
                return
            inc.received += len(data)
            if inc.received > inc.size:
                reason = "more data than announced"
            else:
                try:
                    inc.handle.write(data)
                    inc.hasher.update(data)
                except OSError as e:
                    reason = f"write error: {e}"
            if reason:
                inc.discard()
                self._incoming = None
        if reason is None:
            self._report_transfer(inc)
            return
        self._report_transfer(inc, finished=True)
        self._queue_send(T_FILE_CANCEL, {"id": fid, "reason": reason})
        self.events.file_done(self, f"Receiving '{inc.name}' failed: {reason}", ok=False)

    def _on_file_end(self, info: dict) -> None:
        with self._lock:
            inc = self._incoming
            if not inc or not inc.accepted or inc.id != info["id"]:
                return
            self._incoming = None
        inc.handle.close()
        inc.handle = None
        self._report_transfer(inc, finished=True)
        if inc.received != inc.size or inc.hasher.hexdigest() != info.get("sha256"):
            inc.discard()
            self.events.file_done(self, f"'{inc.name}' arrived incomplete or corrupted and was discarded.", ok=False)
            return
        os.replace(inc.part_path, inc.final_path)
        self.events.file_done(self, f"Received '{inc.name}' ({human_size(inc.size)})", ok=True,
                              saved=inc.final_path)

    def _on_cancel(self, info: dict) -> None:
        with self._lock:
            o = self._outgoing.pop(info["id"], None)
            if o:
                o.cancelled = True
            inc = self._incoming if self._incoming and self._incoming.id == info["id"] else None
            if inc:
                inc.discard()
                self._incoming = None
        if inc:
            self.events.file_offer(self, None)
            if inc.accepted:
                self._report_transfer(inc, finished=True)
        if o or inc:
            name = o.path.name if o else inc.name
            self.events.notice(self, f"Transfer of '{name}' cancelled by {self.peer_nick}: "
                                     f"{info.get('reason', '')}", "error")

    def _report_transfer(self, inc: _Incoming, finished: bool = False) -> None:
        now = time.monotonic()  # at most ~10 progress updates a second
        if finished or now - inc.last_report >= 0.1:
            inc.last_report = now
            self.events.transfer(self, Transfer(f"in-{inc.id}", inc.name, inc.size, inc.received, False), finished)

    # ---- sending (callable from any thread) ---------------------------------

    def _sender_loop(self) -> None:
        while (job := self._outbox.get()) is not None:
            job()

    def _keepalive_loop(self) -> None:
        while not self.ended.wait(min(5, PING_AFTER / 2)):
            if time.monotonic() - self._last_sent >= PING_AFTER:
                self._outbox.put(lambda: self._try_send(T_PING))

    def _try_send(self, msg_type: int, body: bytes = b"") -> None:
        """Send, ignoring errors: a dead connection is reported by the receive loop."""
        try:
            self.channel.send(msg_type, body)
            self._last_sent = time.monotonic()
        except OSError:
            pass

    def _queue_send(self, msg_type: int, info: dict) -> None:
        data = json.dumps(info).encode()
        self._outbox.put(lambda: self._try_send(msg_type, data))

    def send_text(self, mid: str, sent: str, text: str) -> None:
        self._queue_send(T_TEXT, {"id": mid, "sent": sent, "text": text})

    def send_nick(self, nick: str) -> None:
        self.nick = nick
        data = nick.encode()
        self._outbox.put(lambda: self._try_send(T_NICK, data))

    def offer_file(self, path: Path) -> str | None:
        """Offer a file. Returns an error to show the user, or None."""
        path = path.expanduser()
        if not path.is_file():
            return f"Not a file: {path}"
        with self._lock:
            o = _Outgoing(self._next_file_id, path, path.stat().st_size)
            self._next_file_id += 1
            self._outgoing[o.id] = o
        self._queue_send(T_FILE_OFFER, {"id": o.id, "name": path.name, "size": o.size})
        return None

    def accept_offer(self) -> None:
        with self._lock:
            inc = self._incoming
            if not inc or inc.accepted:
                return
            try:
                self.download_dir.mkdir(parents=True, exist_ok=True)
                inc.final_path = unique_path(self.download_dir, inc.name)
                inc.part_path = inc.final_path.with_name(inc.final_path.name + ".part")
                inc.handle = open(inc.part_path, "xb")
            except OSError as e:
                self._incoming = None
                error = e
            else:
                inc.accepted = True  # chunks only arrive after ACCEPT, so the file is ready in time
                error = None
        self.events.file_offer(self, None)
        if error:
            self.events.notice(self, f"Cannot save the file: {error}", "error")
            self._queue_send(T_FILE_REJECT, {"id": inc.id, "reason": "cannot save"})
            return
        self._report_transfer(inc)
        self._queue_send(T_FILE_ACCEPT, {"id": inc.id})

    def reject_offer(self) -> None:
        with self._lock:
            inc = self._incoming if self._incoming and not self._incoming.accepted else None
            if inc:
                self._incoming = None
        self.events.file_offer(self, None)
        if inc:
            self._queue_send(T_FILE_REJECT, {"id": inc.id, "reason": "declined"})

    def _send_file(self, o: _Outgoing) -> None:
        """Stream a file in 64 KB encrypted chunks, then send its SHA-256 for checking."""
        hasher, sent, last_report = hashlib.sha256(), 0, 0.0

        def report(finished: bool = False):
            self.events.transfer(self, Transfer(f"out-{o.id}", o.path.name, o.size, sent, True), finished)

        report()
        try:
            with open(o.path, "rb") as f:
                while chunk := f.read(CHUNK_SIZE):
                    if o.cancelled or self.ended.is_set():
                        return
                    # Chunk body: 4-byte transfer id (big-endian) followed by the data.
                    self.channel.send(T_FILE_CHUNK, struct.pack(">I", o.id) + chunk)
                    self._last_sent = time.monotonic()
                    hasher.update(chunk)
                    sent += len(chunk)
                    if time.monotonic() - last_report >= 0.1:
                        last_report = time.monotonic()
                        report()
            if sent != o.size:
                raise OSError("file changed size while sending")
            self.channel.send(T_FILE_END, json.dumps({"id": o.id, "sha256": hasher.hexdigest()}).encode())
            self.events.file_done(self, f"Sent '{o.path.name}' ({human_size(sent)})", ok=True)
        except OSError as e:
            if not self.ended.is_set():
                self.events.file_done(self, f"Sending '{o.path.name}' failed: {e}", ok=False)
                self._try_send(T_FILE_CANCEL, json.dumps({"id": o.id, "reason": str(e)}).encode())
        finally:
            report(finished=True)
            with self._lock:
                self._outgoing.pop(o.id, None)
