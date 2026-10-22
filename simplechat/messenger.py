"""The messenger: you, your contacts, and the links between you. No UI code.

What it does, in the background, the whole time the app runs:

* **listens** for incoming connections on the TCP port;
* **announces** itself on the LAN and hears others (discovery.py), which
  fills the "nearby" list and tells it where contacts are right now;
* **dials** every contact that is offline: at the address it was just
  announced from, or the last address that worked, retrying with back-off;
* keeps **one link per online contact** (link.py). Online == has a link;
* **queues** messages to offline contacts and sends them when a link comes
  up; a message stays "pending" until the contact acknowledges it.

Trust works as before: a key you haven't verified never becomes a contact
without a human comparing fingerprints (`confirm_trust`), and automatic
dials only ever accept the exact saved key (Link's `expected_key`).

The UI gets told about changes through `MessengerEvents`. These callbacks
come from background threads, and the UI must move them to its own thread.
"""

from __future__ import annotations

import math
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .conversation import Conversation, Message
from .discovery import DISCOVERY_PORT, Discovery
from .handshake import ROLE_INITIATOR, ROLE_RESPONDER
from .history import History
from .identity import Identity, fingerprint
from .link import MAX_MESSAGE, FileOffer, Link, Transfer
from .textutil import clean_text, split_host_port
from .trust import KnownPeers

DEFAULT_PORT = 5000
DIAL_TIMEOUT = 5          # seconds to wait for a TCP connection
RETRY_FIRST = 10          # first retry after a failed dial...
RETRY_MAX = 60            # ...doubling up to this
RETRY_AFTER_DROP = 2      # quick retry when an established link drops
NEARBY_TTL = 20           # an announcement counts as "here now" for this long
YIELD_DIAL = 3            # the larger key waits this long before dialling (see PROTOCOL.md)


@dataclass(frozen=True)
class ContactView:
    public_key: bytes
    nick: str
    fingerprint: str
    online: bool
    unread: int
    pending: int           # messages still waiting for delivery
    address: str | None


@dataclass(frozen=True)
class NearbyPeer:
    public_key: bytes
    nick: str
    fingerprint: str
    address: str


@dataclass(frozen=True)
class TrustRequest:
    """An unknown key: the user must compare fingerprints before it becomes a contact."""
    peer_nick: str
    address: str
    peer_fingerprint: str
    my_fingerprint: str
    incoming: bool          # True: they contacted us (a contact request)


@dataclass(frozen=True)
class KeyChanged:
    """An address the user typed used to belong to a contact with a different key."""
    address: str
    old_label: str
    old_fingerprint: str
    new_fingerprint: str


class MessengerEvents(Protocol):
    def contacts_changed(self) -> None: ...
    def nearby_changed(self) -> None: ...

    def message(self, contact: bytes, message: Message, new: bool) -> None:
        """A message was added (new=True) or its delivery status changed (new=False)."""

    def confirm_trust(self, request: TrustRequest) -> bool:
        """Ask the user; block until they answer."""

    def key_changed(self, warning: KeyChanged) -> None: ...
    def file_offer(self, contact: bytes, offer: FileOffer | None) -> None: ...
    def transfer(self, contact: bytes, progress: Transfer, finished: bool) -> None: ...

    def notice(self, contact: bytes | None, text: str, level: str = "info") -> None:
        """contact=None: not about a particular contact."""


class Messenger:
    def __init__(self, identity: Identity, home: Path, nick: str, download_dir: Path,
                 events: MessengerEvents, port: int = DEFAULT_PORT, bind: str = "0.0.0.0",
                 discovery_port: int = DISCOVERY_PORT, discovery_targets: list[tuple[str, int]] | None = None):
        self.identity = identity
        self.nick = nick
        self.download_dir = download_dir
        self.events = events
        self.contacts = KnownPeers(home / "known_peers.json")
        self._history_dir = home / "history"
        self._history_key = identity.history_key()
        self._requested_port, self._bind = port, bind
        self._discovery_port, self._discovery_targets = discovery_port, discovery_targets

        # Shared state, guarded by _lock. As in Link: no events while holding it.
        self._lock = threading.RLock()
        self._links: dict[bytes, Link] = {}            # the active link per online contact
        self._dialing: set[bytes] = set()              # contacts with a dial in progress
        self._asking: set[bytes] = set()               # unknown keys with an open trust question
        self._next_dial: dict[bytes, float] = {}
        self._backoff: dict[bytes, float] = {}
        self._nearby: dict[bytes, tuple[str, str, int, float]] = {}  # key -> (nick, host, port, seen)
        self._conversations: dict[bytes, Conversation] = {}
        self._unread: dict[bytes, int] = {}
        self.active_contact: bytes | None = None       # the conversation on screen: no unread count
        self.stopped = threading.Event()
        self.port = 0
        self.server: socket.socket | None = None
        self.discovery: Discovery | None = None

    # ---- start / stop -------------------------------------------------------

    def start(self) -> None:
        """Start listening, announcing and dialling. Raises OSError if the port is taken."""
        self.server = socket.create_server((self._bind, self._requested_port))
        self.port = self.server.getsockname()[1]
        self.discovery = Discovery(self.identity.public_bytes, self.port, lambda: self.nick,
                                   self._on_announce, self._discovery_port, self._discovery_targets)
        threading.Thread(target=self._accept_loop, name="accept", daemon=True).start()
        threading.Thread(target=self._dial_loop, name="dialer", daemon=True).start()
        self.discovery.start()

    def stop(self, wait: float = 1.0) -> None:
        """Say goodbye on every link and shut everything down."""
        self.stopped.set()
        if self.server:
            # shutdown() first: on Linux, close() alone doesn't wake the thread blocked
            # in accept(), and the port would stay taken until the process exits.
            try:
                self.server.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.server.close()
        if self.discovery:
            self.discovery.stop()
        with self._lock:
            links = list(self._links.values())
        for link in links:
            link.close(bye=True)
        deadline = time.monotonic() + wait
        for link in links:
            link.ended.wait(max(0.0, deadline - time.monotonic()))

    # ---- what the UI shows --------------------------------------------------

    def contact_list(self) -> list[ContactView]:
        """Online contacts first, then alphabetical."""
        with self._lock:
            online = set(self._links)
            unread = dict(self._unread)
        views = [
            ContactView(p.public_key, p.label, p.fingerprint, p.public_key in online,
                        unread.get(p.public_key, 0), len(self.conversation(p.public_key).pending()),
                        p.last_address)
            for p in self.contacts.all()
        ]
        return sorted(views, key=lambda c: (not c.online, c.nick.lower()))

    def nearby(self) -> list[NearbyPeer]:
        """People announcing themselves on the LAN who aren't contacts yet."""
        now = time.monotonic()
        with self._lock:
            entries = list(self._nearby.items())
        return [
            NearbyPeer(pk, nick, fingerprint(pk), f"{host}:{port}")
            for pk, (nick, host, port, seen) in entries
            if now - seen < NEARBY_TTL and self.contacts.get(pk) is None
        ]

    def conversation(self, contact: bytes) -> Conversation:
        with self._lock:
            conv = self._conversations.get(contact)
            if conv is None:
                conv = Conversation(History(self._history_dir, self._history_key, contact))
                self._conversations[contact] = conv
            return conv

    def is_online(self, contact: bytes) -> bool:
        with self._lock:
            return contact in self._links

    def open_conversation(self, contact: bytes | None) -> None:
        """The UI now shows this conversation: its messages count as read."""
        with self._lock:
            self.active_contact = contact
            changed = contact is not None and self._unread.pop(contact, 0) > 0
        if changed:
            self.events.contacts_changed()

    # ---- what the user does -------------------------------------------------

    def send(self, contact: bytes, text: str) -> str | None:
        """Send (or queue) a message. Returns an error to show, or None."""
        if len(text.encode()) > MAX_MESSAGE:
            return f"Message too long (limit {MAX_MESSAGE // 1024} KB)."
        message = self.conversation(contact).add_outgoing("you", text)
        with self._lock:
            link = self._links.get(contact)
        if link:
            link.send_text(message.id, message.time, text)
        self.events.message(contact, message, True)
        if not link:
            self.events.contacts_changed()  # the pending count changed
        return None

    def add_by_address(self, host: str, port: int = DEFAULT_PORT) -> None:
        """Dial an address the user typed. Unknown keys go through the trust dialog."""
        threading.Thread(target=self._dial, args=(None, host, port, f"{host}:{port}"), daemon=True).start()

    def add_nearby(self, contact: bytes) -> None:
        with self._lock:
            entry = self._nearby.get(contact)
        if entry:
            _, host, port, _ = entry
            threading.Thread(target=self._dial, args=(contact, host, port, f"{host}:{port}"), daemon=True).start()

    def remove_contact(self, contact: bytes) -> None:
        self.contacts.remove(contact)
        with self._lock:
            link = self._links.pop(contact, None)
            self._unread.pop(contact, None)
        if link:
            link.close(bye=True)
        self.events.contacts_changed()
        self.events.nearby_changed()

    def set_nick(self, nick: str) -> None:
        nick = clean_text(nick).strip()[:32]
        if not nick:
            return
        self.nick = nick
        with self._lock:
            links = list(self._links.values())
        for link in links:
            link.send_nick(nick)
        if self.discovery:
            self.discovery.announce()

    def send_file(self, contact: bytes, path: Path) -> str | None:
        """Offer a file (online contacts only). Returns an error to show, or None."""
        with self._lock:
            link = self._links.get(contact)
        if not link:
            return "Files can only be sent while the contact is online."
        if error := link.offer_file(path):
            return error
        self.events.notice(contact, f"Offered '{path.name}'. Waiting for {link.peer_nick} to accept…")
        return None

    def accept_offer(self, contact: bytes) -> None:
        with self._lock:
            link = self._links.get(contact)
        if link:
            link.accept_offer()

    def reject_offer(self, contact: bytes) -> None:
        with self._lock:
            link = self._links.get(contact)
        if link:
            link.reject_offer()

    # ---- connections --------------------------------------------------------

    def _accept_loop(self) -> None:
        while not self.stopped.is_set():
            try:
                conn, (host, port) = self.server.accept()
            except OSError:
                return  # server closed: we're stopping
            link = Link(conn, ROLE_RESPONDER, f"{host}:{port}", self.identity, None, self.nick,
                        self.port, self.download_dir, self)
            threading.Thread(target=link.run, name="link", daemon=True).start()

    def _dial(self, expected: bytes | None, host: str, port: int, manual_host: str | None) -> None:
        """Dial host:port. expected: the contact we're after (None: whoever answers, user-typed)."""
        try:
            sock = socket.create_connection((host, port), timeout=DIAL_TIMEOUT)
        except OSError as e:
            if manual_host:
                self.events.notice(None, f"Could not connect to {manual_host}: {e}", "error")
            if expected is not None:
                self._dial_failed(expected)
            return
        link = Link(sock, ROLE_INITIATOR, f"{host}:{port}", self.identity, expected, self.nick,
                    self.port, self.download_dir, self, manual_host=manual_host)
        link.run()

    def _dial_failed(self, contact: bytes) -> None:
        with self._lock:
            self._dialing.discard(contact)
            backoff = min(RETRY_MAX, self._backoff.get(contact, RETRY_FIRST / 2) * 2)
            self._backoff[contact] = backoff
            self._next_dial[contact] = time.monotonic() + backoff

    def _dial_loop(self) -> None:
        """Once a second: dial offline contacts that are due, and expire old announcements."""
        while not self.stopped.wait(1):
            now = time.monotonic()
            due = []
            with self._lock:
                for peer in self.contacts.all():
                    pk = peer.public_key
                    if pk in self._links or pk in self._dialing or now < self._next_dial.get(pk, 0):
                        continue
                    address = self._address_for(pk, peer.last_address, now)
                    if address:
                        self._dialing.add(pk)
                        due.append((pk, address))
                expired = [pk for pk, (*_, seen) in self._nearby.items() if now - seen >= NEARBY_TTL]
                for pk in expired:
                    del self._nearby[pk]
            for pk, (host, port) in due:
                threading.Thread(target=self._auto_dial, args=(pk, host, port), daemon=True).start()
            if any(self.contacts.get(pk) is None for pk in expired):
                self.events.nearby_changed()

    def _auto_dial(self, contact: bytes, host: str, port: int) -> None:
        try:
            self._dial(contact, host, port, None)
        finally:
            with self._lock:
                self._dialing.discard(contact)
                # No link came up, and nobody scheduled the next try (a failed TCP
                # connect or a dropped link do): e.g. a different key answered. Back off.
                if contact not in self._links and self._next_dial.get(contact, 0) <= time.monotonic():
                    backoff = min(RETRY_MAX, self._backoff.get(contact, RETRY_FIRST / 2) * 2)
                    self._backoff[contact] = backoff
                    self._next_dial[contact] = time.monotonic() + backoff

    def _address_for(self, contact: bytes, last_address: str | None, now: float) -> tuple[str, int] | None:
        """Where to dial a contact: where it was just announced from, else the last address that worked."""
        entry = self._nearby.get(contact)
        if entry and now - entry[3] < NEARBY_TTL:
            return entry[1], entry[2]
        if last_address:
            return split_host_port(last_address, DEFAULT_PORT)
        return None

    def _on_announce(self, contact: bytes, nick: str, host: str, port: int) -> None:
        now = time.monotonic()
        with self._lock:
            entry = self._nearby.get(contact)
            moved = entry is None or (entry[1], entry[2]) != (host, port)
            self._nearby[contact] = (nick, host, port, now)
            is_contact = self.contacts.get(contact) is not None
            if is_contact and contact not in self._links and contact not in self._dialing and moved:
                # A contact just appeared (or moved): dial now. If both sides would
                # dial at once, the one with the larger key waits a little.
                delay = 0 if self.identity.public_bytes < contact else YIELD_DIAL
                self._next_dial[contact] = min(self._next_dial.get(contact, math.inf), now + delay)
                self._backoff.pop(contact, None)
        if not is_contact and entry is None:
            self.events.nearby_changed()

    # ---- LinkEvents: called by links, on their threads ----------------------

    def verify(self, link: Link) -> str | None:
        pk = link.peer_public
        if pk == self.identity.public_bytes:
            return "That's this app itself."
        if self.contacts.get(pk):
            return None
        if link.manual_host:
            previous = self.contacts.others_for_host(link.manual_host, pk)
            if previous:
                self.events.key_changed(KeyChanged(link.manual_host, previous[0].label,
                                                   previous[0].fingerprint, link.peer_fingerprint))
                return ""
        with self._lock:
            if pk in self._asking or self.stopped.is_set():
                return "busy"  # one open question per key, so nobody can flood us with dialogs
            self._asking.add(pk)
        try:
            request = TrustRequest(link.peer_nick, link.address, link.peer_fingerprint,
                                   self.identity.fingerprint, incoming=link.role == ROLE_RESPONDER)
            if not self.events.confirm_trust(request):
                return "Not trusted."
        finally:
            with self._lock:
                self._asking.discard(pk)
        # Saved as a contact only in link_up, once the other side has said yes too.
        link.newly_trusted = True
        return None

    def link_up(self, link: Link) -> None:
        pk = link.peer_public
        with self._lock:
            existing = self._links.get(pk)
            loser = None
            if existing and not existing.ended.is_set():
                # Two links to the same contact (both dialled at once): keep the one
                # whose initiator has the smaller key. The other side does the same.
                if link.initiator_key < existing.initiator_key:
                    loser, self._links[pk] = existing, link
                else:
                    loser = link
            else:
                self._links[pk] = link
            self._backoff.pop(pk, None)
            self._next_dial.pop(pk, None)
            self._dialing.discard(pk)
        if loser is not None:
            loser.close(bye=False)
            if loser is link:
                return
        if getattr(link, "newly_trusted", False):
            self.contacts.trust(pk, link.peer_nick, link.manual_host)
            self.events.nearby_changed()
        if link.peer_port:
            self.contacts.set_last_address(pk, f"{link.peer_host}:{link.peer_port}")
        self.contacts.rename(pk, link.peer_nick)
        for message in self.conversation(pk).pending():
            link.send_text(message.id, message.time, message.text)
        self.events.contacts_changed()

    def link_down(self, link: Link, reason: str | None) -> None:
        pk = link.peer_public
        with self._lock:
            was_active = self._links.get(pk) is link
            if was_active:
                del self._links[pk]
                self._next_dial[pk] = time.monotonic() + RETRY_AFTER_DROP
        if was_active:
            self.events.file_offer(pk, None)
            if reason and reason.startswith("Security"):
                self.events.notice(pk, reason, "error")
            self.events.contacts_changed()
        elif not link.up and link.manual_host and not self.stopped.is_set():
            self.events.notice(None, reason or f"Could not add {link.manual_host}: a different key answered.",
                               "error" if reason != "Not trusted." else "info")
        elif not link.up and reason and reason.startswith("Security"):
            self.events.notice(None, f"{link.address}: {reason}", "error")

    def text(self, link: Link, mid: str, sent: str, text: str) -> None:
        pk = link.peer_public
        message = self.conversation(pk).add_incoming(mid, sent, link.peer_nick, text)
        if message is None:
            return  # a re-sent message we already have
        with self._lock:
            if pk != self.active_contact:
                self._unread[pk] = self._unread.get(pk, 0) + 1
        self.events.message(pk, message, True)
        self.events.contacts_changed()

    def ack(self, link: Link, mid: str) -> None:
        message = self.conversation(link.peer_public).mark_delivered(mid)
        if message:
            self.events.message(link.peer_public, message, False)
            self.events.contacts_changed()

    def nick(self, link: Link, nick: str) -> None:
        if link.up:
            self.contacts.rename(link.peer_public, nick)
            self.events.contacts_changed()

    def file_offer(self, link: Link, offer: FileOffer | None) -> None:
        self.events.file_offer(link.peer_public, offer)

    def transfer(self, link: Link, progress: Transfer, finished: bool) -> None:
        self.events.transfer(link.peer_public, progress, finished)

    def file_done(self, link: Link, text: str, ok: bool, saved: Path | None = None) -> None:
        if ok:
            note = self.conversation(link.peer_public).add_note(text + (f" → {saved}" if saved else ""))
            self.events.message(link.peer_public, note, True)
        else:
            self.events.notice(link.peer_public, text, "error")

    def notice(self, link: Link, text: str, level: str = "info") -> None:
        self.events.notice(link.peer_public, text, level)
