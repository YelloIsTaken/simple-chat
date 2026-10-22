"""Finding other Simple Chat apps on the local network (UDP broadcast).

Every few seconds each app shouts "I'm here" to the whole LAN:

    "SCHAT-ANNOUNCE v2\\n" + JSON {"pk": <identity key, hex>, "port": <TCP port>, "nick": <nickname>}

and listens for everyone else's shouts. That's how a contact whose IP
address changed (a new DHCP lease, another Wi-Fi) is found again, and how
strangers appear in the "nearby" list.

Announcements are *not* authenticated: anyone on the LAN can claim any key.
That's fine, because an announcement only says where to dial. The handshake
on the resulting connection proves who's really there, and a wrong key gets
nowhere (see link.py, WrongPeer). The cost of a fake announcement is one
failed connection attempt.
"""

from __future__ import annotations

import json
import socket
import threading
from typing import Callable

from .textutil import clean_text, local_ip

DISCOVERY_PORT = 50505
ANNOUNCE_EVERY = 5  # seconds
PREFIX = b"SCHAT-ANNOUNCE v2\n"
MAX_DATAGRAM = 1024


def broadcast_targets(port: int = DISCOVERY_PORT) -> list[tuple[str, int]]:
    """The global broadcast address, plus this LAN's /24 broadcast (some routers drop the global one)."""
    targets = [("255.255.255.255", port)]
    if ip := local_ip():
        targets.append((ip.rsplit(".", 1)[0] + ".255", port))
    return targets


class Discovery:
    def __init__(self, public_key: bytes, tcp_port: int, nick: Callable[[], str],
                 on_announce: Callable[[bytes, str, str, int], None],
                 listen_port: int = DISCOVERY_PORT, targets: list[tuple[str, int]] | None = None):
        """on_announce(public_key, nick, host, tcp_port) is called for every announcement heard."""
        self.public_key = public_key
        self.tcp_port = tcp_port
        self.nick = nick
        self.on_announce = on_announce
        self.targets = targets if targets is not None else broadcast_targets(listen_port)
        self.stopped = threading.Event()

        # SO_REUSEADDR/SO_REUSEPORT: several apps on one computer (or a test)
        # can all bind the discovery port and all receive the broadcasts.
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(("", listen_port))
        self.port = self.sock.getsockname()[1]

    def start(self) -> None:
        threading.Thread(target=self._listen, name="discovery-listen", daemon=True).start()
        threading.Thread(target=self._announce_loop, name="discovery-announce", daemon=True).start()

    def stop(self) -> None:
        self.stopped.set()
        self.sock.close()

    def announce(self) -> None:
        payload = PREFIX + json.dumps({"pk": self.public_key.hex(), "port": self.tcp_port,
                                       "nick": self.nick()}).encode()
        for target in self.targets:
            try:
                self.sock.sendto(payload, target)
            except OSError:
                pass  # e.g. no network right now; try again next round

    def _announce_loop(self) -> None:
        while not self.stopped.is_set():
            self.announce()
            self.stopped.wait(ANNOUNCE_EVERY)

    def _listen(self) -> None:
        while not self.stopped.is_set():
            try:
                data, (host, _) = self.sock.recvfrom(MAX_DATAGRAM)
            except OSError:
                return  # socket closed by stop()
            if not data.startswith(PREFIX):
                continue
            try:
                info = json.loads(data[len(PREFIX):])
                pk = bytes.fromhex(info["pk"])
                port = int(info["port"])
                nick = clean_text(str(info.get("nick", "")))[:32].strip() or "unknown"
            except (ValueError, KeyError, TypeError):
                continue  # malformed: ignore
            if len(pk) != 32 or not 0 < port < 65536 or pk == self.public_key:
                continue  # invalid, or our own announcement
            self.on_announce(pk, nick, host, port)
