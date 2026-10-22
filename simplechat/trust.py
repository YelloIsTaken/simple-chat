"""Contacts: a trust-on-first-use (TOFU) store, like SSH's known_hosts.

The handshake proves the peer owns *some* identity key, but only a human can
tell whether it's the *right* one. The first time you meet someone, you both
compare fingerprints over another channel (in person, a phone call) and the
key is saved as a contact. After that:

* the same key connecting again is recognised automatically;
* the app dials contacts by themselves, but only accepts the exact saved key
  on the other end (see messenger.py);
* when *you* type an address that used to belong to a contact with a
  different key, the app refuses and shows a loud warning, because that's
  what a man-in-the-middle looks like.

Several threads (one per connection) update contacts, so every method takes
a lock.
"""

import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path

from .identity import fingerprint

MAX_HOSTS = 10  # addresses remembered per contact, for the changed-key check


@dataclass
class Peer:
    public_key: bytes
    label: str                                   # their nickname, kept up to date
    hosts: list[str] = field(default_factory=list)  # "host:port" addresses they were reached at
    last_address: str | None = None              # where to dial them next ("host:port")

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_key)


class KnownPeers:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self._peers: dict[bytes, Peer] = {}
        if path.exists():
            for item in json.loads(path.read_text()):
                pk = bytes.fromhex(item["public_key"])
                self._peers[pk] = Peer(pk, item["label"], list(item.get("hosts", [])), item.get("last_address"))

    def _save(self) -> None:
        data = [
            {"public_key": p.public_key.hex(), "label": p.label, "hosts": p.hosts, "last_address": p.last_address}
            for p in self._peers.values()
        ]
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.path)

    def get(self, public_key: bytes) -> Peer | None:
        with self._lock:
            return self._peers.get(public_key)

    def all(self) -> list[Peer]:
        with self._lock:
            return list(self._peers.values())

    def others_for_host(self, host: str, public_key: bytes) -> list[Peer]:
        """Contacts *other than* public_key previously reached at this address."""
        with self._lock:
            return [p for p in self._peers.values() if host in p.hosts and p.public_key != public_key]

    def trust(self, public_key: bytes, label: str, host: str | None = None) -> Peer:
        with self._lock:
            peer = self._peers.setdefault(public_key, Peer(public_key, label))
            if host:
                self._remember(peer, host)
            self._save()
            return peer

    def add_host(self, public_key: bytes, host: str) -> None:
        with self._lock:
            peer = self._peers.get(public_key)
            if peer and host not in peer.hosts:
                self._remember(peer, host)
                self._save()

    @staticmethod
    def _remember(peer: Peer, host: str) -> None:
        if host not in peer.hosts:
            peer.hosts = (peer.hosts + [host])[-MAX_HOSTS:]

    def set_last_address(self, public_key: bytes, address: str) -> None:
        with self._lock:
            peer = self._peers.get(public_key)
            if peer and peer.last_address != address:
                peer.last_address = address
                self._remember(peer, address)
                self._save()

    def rename(self, public_key: bytes, label: str) -> None:
        with self._lock:
            peer = self._peers.get(public_key)
            if peer and peer.label != label:
                peer.label = label
                self._save()

    def remove(self, public_key: bytes) -> None:
        with self._lock:
            if self._peers.pop(public_key, None):
                self._save()

    def forget(self, query: str) -> list[Peer]:
        """Remove peers whose fingerprint starts with `query` (dashes optional) or whose label equals it."""
        q = query.replace("-", "").upper()
        with self._lock:
            removed = [
                p for p in self._peers.values()
                if p.label == query or (q and p.fingerprint.replace("-", "").startswith(q))
            ]
            for p in removed:
                del self._peers[p.public_key]
            if removed:
                self._save()
            return removed
