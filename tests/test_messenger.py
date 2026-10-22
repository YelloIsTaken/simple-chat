"""Several Messengers in one process: discovery, presence, queued delivery, trust."""

from __future__ import annotations

import os
import socket
import threading
import time
from pathlib import Path

import pytest

from simplechat import link as link_module
from simplechat.identity import create_identity, load_identity
from simplechat.messenger import Messenger


class Events:
    """A scripted UI: records everything; answers trust questions with `trust`."""

    def __init__(self, trust: bool = True, accept_files: bool = True):
        self.trust = trust
        self.accept_files = accept_files
        self.log: list[tuple] = []
        self.messenger: Messenger | None = None
        self.cond = threading.Condition()

    def _add(self, *event):
        with self.cond:
            self.log.append(event)
            self.cond.notify_all()

    def contacts_changed(self): self._add("contacts")
    def nearby_changed(self): self._add("nearby")
    def message(self, contact, message, new): self._add("message", contact, message, new)
    def confirm_trust(self, request): self._add("trust", request); return self.trust
    def key_changed(self, warning): self._add("key_changed", warning)
    def transfer(self, contact, progress, finished): self._add("transfer", progress, finished)
    def notice(self, contact, text, level="info"): self._add("notice", contact, text, level)

    def file_offer(self, contact, offer):
        self._add("offer", contact, offer)
        if offer and self.accept_files:
            threading.Thread(target=self.messenger.accept_offer, args=(contact,), daemon=True).start()

    def count(self, kind: str) -> int:
        return sum(1 for e in self.log if e[0] == kind)


def wait_until(condition, timeout: float = 15, what: str = "condition") -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, f"timed out waiting for {what}"
        time.sleep(0.05)


def free_port(kind=socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Node:
    """One app instance: an identity in its own home directory, plus a Messenger."""

    def __init__(self, tmp: Path, name: str, trust: bool = True, port: int | None = None):
        self.home = tmp / name
        self.name = name
        self.port = port or free_port()
        self.udp = free_port(socket.SOCK_DGRAM)
        path = self.home / "identity.json"
        self.identity = (load_identity(path, "pw") if path.exists()
                         else create_identity(path, "pw", scrypt_n=2**10))
        self.events = Events(trust)
        self.m: Messenger | None = None

    def start(self, peers: list[Node] = ()) -> Node:
        self.m = Messenger(self.identity, self.home, self.name, self.home / "downloads", self.events,
                           port=self.port, bind="127.0.0.1", discovery_port=self.udp,
                           discovery_targets=[("127.0.0.1", p.udp) for p in peers])
        self.events.messenger = self.m
        self.m.start()
        return self

    def hear(self, *peers: Node) -> None:
        """Send discovery announcements to these nodes (instead of a LAN broadcast)."""
        self.m.discovery.targets = [("127.0.0.1", p.udp) for p in peers]
        self.m.discovery.announce()

    def contact(self, other: Node):
        return next((c for c in self.m.contact_list() if c.public_key == other.identity.public_bytes), None)

    def online(self, other: Node) -> bool:
        c = self.contact(other)
        return bool(c and c.online)

    def texts(self, other: Node) -> list[str]:
        return [m.text for m in self.m.conversation(other.identity.public_bytes).messages if not m.note]

    def stop(self) -> None:
        self.m.stop()


@pytest.fixture
def nodes(tmp_path):
    made: list[Node] = []

    def make(name: str, **kw) -> Node:
        n = Node(tmp_path, name, **kw)
        made.append(n)
        return n

    yield make
    for n in made:
        if n.m:
            n.m.stop(wait=0)


def befriend(a: Node, b: Node) -> None:
    """a discovers b on the 'LAN' and adds it; both accept the trust question."""
    b.hear(a)
    wait_until(lambda: any(p.public_key == b.identity.public_bytes for p in a.m.nearby()), what="nearby")
    a.m.add_nearby(b.identity.public_bytes)
    wait_until(lambda: a.online(b) and b.online(a), what="link up")


def test_discover_add_chat_and_presence(nodes):
    alice, bob = nodes("alice").start(), nodes("bob").start()
    befriend(alice, bob)
    request = next(e[1] for e in bob.events.log if e[0] == "trust")
    assert request.incoming and request.peer_fingerprint == alice.identity.fingerprint
    assert not alice.m.nearby()  # bob is a contact now, not "nearby"

    assert alice.m.send(bob.identity.public_bytes, "hello bob") is None
    wait_until(lambda: bob.texts(alice) == ["hello bob"], what="delivery")
    wait_until(lambda: all(m.delivered for m in alice.m.conversation(bob.identity.public_bytes).messages))
    assert bob.contact(alice).unread == 1
    bob.m.open_conversation(alice.identity.public_bytes)
    assert bob.contact(alice).unread == 0

    bob.m.set_nick("robert")
    wait_until(lambda: alice.contact(bob).nick == "robert", what="nick change")

    bob.stop()
    wait_until(lambda: not alice.online(bob), what="bob offline")


def test_queued_messages_are_delivered_when_contact_returns(nodes):
    alice, bob = nodes("alice").start(), nodes("bob").start()
    befriend(alice, bob)
    bob.stop()
    wait_until(lambda: not alice.online(bob))

    alice.m.send(bob.identity.public_bytes, "while you were away")
    alice.m.send(bob.identity.public_bytes, "second one")
    assert alice.contact(bob).pending == 2

    # Bob comes back on the same port: alice redials his last address by herself.
    bob2 = nodes("bob", port=bob.port).start()
    wait_until(lambda: alice.online(bob2), timeout=30, what="redial")
    wait_until(lambda: bob2.texts(alice) == ["while you were away", "second one"], what="queued delivery")
    wait_until(lambda: alice.contact(bob).pending == 0, what="acks")
    assert not any(e[0] == "trust" for e in bob2.events.log)  # still a contact: no questions

    # Persisted: a fresh messenger for alice still knows they were delivered.
    alice.stop()
    alice2 = nodes("alice", port=alice.port).start()
    assert alice2.contact(bob).pending == 0
    assert alice2.texts(bob) == ["while you were away", "second one"]


def test_announcement_reveals_new_address(nodes):
    alice, bob = nodes("alice").start(), nodes("bob").start()
    befriend(alice, bob)
    bob.stop()
    wait_until(lambda: not alice.online(bob))
    bob2 = nodes("bob", port=free_port()).start()  # a new address, e.g. a new DHCP lease
    bob2.hear(alice)
    wait_until(lambda: alice.online(bob2), timeout=15, what="found via announcement")


def test_duplicate_links_resolve_to_one(nodes):
    alice, bob = nodes("alice").start(), nodes("bob").start()
    befriend(alice, bob)
    for _ in range(3):  # make both sides dial each other at the same moment
        alice.m.add_by_address("127.0.0.1", bob.port)
        bob.m.add_by_address("127.0.0.1", alice.port)
    time.sleep(1.5)
    assert alice.online(bob) and bob.online(alice)
    a_link = alice.m._links[bob.identity.public_bytes]
    b_link = bob.m._links[alice.identity.public_bytes]
    assert a_link.initiator_key == b_link.initiator_key  # both kept the same connection
    alice.m.send(bob.identity.public_bytes, "still works")
    wait_until(lambda: "still works" in bob.texts(alice))


def test_declined_request_and_changed_key(nodes):
    alice = nodes("alice").start()
    shy = nodes("shy", trust=False).start()
    alice.m.add_by_address("127.0.0.1", shy.port)
    wait_until(lambda: any(e[0] == "notice" for e in alice.events.log), what="refusal notice")
    assert alice.contact(shy) is None and shy.contact(alice) is None

    bob = nodes("bob").start()
    alice.m.add_by_address("127.0.0.1", bob.port)
    wait_until(lambda: alice.online(bob))
    bob.stop()
    wait_until(lambda: not alice.online(bob))

    # An impostor takes over bob's address. Automatic dials silently refuse it...
    questions_before = alice.events.count("trust")
    impostor = nodes("impostor", port=bob.port).start()
    time.sleep(3)
    assert not alice.online(bob) and alice.contact(impostor) is None
    assert alice.events.count("trust") == questions_before
    # ...and typing the address yourself shows the changed-key warning.
    alice.m.add_by_address("127.0.0.1", bob.port)
    wait_until(lambda: alice.events.count("key_changed") == 1, what="key changed warning")


def test_file_transfer_and_keepalive(nodes, monkeypatch):
    monkeypatch.setattr(link_module, "PING_AFTER", 0.3)
    monkeypatch.setattr(link_module, "DEAD_AFTER", 2)
    alice, bob = nodes("alice").start(), nodes("bob").start()
    befriend(alice, bob)

    payload = os.urandom(250_000)
    (alice.home / "pic.bin").write_bytes(payload)
    assert alice.m.send_file(bob.identity.public_bytes, alice.home / "pic.bin") is None
    wait_until(lambda: (bob.home / "downloads" / "pic.bin").exists(), what="file")
    wait_until(lambda: any(m.note and "Received 'pic.bin'" in m.text
                           for m in bob.m.conversation(alice.identity.public_bytes).messages))
    assert (bob.home / "downloads" / "pic.bin").read_bytes() == payload

    time.sleep(4)  # twice DEAD_AFTER with no messages: pings keep the link up
    assert alice.online(bob) and bob.online(alice)
