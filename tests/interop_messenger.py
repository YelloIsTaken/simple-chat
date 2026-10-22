"""A scripted desktop Messenger for the Android app's JVM interop tests.

    interop_messenger.py <home> <tcp-port> <announce-to-udp-port>

Trusts everyone, accepts every file, and answers each message with "echo: <text>".
Prints one line per event on stdout:

    READY <tcp port> <public key hex>
    ONLINE <key> / OFFLINE <key>
    TEXT <key> <text>
    FILE <saved path>

Reads commands on stdin: "send <key> <text>", "file <key> <path>", "quit".
"""

import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from simplechat.identity import create_identity, load_identity  # noqa: E402
from simplechat.messenger import Messenger  # noqa: E402


def say(*parts) -> None:
    print(*parts, flush=True)


class Events:
    def __init__(self):
        self.m: Messenger | None = None
        self.online: set[bytes] = set()

    def contacts_changed(self):
        now = {c.public_key for c in self.m.contact_list() if c.online}
        for pk in now - self.online:
            say("ONLINE", pk.hex())
        for pk in self.online - now:
            say("OFFLINE", pk.hex())
        self.online = now

    def nearby_changed(self): pass
    def confirm_trust(self, request): return True
    def key_changed(self, warning): say("KEY_CHANGED", warning.address)
    def transfer(self, contact, progress, finished): pass
    def notice(self, contact, text, level="info"): pass

    def message(self, contact, message, new):
        if new and not message.outgoing and not message.note:
            say("TEXT", contact.hex(), message.text)
            self.m.send(contact, "echo: " + message.text)
        elif new and message.note and message.text.startswith("Received"):
            say("FILE", message.text.rsplit(" → ", 1)[1])

    def file_offer(self, contact, offer):
        if offer:
            threading.Thread(target=self.m.accept_offer, args=(contact,), daemon=True).start()


def main() -> None:
    home, port, announce_to = Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
    path = home / "identity.json"
    identity = load_identity(path, "pw") if path.exists() else create_identity(path, "pw", scrypt_n=2**10)
    events = Events()
    m = Messenger(identity, home, "desktop-py", home / "downloads", events, port=port, bind="127.0.0.1",
                  discovery_port=0, discovery_targets=[("127.0.0.1", announce_to)])
    events.m = m
    m.start()
    say("READY", m.port, identity.public_bytes.hex())
    for line in sys.stdin:
        cmd, *rest = line.rstrip("\n").split(" ", 2)
        if cmd == "send":
            m.send(bytes.fromhex(rest[0]), rest[1])
        elif cmd == "file":
            m.send_file(bytes.fromhex(rest[0]), Path(rest[1]))
        elif cmd == "quit":
            break
    m.stop()
    say("STOPPED")


if __name__ == "__main__":
    main()
