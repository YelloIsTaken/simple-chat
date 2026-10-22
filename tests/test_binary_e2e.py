"""End-to-end test of the PyInstaller binary's TUI, against an in-process Messenger peer.

Run `./build.sh` first; skipped if dist/simplechat doesn't exist.
"""

import time

import pytest

pytest.importorskip("pexpect")
pytest.importorskip("pyte")

from test_messenger import Node, free_port, wait_until  # noqa: E402
from tui_driver import BINARY, Tui  # noqa: E402

pytestmark = pytest.mark.skipif(not BINARY.exists(), reason="binary not built")


def test_binary_chat(tmp_path):
    port = free_port()
    tui = Tui(tmp_path / "me", "--nick", "desk", "--port", str(port))
    peer = Node(tmp_path, "peer").start()
    try:
        tui.unlock()
        tui.wait_for("CONTACTS")

        peer.m.add_by_address("127.0.0.1", port)  # a contact request reaches the TUI
        tui.wait_for("Contact request from 'peer'")
        tui.wait_for(peer.identity.fingerprint)
        tui.type("y")
        tui.wait_for("● peer")
        me = next(c.public_key for c in peer.m.contact_list())

        peer.m.send(me, "hello binary, zażółć 🔒")
        tui.wait_for(r"peer\s+1")         # unread badge in the sidebar
        tui.key("enter")                  # open the highlighted conversation
        tui.wait_for("peer: hello binary, zażółć")
        tui.submit("hi from the tui")
        wait_until(lambda: "hi from the tui" in [m.text for m in peer.m.conversation(me).messages])
        tui.wait_for("you: hi from the tui ✓")

        tui.key("ctrl+q")
        assert tui.wait_exit() == 0
        wait_until(lambda: not peer.m.is_online(me), what="peer sees us go offline")
    finally:
        tui.kill()
        peer.stop()


def test_binary_wrong_password(tmp_path):
    Node(tmp_path, "me")  # an identity with a different password
    tui = Tui(tmp_path / "me", "--port", str(free_port()))
    try:
        for attempt in range(3):
            tui.wait_for("Unlock your identity")
            if attempt:
                tui.wait_for("Wrong password")
            tui.submit("not-the-password")
            time.sleep(0.5)
        assert tui.wait_exit() == 1
    finally:
        tui.kill()
