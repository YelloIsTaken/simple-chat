"""Drive the Textual app with its test pilot, against Messenger peers running in-process."""

import asyncio
import os
import socket
import time

from textual.widgets import OptionList
from test_messenger import Node, free_port  # pytest puts tests/ on sys.path

from simplechat.tui import MainScreen, OfferDialog, SimpleChatApp, TrustDialog


def log_text(app: SimpleChatApp) -> str:
    if app.main is None:
        return ""
    return "\n".join(line.text for line in app.main.query_one("#log").lines)


def sidebar(app: SimpleChatApp) -> list[tuple[str | None, str]]:
    options = app.main.query_one("#contacts", OptionList)
    return [(o.id, str(o.prompt)) for o in (options.get_option_at_index(i) for i in range(options.option_count))]


def sidebar_line(app: SimpleChatApp, node: Node, prefix: str) -> str:
    wanted = f"{prefix}:{node.identity.public_bytes.hex()}"
    return next((text for oid, text in sidebar(app) if oid == wanted), "")


async def wait_until(pilot, condition, timeout: float = 20, what: str = "the UI") -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, f"timed out waiting for {what}"
        await pilot.pause(0.05)


async def pick(pilot, app: SimpleChatApp, option_id: str) -> None:
    options = app.main.query_one("#contacts", OptionList)
    options.focus()
    options.highlighted = options.get_option_index(option_id)
    await pilot.press("enter")


async def type_message(pilot, app: SimpleChatApp, text: str) -> None:
    field = app.main.query_one("#message")
    field.value = text
    field.focus()
    await pilot.press("enter")


async def scenario(tmp_path) -> None:
    udp = free_port(socket.SOCK_DGRAM)
    port = free_port()
    app = SimpleChatApp(tmp_path / "me", "tui-user", tmp_path / "downloads", port,
                        messenger_options={"bind": "127.0.0.1", "discovery_port": udp, "discovery_targets": []})
    alice = Node(tmp_path, "alice")

    async with app.run_test(size=(120, 40)) as pilot:
        # First run: choose a password (twice).
        pilot.app.screen.query_one("#pw").value = "password123"
        await pilot.press("enter")
        pilot.app.screen.query_one("#pw2").value = "password123"
        await pilot.press("enter")
        await wait_until(pilot, lambda: isinstance(app.screen, MainScreen), what="main screen")
        assert "Welcome!" in log_text(app)

        # Alice announces herself on the "LAN": she shows up under NEARBY.
        alice.start()
        alice.m.discovery.targets = [("127.0.0.1", udp)]
        alice.m.discovery.announce()
        await wait_until(pilot, lambda: sidebar_line(app, alice, "n"), what="nearby entry")
        assert "alice" in sidebar_line(app, alice, "n")

        # Pick her: we dial her, and compare fingerprints in the dialog.
        await pick(pilot, app, "n:" + alice.identity.public_bytes.hex())
        await wait_until(pilot, lambda: isinstance(app.screen, TrustDialog), what="trust dialog")
        assert app.screen.request.peer_fingerprint == alice.identity.fingerprint
        assert not app.screen.request.incoming
        await pilot.press("y")
        await wait_until(pilot, lambda: sidebar_line(app, alice, "c").startswith("● alice"), what="online")

        # Open the conversation and chat both ways.
        await pick(pilot, app, "c:" + alice.identity.public_bytes.hex())
        await type_message(pilot, app, "hi alice [red]literal[/red]")
        me = app.identity.public_bytes
        await asyncio.to_thread(lambda: wait_for_texts(alice, me, ["hi alice [red]literal[/red]"]))
        await wait_until(pilot, lambda: "you: hi alice [red]literal[/red] ✓" in log_text(app), what="✓")
        alice.m.send(me, "hello from alice")
        await wait_until(pilot, lambda: "alice: hello from alice" in log_text(app), what="incoming")

        # Alice goes offline: grey in the sidebar, and messages queue up (⏳).
        await asyncio.to_thread(alice.stop)
        await wait_until(pilot, lambda: sidebar_line(app, alice, "c").startswith("○ alice"), what="offline")
        await type_message(pilot, app, "are you there?")
        await wait_until(pilot, lambda: "you: are you there? ⏳" in log_text(app), what="pending mark")
        assert "⏳1" in sidebar_line(app, alice, "c")

        # She comes back (same port): we redial her and the queued message is delivered.
        alice2 = Node(tmp_path, "alice", port=alice.port).start()
        await wait_until(pilot, lambda: "you: are you there? ✓" in log_text(app), timeout=30, what="delivery")
        assert sidebar_line(app, alice, "c").startswith("● alice")
        assert "are you there?" in [m.text for m in alice2.m.conversation(me).messages]

        # She sends a file: accept it in the dialog.
        payload = os.urandom(150_000)
        (tmp_path / "photo.bin").write_bytes(payload)
        alice2.m.send_file(me, tmp_path / "photo.bin")
        await wait_until(pilot, lambda: isinstance(app.screen, OfferDialog), what="offer dialog")
        await pilot.press("y")
        await wait_until(pilot, lambda: "Received 'photo.bin'" in log_text(app), what="file")
        assert (tmp_path / "downloads" / "photo.bin").read_bytes() == payload

        # Bob adds *us* by address: a contact request. While alice's chat is open,
        # bob's message shows as unread in the sidebar.
        bob = Node(tmp_path, "bob").start()
        bob.m.add_by_address("127.0.0.1", port)
        await wait_until(pilot, lambda: isinstance(app.screen, TrustDialog), what="contact request")
        assert app.screen.request.incoming and app.screen.request.peer_nick == "bob"
        await pilot.press("y")
        await wait_until(pilot, lambda: sidebar_line(app, bob, "c").startswith("● bob"), what="bob online")
        bob.m.send(me, "hey, it's bob")
        await wait_until(pilot, lambda: sidebar_line(app, bob, "c").endswith("1"), what="unread count")
        await pick(pilot, app, "c:" + bob.identity.public_bytes.hex())
        await wait_until(pilot, lambda: "bob: hey, it's bob" in log_text(app), what="bob's message")
        assert not sidebar_line(app, bob, "c").endswith("1")

        await pilot.press("ctrl+q")
        await asyncio.to_thread(lambda: wait_for(lambda: not bob.online(alice2) and not bob.m.is_online(me)))
        for node in (alice2, bob):
            node.stop()


def wait_for(condition, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline
        time.sleep(0.05)


def wait_for_texts(node: Node, contact: bytes, texts: list[str]) -> None:
    wait_for(lambda: [m.text for m in node.m.conversation(contact).messages] == texts)


def test_tui(tmp_path):
    asyncio.run(scenario(tmp_path))


async def wrong_password(tmp_path) -> None:
    Node(tmp_path, "me")  # creates tmp_path/me/identity.json with another password
    app = SimpleChatApp(tmp_path / "me", "x", tmp_path / "dl", free_port(),
                        messenger_options={"bind": "127.0.0.1"})
    async with app.run_test() as pilot:
        for _ in range(3):
            await wait_until(pilot, lambda: not app.screen.query_one("#pw").disabled)
            app.screen.query_one("#pw").value = "not-the-password"
            await pilot.press("enter")
        await wait_until(pilot, lambda: app.return_code == 1)


def test_wrong_password_exits(tmp_path):
    asyncio.run(wrong_password(tmp_path))
