"""End-to-end test: Android app (in a running emulator) <-> desktop binary.

Needs: a booted emulator with the debug APK installed, and dist/simplechat built.
    .venv/bin/python tests/android_e2e.py

The phone is driven with adb + uiautomator; the app exposes its Compose test
tags as resource ids. The emulator reaches this computer at 10.0.2.2, and
`adb forward` lets the desktop reach the phone. (LAN discovery can't cross the
emulator's NAT; it is covered by the JVM interop test instead.)
"""

import hashlib
import os
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pexpect

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tui_driver import Tui  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "wtf.yello.simplechat"
DESK_PORT = 5600


# ---- phone helpers ----------------------------------------------------------

def pick_emulator() -> str:
    """The emulator to test on. Never a real phone: the test wipes the app's data."""
    out = subprocess.run(["adb", "devices"], capture_output=True, text=True, check=True).stdout
    emulators = [line.split()[0] for line in out.splitlines()[1:]
                 if line.startswith("emulator-") and line.split()[-1] == "device"]
    if not emulators:
        sys.exit("No running emulator found (real devices are never used: the test wipes app data).")
    return emulators[0]


SERIAL = pick_emulator()


def adb(*args: str, check: bool = True) -> str:
    return subprocess.run(["adb", "-s", SERIAL, *args], capture_output=True, text=True, check=check).stdout


def ui_nodes() -> list[ET.Element]:
    adb("shell", "uiautomator", "dump", "/sdcard/ui.xml")
    return list(ET.fromstring(adb("exec-out", "cat", "/sdcard/ui.xml")).iter("node"))


def find(tag: str | None = None, text: str | None = None, timeout: float = 15) -> ET.Element:
    deadline = time.time() + timeout
    while time.time() < deadline:
        for n in ui_nodes():
            if tag and n.get("resource-id") != tag:
                continue
            if text and text not in n.get("text", ""):
                continue
            return n
        time.sleep(0.5)
    screenshot("failure")
    raise AssertionError(f"phone: no element tag={tag!r} text={text!r}")


def screen_text() -> str:
    return "\n".join(n.get("text") for n in ui_nodes() if n.get("text"))


def tap(node: ET.Element) -> None:
    x1, y1, x2, y2 = map(int, re.findall(r"\d+", node.get("bounds")))
    adb("shell", "input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2))


def type_into(tag: str, text: str) -> None:
    tap(find(tag))
    adb("shell", "input", "keyevent", "KEYCODE_MOVE_END", *["KEYCODE_DEL"] * 40)  # clear the field
    adb("shell", "input", "text", text.replace(" ", "%s"))


def screenshot(name: str) -> Path:
    path = Path(tempfile.gettempdir()) / f"simplechat-{name}.png"
    path.write_bytes(subprocess.run(["adb", "-s", SERIAL, "exec-out", "screencap", "-p"], capture_output=True).stdout)
    print(f"  screenshot: {path}")
    return path


def start_app() -> None:
    """Fresh install state, permissions granted (the prompts were tested before), app launched."""
    adb("shell", "pm", "clear", PACKAGE)
    for perm in ("android.permission.ACCESS_LOCAL_NETWORK", "android.permission.POST_NOTIFICATIONS"):
        adb("shell", "pm", "grant", PACKAGE, perm, check=False)
    adb("shell", "am", "start", "-n", f"{PACKAGE}/.MainActivity")
    find("contacts")


def phone_text_appears(text: str, timeout: float = 20) -> None:
    find(text=text, timeout=timeout)


# ---- desktop helpers --------------------------------------------------------

def desktop(home: Path, *args: str) -> Tui:
    """Start the desktop TUI binary and unlock it."""
    tui = Tui(home, *args, cwd=home.parent)
    tui.unlock()
    tui.wait_for("CONTACTS")
    return tui


def step(text: str) -> None:
    print(f"- {text}")


# ---- scenario ---------------------------------------------------------------

def main() -> None:
    work = Path(tempfile.mkdtemp(prefix="simplechat-e2e-"))
    desk_home = work / "desk"
    desk_args = ("--nick", "desktop", "--port", str(DESK_PORT))

    step("start both apps; the phone goes online by itself (foreground service)")
    start_app()
    tap(find("profile"))
    phone_fp = find("my_fingerprint").get("text")
    type_into("nick", "pixel")
    tap(find("save_profile"))
    desk = desktop(desk_home, *desk_args)
    desk_fp = subprocess.run([str(ROOT / "dist" / "simplechat"), "--home", str(desk_home), "fingerprint"],
                             capture_output=True, text=True, check=True).stdout.strip()
    assert "Simple Chat is online" in adb("shell", "dumpsys", "notification", "--noredact"), "no service notification"

    step("phone adds the desktop by address; both compare fingerprints")
    tap(find("add"))
    type_into("add_address", f"10.0.2.2:{DESK_PORT}")
    tap(find("add_ok"))
    desk.wait_for("Contact request from 'pixel'")
    desk.wait_for(phone_fp)
    assert find("peer_fingerprint").get("text") == desk_fp
    screenshot("trust-dialog")
    desk.type("y")
    tap(find("trust_yes"))
    find("contact:desktop")
    desk.wait_for("● pixel")

    step("messages both ways, with delivery ticks")
    tap(find("contact:desktop"))
    find("peer_status", "online")
    type_into("input", "hello from android")
    tap(find("send"))
    desk.wait_for(r"pixel\s+1")       # unread badge on the desktop
    desk.key("enter")                 # open the conversation
    desk.wait_for("pixel: hello from android")
    phone_text_appears("✓")           # the phone's bubble got its delivery tick
    desk.submit("hi phone, zażółć gęślą jaźń 🔒")
    phone_text_appears("zażółć gęślą jaźń 🔒")

    step("desktop sends a file to the phone")
    payload = os.urandom(300_000)
    (work / "photo.bin").write_bytes(payload)
    desk.submit(f"/send {work / 'photo.bin'}")
    tap(find("accept"))
    desk.wait_for("Sent 'photo.bin'")
    notice = find(text="Received 'photo.bin'").get("text")
    saved = "/sdcard/Download/" + notice.split("Downloads/", 1)[1]  # MediaStore may rename "photo (1).bin"
    assert adb("shell", "sha256sum", f"'{saved}'").split()[0] == hashlib.sha256(payload).hexdigest()

    step("phone sends a file to the desktop (through the system file picker)")
    phone_payload = os.urandom(150_000)
    (work / "fromphone.bin").write_bytes(phone_payload)
    adb("push", str(work / "fromphone.bin"), "/sdcard/Download/fromphone.bin")
    adb("shell", "content", "call", "--method", "scan_volume", "--uri", "content://media", "--arg", "external_primary",
        check=False)
    tap(find("attach"))
    time.sleep(2)
    if "fromphone.bin" not in screen_text():  # picker opened elsewhere: go to Downloads
        tap(find(text="Downloads"))
    tap(find(text="fromphone.bin"))
    desk.wait_for(r"wants to send you 'fromphone.bin' \(146.5 KB\)")
    desk.type("y")
    desk.wait_for("Received 'fromphone.bin'")
    assert (work / "received" / "fromphone.bin").read_bytes() == phone_payload
    screenshot("chat")

    step("desktop quits: the phone shows it offline and queues a message (⏳)")
    desk.key("ctrl+q")
    desk.wait_exit()
    find("peer_status", "offline")
    type_into("input", "are you there?")
    tap(find("send"))
    phone_text_appears("⏳")
    screenshot("queued")

    step("desktop comes back: the phone redials it by itself and delivers the message (✓)")
    desk = desktop(desk_home, *desk_args)
    find("peer_status", "online", timeout=40)
    desk.wait_for(r"● pixel\s+1")
    desk.key("enter")
    desk.wait_for("pixel: are you there?")
    tap(find("back"))
    find("contact:desktop")
    screenshot("contacts")

    step("a second computer adds the phone (contact request on the phone)")
    adb("forward", f"tcp:{DESK_PORT + 100}", "tcp:5000")
    desk2 = desktop(work / "desk2", "--nick", "laptop", "--port", str(DESK_PORT + 1),
                    "connect", f"127.0.0.1:{DESK_PORT + 100}")
    find(text="Contact request from 'laptop'")
    tap(find("trust_yes"))
    desk2.wait_for("Add 'pixel'")
    desk2.type("y")
    find("contact:laptop")
    desk2.wait_for("● pixel")

    step("app in the background: still online, and a new message is a notification")
    adb("shell", "input", "keyevent", "KEYCODE_HOME")
    time.sleep(1)
    desk2.key("enter")
    desk2.submit("ping from the laptop")
    deadline = time.time() + 15
    while "ping from the laptop" not in adb("shell", "dumpsys", "notification", "--noredact"):
        assert time.time() < deadline, "no message notification"
        time.sleep(0.5)
    adb("shell", "am", "start", "-n", f"{PACKAGE}/.MainActivity")
    find("unread:laptop")
    desk2.key("ctrl+q")
    desk2.wait_exit()
    adb("forward", "--remove", f"tcp:{DESK_PORT + 100}")

    step("an impostor at the desktop's address: auto-dial refuses silently; typing it shows a warning")
    desk.key("ctrl+q")
    desk.wait_exit()
    impostor = desktop(work / "impostor", "--port", str(DESK_PORT))
    time.sleep(5)
    assert "Contact request" not in impostor.text()
    tap(find("add"))
    type_into("add_address", f"10.0.2.2:{DESK_PORT}")
    tap(find("add_ok"))
    find(text="WARNING: the identity key at this address has changed!")
    screenshot("key-changed")
    tap(find("alert_ok"))
    impostor.kill()

    print("\nALL PASSED")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, pexpect.ExceptionPexpect) as e:
        print(f"\nFAILED: {e}", file=sys.stderr)
        sys.exit(1)
