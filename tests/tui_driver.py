"""Run the simplechat binary in a pseudo-terminal and read its screen.

pexpect gives the program a real terminal; pyte replays everything it draws
into an in-memory screen, so tests can wait for text to appear anywhere on
it, the way a person looks at the window.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

import pexpect
import pyte

BINARY = Path(__file__).resolve().parent.parent / "dist" / "simplechat"
PASSWORD = "password123"

KEYS = {"enter": "\r", "escape": "\x1b", "tab": "\t", "backspace": "\x7f"}


class Tui:
    def __init__(self, home: Path, *args: str, cwd: Path | None = None, cols: int = 130, rows: int = 40):
        env = dict(os.environ, TERM="xterm-256color", COLUMNS=str(cols), LINES=str(rows))
        self.child = pexpect.spawn(str(BINARY), ["--home", str(home), *args], cwd=str(cwd or home.parent),
                                   dimensions=(rows, cols), env=env, encoding="utf-8",
                                   codec_errors="replace")
        self.screen = pyte.Screen(cols, rows)
        self.stream = pyte.Stream(self.screen)

    def pump(self) -> None:
        """Feed everything the program has drawn so far into the virtual screen."""
        while True:
            try:
                self.stream.feed(self.child.read_nonblocking(65536, timeout=0.05))
            except pexpect.TIMEOUT:
                return
            except pexpect.EOF:
                return

    def text(self) -> str:
        self.pump()
        return "\n".join(line.rstrip() for line in self.screen.display)

    def wait_for(self, pattern: str, timeout: float = 20) -> re.Match:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if m := re.search(pattern, self.text()):
                return m
        raise AssertionError(f"screen never showed {pattern!r}. Screen:\n{self.text()}")

    def type(self, text: str) -> None:
        self.child.send(text)

    def key(self, name: str) -> None:
        if name.startswith("ctrl+"):
            self.child.send(chr(ord(name[5:].lower()) - 96))
        else:
            self.child.send(KEYS[name])
        time.sleep(0.15)  # Textual needs a moment to tell a lone Escape from an escape sequence

    def submit(self, text: str) -> None:
        self.type(text)
        time.sleep(0.1)
        self.key("enter")

    def unlock(self) -> None:
        """Answer the password screen (creating the identity on first run)."""
        m = self.wait_for(r"Welcome to Simple Chat|Unlock your identity")
        self.submit(PASSWORD)
        if m.group(0).startswith("Welcome"):
            time.sleep(0.2)
            self.submit(PASSWORD)

    def wait_exit(self, timeout: float = 10) -> int:
        self.child.expect(pexpect.EOF, timeout=timeout)
        self.child.close()
        return self.child.exitstatus

    def kill(self) -> None:
        self.child.terminate(force=True)
