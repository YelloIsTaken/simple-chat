"""The message log with one contact, including messages still waiting to be delivered.

Built on the encrypted, append-only History file. Nothing is ever rewritten;
state changes are new records (see PROTOCOL.md, "Stored data"):

    {"k": "msg", "id", "t", "dir": "in"|"out", "who", "text"}   a message
    {"k": "ack", "id"}                                          our message `id` was delivered
    {"k": "note", "t", "text"}                                  e.g. "received photo.jpg"

Queued delivery works like this: an outgoing message is written as "msg"
first. Until an "ack" record exists for its id it is *pending*, and is
re-sent each time a link to the contact comes up. Incoming ids are
remembered, so a message re-sent after a lost ack isn't shown twice.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from datetime import datetime

from .history import History, HistoryError


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def new_message_id() -> str:
    return os.urandom(16).hex()


@dataclass
class Message:
    id: str
    time: str        # ISO 8601, local time
    outgoing: bool
    who: str
    text: str
    delivered: bool  # always True for incoming messages and notes
    note: bool = False

    @property
    def clock(self) -> str:
        return self.time[11:16]


class Conversation:
    def __init__(self, history: History):
        self.history = history
        self._lock = threading.Lock()
        self.messages: list[Message] = []
        self._by_id: dict[str, Message] = {}
        self.load_error: str | None = None
        try:
            records = history.read_all()
        except HistoryError as e:
            records, self.load_error = [], str(e)
        acked = {r["id"] for r in records if r.get("k") == "ack"}
        for r in records:
            kind = r.get("k", "msg")  # v1 records have no "k": plain delivered messages
            if kind == "msg":
                mid = r.get("id") or new_message_id()
                out = r["dir"] == "out"
                self._add(Message(mid, r["t"], out, r["who"], r["text"], delivered=not out or mid in acked
                                  or "id" not in r))
            elif kind == "note":
                self._add(Message(new_message_id(), r["t"], False, "", r["text"], True, note=True))

    def _add(self, m: Message) -> None:
        self.messages.append(m)
        self._by_id[m.id] = m

    def add_outgoing(self, who: str, text: str) -> Message:
        with self._lock:
            m = Message(new_message_id(), now_iso(), True, who, text, delivered=False)
            self.history.append({"k": "msg", "id": m.id, "t": m.time, "dir": "out", "who": who, "text": text})
            self._add(m)
            return m

    def add_incoming(self, mid: str, sent: str, who: str, text: str) -> Message | None:
        """Store an incoming message. None if we already have it (a re-sent duplicate)."""
        with self._lock:
            if mid in self._by_id:
                return None
            m = Message(mid, sent or now_iso(), False, who, text, delivered=True)
            self.history.append({"k": "msg", "id": mid, "t": m.time, "dir": "in", "who": who, "text": text})
            self._add(m)
            return m

    def mark_delivered(self, mid: str) -> Message | None:
        with self._lock:
            m = self._by_id.get(mid)
            if m is None or not m.outgoing or m.delivered:
                return None
            self.history.append({"k": "ack", "id": mid})
            m.delivered = True
            return m

    def add_note(self, text: str) -> Message:
        with self._lock:
            m = Message(new_message_id(), now_iso(), False, "", text, True, note=True)
            self.history.append({"k": "note", "t": m.time, "text": text})
            self._add(m)
            return m

    def pending(self) -> list[Message]:
        with self._lock:
            return [m for m in self.messages if m.outgoing and not m.delivered]
