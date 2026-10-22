"""Full-screen terminal interface, built with Textual (https://textual.textualize.io).

Layout (like a chat app with direct messages):

    ┌ Simple Chat ─────────────────────────────────────────────────┐
    │ CONTACTS          │ ● alice · online · 0009-EFD9-…           │
    │ ● alice        2  │ 12:01 alice: hi                          │
    │ ● bob             │ 12:02 you: hello ✓                        │
    │ ○ carol    ⏳1    │ 12:03 you: are you there? ⏳              │
    │ NEARBY            │                                          │
    │ + dave            │ [ message input                       ]  │
    └ ^A Add  ^O Send file  ^N Nickname  ^D Remove  ^Q Quit ───────┘

* Contacts are green (●) while there's a live link to them, grey (○) when
  not. Unread counts and queued (⏳) messages are shown next to the name.
* "Nearby" lists people announcing themselves on the LAN; pick one to add.
* Messages to offline contacts are queued (⏳) and delivered automatically
  (✓) when the contact comes online.

How Textual works, in brief
---------------------------
* `compose()` yields the widgets a screen is made of; CSS lays them out.
* User actions arrive as messages, handled by `on_...` methods or `@on(...)`,
  and by `action_...` methods that BINDINGS map to keys (shown in the footer).
* All UI work happens on one thread. The messenger runs on background
  threads and reports through `TuiEvents`, which hands every update to the
  UI thread with `app.call_from_thread(...)`.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button, DirectoryTree, Footer, Header, Input, Label, OptionList, ProgressBar, RichLog, Static,
)
from textual.widgets.option_list import Option

from .conversation import Message
from .identity import Identity, WrongPassword, create_identity, load_identity
from .link import FileOffer, Transfer
from .messenger import DEFAULT_PORT, KeyChanged, Messenger, TrustRequest
from .textutil import MAX_NICK, clean_text, human_size, local_ip, split_host_port

MIN_PASSWORD = 8
PASSWORD_ATTEMPTS = 3
SHOWN_MESSAGES = 500  # the conversation pane shows at most the last 500 messages

HELP = """\
Up/Down, Enter   pick a contact (or a nearby person, to add them)
Tab              move between the contact list and the message box
Enter            send the message (queued if the contact is offline)
Ctrl+A           add a contact by address (IP or host:port)
Ctrl+O           send a file to the selected contact (or /send <path>)
Ctrl+N           change your nickname
Ctrl+D           remove the selected contact
Ctrl+Q           quit

●  online      ○  offline      ⏳ queued, not delivered yet      ✓ delivered"""


def short_fp(fp: str) -> str:
    return "-".join(fp.split("-")[:2]) + "-…"


# ===========================================================================
# Dialogs (modal screens: shown on top of the current screen, block it)
# ===========================================================================

class Dialog(ModalScreen):
    """Base for the pop-ups: a centred box; `dismiss(value)` closes it and returns value."""

    DEFAULT_CSS = """
    Dialog { align: center middle; background: $background 60%; }
    Dialog > Vertical {
        width: 76; max-width: 95%; height: auto; max-height: 90%;
        border: thick $primary; background: $surface; padding: 1 2;
    }
    Dialog.danger > Vertical { border: thick $error; }
    Dialog Label { width: 100%; }  /* full width, so long text wraps instead of being cut off */
    Dialog .title { text-style: bold; margin-bottom: 1; }
    Dialog .fingerprint { text-style: bold; color: $accent; margin-bottom: 1; }
    Dialog .buttons { height: auto; align-horizontal: right; margin-top: 1; }
    Dialog .buttons Button { margin-left: 2; }
    """


class TrustDialog(Dialog):
    """Compare fingerprints. Escape counts as "no": the check can't be skipped."""

    BINDINGS = [Binding("y", "answer(True)", "They match"), Binding("n,escape", "answer(False)", "Decline")]

    def __init__(self, request: TrustRequest):
        super().__init__()
        self.request = request

    def compose(self) -> ComposeResult:
        r = self.request
        title = (f"Contact request from '{r.peer_nick}' ({r.address})" if r.incoming
                 else f"Add '{r.peer_nick}' ({r.address}) as a contact?")
        with Vertical():
            yield Label(title, classes="title")
            yield Label("Their fingerprint:")
            yield Label(r.peer_fingerprint, classes="fingerprint", id="peer-fingerprint")
            yield Label("Your fingerprint:")
            yield Label(r.my_fingerprint, classes="fingerprint")
            yield Label("Compare BOTH fingerprints with them over a channel you trust "
                        "(in person, a phone call). The nickname proves nothing.")
            with Horizontal(classes="buttons"):
                yield Button("Decline (n)", id="no", variant="error")
                yield Button("They match (y)", id="yes", variant="success")

    def on_mount(self) -> None:
        self.query_one("#no", Button).focus()  # the safe choice has focus

    def action_answer(self, trusted: bool) -> None:
        self.dismiss(trusted)

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")


class OfferDialog(Dialog):
    BINDINGS = [Binding("y", "answer(True)", "Accept"), Binding("n,escape", "answer(False)", "Decline")]

    def __init__(self, peer: str, offer: FileOffer, download_dir: Path):
        super().__init__()
        self.peer, self.offer, self.download_dir = peer, offer, download_dir

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Incoming file", classes="title")
            yield Label(f"{self.peer} wants to send you '{self.offer.name}' ({human_size(self.offer.size)}).")
            yield Label(f"It will be saved in {self.download_dir.resolve()}/")
            with Horizontal(classes="buttons"):
                yield Button("Decline (n)", id="no")
                yield Button("Accept (y)", id="yes", variant="primary")

    def action_answer(self, accept: bool) -> None:
        self.dismiss(accept)

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")


class MessageDialog(Dialog):
    """A notice with an OK button: warnings, help."""

    BINDINGS = [Binding("escape,enter", "close", "Close")]

    def __init__(self, title: str, body: str, danger: bool = False):
        super().__init__(classes="danger" if danger else "")
        self.title_text, self.body = title, body

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self.title_text, classes="title")
            yield Label(self.body)
            with Horizontal(classes="buttons"):
                yield Button("OK", id="ok", variant="primary")

    def action_close(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed)
    def pressed(self) -> None:
        self.dismiss(None)


class ConfirmDialog(Dialog):
    BINDINGS = [Binding("y", "answer(True)", "Yes"), Binding("n,escape", "answer(False)", "No")]

    def __init__(self, question: str):
        super().__init__()
        self.question = question

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self.question, classes="title")
            with Horizontal(classes="buttons"):
                yield Button("No (n)", id="no")
                yield Button("Yes (y)", id="yes", variant="primary")

    def action_answer(self, yes: bool) -> None:
        self.dismiss(yes)

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")


class TextDialog(Dialog):
    """Ask for one line of text (nickname, address)."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, title: str, value: str = "", placeholder: str = "", hint: str = ""):
        super().__init__()
        self.title_text, self.value, self.placeholder, self.hint = title, value, placeholder, hint

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self.title_text, classes="title")
            if self.hint:
                yield Label(self.hint)
            yield Input(self.value, placeholder=self.placeholder, id="value")

    @on(Input.Submitted)
    def submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value.strip() or None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class FilePickerDialog(Dialog):
    """Browse for a file to send, or type its path."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]
    DEFAULT_CSS = """
    FilePickerDialog > Vertical { width: 90; height: 80%; }
    FilePickerDialog DirectoryTree { height: 1fr; border: round $primary-darken-2; }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Send a file: pick it below (Enter), or type a path", classes="title")
            yield DirectoryTree(Path.home(), id="tree")
            yield Input(placeholder="/path/to/file", id="path")

    def on_mount(self) -> None:
        self.query_one("#tree").focus()

    @on(DirectoryTree.FileSelected)
    def picked(self, event: DirectoryTree.FileSelected) -> None:
        self.dismiss(Path(event.path))

    @on(Input.Submitted)
    def typed(self, event: Input.Submitted) -> None:
        if event.value.strip():
            self.dismiss(Path(event.value.strip().strip("'\"")))

    def action_cancel(self) -> None:
        self.dismiss(None)


# ===========================================================================
# Unlock screen
# ===========================================================================

class UnlockScreen(Screen):
    """Unlock the identity key with its password, or create one on first run.

    The key derivation (scrypt) deliberately takes about half a second, so it
    runs on a worker thread to keep the screen responsive.
    """

    DEFAULT_CSS = """
    UnlockScreen { align: center middle; }
    UnlockScreen > Vertical {
        width: 64; height: auto; border: thick $primary; padding: 1 2; background: $surface;
    }
    UnlockScreen .title { text-style: bold; margin-bottom: 1; }
    UnlockScreen Label { width: 100%; }
    UnlockScreen #error { color: $error; height: auto; }
    """

    def __init__(self, path: Path):
        super().__init__()
        self.path = path
        self.creating = not path.exists()
        self.attempts = 0

    def compose(self) -> ComposeResult:
        with Vertical():
            if self.creating:
                yield Label("Welcome to Simple Chat!", classes="title")
                yield Label("Choose a password. It protects your private key and your chat history.")
                yield Input(placeholder="New password", password=True, id="pw")
                yield Input(placeholder="Repeat password", password=True, id="pw2")
            else:
                yield Label("Unlock your identity", classes="title")
                yield Input(placeholder="Password", password=True, id="pw")
            yield Static("", id="error")

    def on_mount(self) -> None:
        self.query_one("#pw").focus()

    @on(Input.Submitted, "#pw")
    def password_entered(self) -> None:
        if self.creating:
            self.query_one("#pw2").focus()
        else:
            self.unlock(self.query_one("#pw", Input).value)

    @on(Input.Submitted, "#pw2")
    def password_repeated(self) -> None:
        pw, pw2 = self.query_one("#pw", Input).value, self.query_one("#pw2", Input).value
        if len(pw) < MIN_PASSWORD:
            self.show_error(f"Please use at least {MIN_PASSWORD} characters.")
        elif pw != pw2:
            self.show_error("The passwords don't match.")
        else:
            self.create(pw)

    def show_error(self, text: str) -> None:
        self.query_one("#error", Static).update(text)
        for field in self.query(Input):
            field.disabled = False
            field.value = ""
        self.query_one("#pw").focus()

    def busy(self, text: str) -> None:
        self.query_one("#error", Static).update(Text(text, style="dim"))
        for field in self.query(Input):
            field.disabled = True

    @work(thread=True)
    def create(self, password: str) -> None:
        self.app.call_from_thread(self.busy, "Deriving key (this takes a moment)…")
        identity = create_identity(self.path, password)
        self.app.call_from_thread(self.dismiss, identity)

    @work(thread=True)
    def unlock(self, password: str) -> None:
        self.app.call_from_thread(self.busy, "Unlocking…")
        try:
            identity = load_identity(self.path, password)
        except WrongPassword:
            self.attempts += 1
            if self.attempts >= PASSWORD_ATTEMPTS:
                self.app.call_from_thread(self.app.exit, None, 1, "Wrong password.")
            else:
                left = PASSWORD_ATTEMPTS - self.attempts
                self.app.call_from_thread(self.show_error, f"Wrong password ({left} attempts left).")
            return
        self.app.call_from_thread(self.dismiss, identity)


# ===========================================================================
# Main screen: contacts on the left, the selected conversation on the right
# ===========================================================================

class MainScreen(Screen):
    # priority=True: these keys work even while the message box has focus.
    BINDINGS = [
        Binding("ctrl+a", "add", "Add contact", priority=True),
        Binding("ctrl+o", "send_file", "Send file", priority=True),
        Binding("ctrl+n", "nick", "Nickname", priority=True),
        Binding("ctrl+d", "remove", "Remove", priority=True),
        Binding("f1", "help", "Help", priority=True),
    ]

    DEFAULT_CSS = """
    MainScreen #body { height: 1fr; }
    MainScreen #sidebar { width: 32; border-right: solid $panel-lighten-2; }
    MainScreen #contacts { height: 1fr; border: none; background: $surface; }
    MainScreen #me { height: auto; padding: 0 1; background: $boost; }
    MainScreen #main { width: 1fr; }
    MainScreen #conv-header { height: 1; padding: 0 1; background: $boost; }
    MainScreen #log { height: 1fr; padding: 0 1; }
    MainScreen #transfers { height: auto; padding: 0 1; }
    MainScreen #transfers.empty { display: none; }
    MainScreen #transfers ProgressBar { width: 1fr; }
    """

    def __init__(self):
        super().__init__()
        self.transfers: dict[tuple[bytes, str], tuple[Label, ProgressBar]] = {}

    @property
    def messenger(self) -> Messenger:
        return self.app.messenger

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):
                yield OptionList(id="contacts")
                yield Static(id="me")
            with Vertical(id="main"):
                yield Static(id="conv-header")
                yield RichLog(wrap=True, min_width=20, id="log")
                yield Vertical(id="transfers", classes="empty")
                yield Input(placeholder="Pick a contact on the left", id="message", disabled=True)
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_contacts()
        self.update_me()
        self.show_conversation()
        self.query_one("#contacts").focus()

    # ---- the sidebar --------------------------------------------------------

    def refresh_contacts(self) -> None:
        """Rebuild the contact list, keeping the highlighted entry where it was."""
        options = self.query_one("#contacts", OptionList)
        keep = options.highlighted_option.id if options.highlighted_option else None
        entries: list[Option | None] = [Option(Text("CONTACTS", style="bold dim"), disabled=True)]
        contacts = self.messenger.contact_list()
        if not contacts:
            entries.append(Option(Text("none yet, Ctrl+A to add", style="dim italic"), disabled=True))
        for c in contacts:
            line = Text()
            line.append("● " if c.online else "○ ", style="green" if c.online else "dim")
            line.append(c.nick, style="bold" if c.unread else ("" if c.online else "dim"))
            if c.pending:
                line.append(f"  ⏳{c.pending}", style="yellow")
            if c.unread:
                line.append(f"  {c.unread}", style="bold reverse cyan")
            entries.append(Option(line, id="c:" + c.public_key.hex()))
        nearby = self.messenger.nearby()
        if nearby:
            entries += [None, Option(Text("NEARBY", style="bold dim"), disabled=True)]
            for p in nearby:
                entries.append(Option(Text.assemble(("+ ", "cyan"), p.nick, (f"  {p.address}", "dim")),
                                      id="n:" + p.public_key.hex()))
        options.clear_options()
        options.add_options(entries)
        selectable = [o.id for o in entries if o is not None and not o.disabled]
        if keep not in selectable:  # gone (e.g. a nearby person became a contact) or nothing yet
            keep = ("c:" + self.app.current.hex()) if self.app.current else None
            keep = keep if keep in selectable else (selectable[0] if selectable else None)
        if keep:
            options.highlighted = options.get_option_index(keep)

    def update_me(self) -> None:
        app: SimpleChatApp = self.app
        self.query_one("#me", Static).update(Text.assemble(
            ("You: ", "dim"), (app.messenger.nick, "bold"), "\n",
            (short_fp(app.identity.fingerprint), "dim"), (f"  port {app.messenger.port}", "dim")))

    @on(OptionList.OptionSelected, "#contacts")
    def picked(self, event: OptionList.OptionSelected) -> None:
        kind, key = event.option.id.split(":", 1)
        pk = bytes.fromhex(key)
        if kind == "c":
            self.app.current = pk
            self.messenger.open_conversation(pk)
            self.show_conversation()
            self.query_one("#message").focus()
        else:
            peer = next((p for p in self.messenger.nearby() if p.public_key == pk), None)
            if peer:
                self.notify(f"Connecting to {peer.nick}… compare fingerprints when asked.")
                self.messenger.add_nearby(pk)

    # ---- the conversation pane ----------------------------------------------

    def show_conversation(self) -> None:
        """Redraw the header and all messages of the selected contact."""
        log = self.query_one("#log", RichLog)
        log.clear()
        field = self.query_one("#message", Input)
        pk = self.app.current
        contact = self.messenger.contacts.get(pk) if pk else None
        if contact is None:
            self.app.current = None
            self.query_one("#conv-header", Static).update(Text("No conversation selected", style="dim"))
            log.write(Text("Welcome! Your contacts are on the left: green ● is online, grey ○ is offline.\n"
                           "People on your network who run Simple Chat appear under NEARBY: pick one "
                           "to add them. Or press Ctrl+A to add someone by IP address.\n"
                           "Everything is end-to-end encrypted. Press F1 for help.", style="dim"))
            field.disabled, field.placeholder = True, "Pick a contact on the left"
            return
        self.update_header()
        conv = self.messenger.conversation(pk)
        if conv.load_error:
            log.write(Text(conv.load_error, style="bold red"))
        for m in conv.messages[-SHOWN_MESSAGES:]:
            self.write_message(m)
        field.disabled = False
        field.placeholder = f"Message {contact.label}"

    def update_header(self) -> None:
        pk = self.app.current
        contact = self.messenger.contacts.get(pk) if pk else None
        if contact is None:
            return
        online = self.messenger.is_online(pk)
        self.query_one("#conv-header", Static).update(Text.assemble(
            ("● " if online else "○ ", "green" if online else "dim"), (contact.label, "bold"),
            ("  online · end-to-end encrypted" if online else "  offline · messages will be queued", "dim"),
            ("   " + contact.fingerprint, "dim")))

    def write_message(self, m: Message) -> None:
        # Text objects, never markup strings: a peer typing "[red]" must stay literal.
        log = self.query_one("#log", RichLog)
        if m.note:
            log.write(Text(f"── {m.text}", style="green"))
            return
        line = Text.assemble((f"{m.clock} ", "dim"),
                             (f"{m.who}: ", "bold green" if m.outgoing else "bold cyan"), m.text)
        if m.outgoing:
            line.append(" ✓" if m.delivered else " ⏳", style="dim" if m.delivered else "yellow")
        log.write(line)

    def add_notice(self, text: str, level: str) -> None:
        style = {"info": "italic dim", "success": "green", "error": "bold red"}.get(level, "")
        self.query_one("#log", RichLog).write(Text(f"── {text}", style=style))

    def transfer(self, contact: bytes, t: Transfer, finished: bool) -> None:
        key = (contact, t.id)
        box = self.query_one("#transfers")
        if finished:
            for widget in self.transfers.pop(key, ()):
                widget.remove()
        else:
            if key not in self.transfers:
                peer = self.messenger.contacts.get(contact)
                arrow = "↑" if t.outgoing else "↓"
                label = Label(f"{arrow} {t.name} ({human_size(t.size)}) {'to' if t.outgoing else 'from'} "
                              f"{peer.label if peer else '?'}")
                bar = ProgressBar(total=max(t.size, 1), show_eta=False)
                self.transfers[key] = (label, bar)
                box.mount(label, bar)
            self.transfers[key][1].update(total=max(t.size, 1), progress=t.done)
        box.set_class(not self.transfers, "empty")

    # ---- what the user does -------------------------------------------------

    @on(Input.Submitted, "#message")
    def message_submitted(self, event: Input.Submitted) -> None:
        text = event.value
        pk = self.app.current
        if not text.strip() or pk is None:
            return
        event.input.value = ""
        if text.startswith("/send "):
            self.offer(Path(text[6:].strip().strip("'\"")))
        elif text.strip() == "/help":
            self.action_help()
        elif error := self.messenger.send(pk, text):
            self.notify(error, severity="error")

    def offer(self, path: Path | None) -> None:
        if path is not None and self.app.current is not None:
            if error := self.messenger.send_file(self.app.current, path):
                self.notify(error, severity="error")

    def action_send_file(self) -> None:
        if self.app.current is None:
            self.notify("Pick a contact first.", severity="warning")
        elif not self.messenger.is_online(self.app.current):
            self.notify("Files can only be sent while the contact is online.", severity="warning")
        else:
            self.app.push_screen(FilePickerDialog(), self.offer)

    def action_add(self) -> None:
        def entered(address: str | None) -> None:
            if address:
                host, port = split_host_port(address, DEFAULT_PORT)
                self.notify(f"Connecting to {host}:{port}… compare fingerprints when asked.")
                self.messenger.add_by_address(host, port)

        ip = local_ip()
        hint = f"Your address (for the other person): {ip}:{self.messenger.port}" if ip else ""
        self.app.push_screen(TextDialog("Add a contact by address", placeholder="192.168.1.20 or host:port",
                                        hint=hint), entered)

    def action_nick(self) -> None:
        def entered(nick: str | None) -> None:
            nick = clean_text(nick or "").strip()[:MAX_NICK]
            if nick:
                self.messenger.set_nick(nick)
                self.update_me()

        self.app.push_screen(TextDialog("Your new nickname", self.messenger.nick), entered)

    def action_remove(self) -> None:
        pk = self.app.current
        contact = self.messenger.contacts.get(pk) if pk else None
        if contact is None:
            self.notify("Pick a contact first.", severity="warning")
            return

        def confirmed(yes: bool) -> None:
            if yes:
                self.messenger.remove_contact(pk)
                self.app.current = None
                self.show_conversation()

        self.app.push_screen(ConfirmDialog(
            f"Remove '{contact.label}' ({contact.fingerprint}) from your contacts? "
            "You'd have to compare fingerprints again to re-add them."), confirmed)

    def action_help(self) -> None:
        self.app.push_screen(MessageDialog("Keys", HELP))


# ===========================================================================
# Messenger -> UI bridge
# ===========================================================================

class TuiEvents:
    """Receives the messenger's events (on its threads) and shows them on the main screen.

    `call_from_thread` runs a function on the UI thread and waits for it, so
    widgets are only ever touched from the UI thread.
    """

    def __init__(self, app: SimpleChatApp):
        self.app = app
        self.offer_dialogs: dict[bytes, OfferDialog] = {}

    def _ui(self, fn, *args) -> bool:
        try:
            if threading.get_ident() == self.app.ui_thread:
                fn(*args)
            else:
                self.app.call_from_thread(fn, *args)
            return True
        except RuntimeError:  # the app is shutting down
            return False

    @property
    def main(self) -> MainScreen | None:
        return self.app.main

    def contacts_changed(self) -> None:
        self._ui(self._contacts_changed)

    def _contacts_changed(self) -> None:
        if self.main:
            self.main.refresh_contacts()
            self.main.update_header()

    def nearby_changed(self) -> None:
        self._ui(self._contacts_changed)

    def message(self, contact: bytes, message: Message, new: bool) -> None:
        self._ui(self._message, contact, message, new)

    def _message(self, contact: bytes, message: Message, new: bool) -> None:
        if not self.main or contact != self.app.current:
            if new and not message.outgoing and not message.note:
                peer = self.app.messenger.contacts.get(contact)
                self.app.notify(message.text[:80], title=peer.label if peer else "message")
            return
        if new:
            self.main.write_message(message)
        else:
            self.main.show_conversation()  # a ⏳ became ✓: redraw (the log can't edit lines)

    def confirm_trust(self, request: TrustRequest) -> bool:
        # Show the dialog on the UI thread, then wait here, on the link's thread.
        answer: dict[str, bool] = {}
        done = threading.Event()

        def on_answer(trusted: bool) -> None:
            answer["trusted"] = bool(trusted)
            done.set()

        if not self._ui(self.app.push_screen, TrustDialog(request), on_answer):
            return False
        while not done.wait(0.2):
            if self.app.messenger.stopped.is_set():
                return False
        return answer["trusted"]

    def key_changed(self, w: KeyChanged) -> None:
        self._ui(self.app.push_screen, MessageDialog(
            "WARNING: the identity key at this address has changed!",
            f"{w.address} used to be '{w.old_label}'\n  {w.old_fingerprint}\n"
            f"but now presents a different key:\n  {w.new_fingerprint}\n\n"
            "Someone may be intercepting this connection (man-in-the-middle), or your contact "
            "reinstalled the app. Confirm with them directly. If it's legitimate, remove "
            f"'{w.old_label}' (Ctrl+D) and add them again.\n\nConnection refused.",
            danger=True,
        ))

    def file_offer(self, contact: bytes, offer: FileOffer | None) -> None:
        self._ui(self._file_offer, contact, offer)

    def _file_offer(self, contact: bytes, offer: FileOffer | None) -> None:
        if offer is None:  # answered or withdrawn
            dialog = self.offer_dialogs.pop(contact, None)
            if dialog and dialog.is_attached:
                dialog.dismiss(None)
            return

        def answered(accept: bool | None) -> None:
            self.offer_dialogs.pop(contact, None)
            if accept is True:
                self.app.messenger.accept_offer(contact)
            elif accept is False:
                self.app.messenger.reject_offer(contact)

        peer = self.app.messenger.contacts.get(contact)
        dialog = OfferDialog(peer.label if peer else "?", offer, self.app.messenger.download_dir)
        self.offer_dialogs[contact] = dialog
        self.app.push_screen(dialog, answered)

    def transfer(self, contact: bytes, progress: Transfer, finished: bool) -> None:
        self._ui(self._transfer, contact, progress, finished)

    def _transfer(self, contact: bytes, progress: Transfer, finished: bool) -> None:
        if self.main:
            self.main.transfer(contact, progress, finished)

    def notice(self, contact: bytes | None, text: str, level: str = "info") -> None:
        self._ui(self._notice, contact, text, level)

    def _notice(self, contact: bytes | None, text: str, level: str) -> None:
        if self.main and contact is not None and contact == self.app.current:
            self.main.add_notice(text, level)
        else:
            self.app.notify(text, severity="error" if level == "error" else "information", timeout=8)


# ===========================================================================
# The application
# ===========================================================================

class SimpleChatApp(App):
    TITLE = "Simple Chat"
    BINDINGS = [Binding("ctrl+q", "quit", "Quit", priority=True)]

    def __init__(self, home: Path, nick: str, download_dir: Path, port: int = DEFAULT_PORT,
                 connect_to: tuple[str, int] | None = None, messenger_options: dict | None = None):
        super().__init__()
        self.data_home = home
        self.nick = nick
        self.download_dir = download_dir
        self.port = port
        self.connect_to = connect_to
        self.messenger_options = messenger_options or {}  # for tests: bind address, discovery ports
        self.identity: Identity | None = None
        self.messenger: Messenger | None = None
        self.main: MainScreen | None = None
        self.current: bytes | None = None  # the contact whose conversation is shown
        self.ui_thread = threading.get_ident()

    def on_mount(self) -> None:
        self.ui_thread = threading.get_ident()
        self.push_screen(UnlockScreen(self.data_home / "identity.json"), self.unlocked)

    def unlocked(self, identity: Identity) -> None:
        self.identity = identity
        self.sub_title = f"you are {self.nick} · {short_fp(identity.fingerprint)}"
        self.messenger = Messenger(identity, self.data_home, self.nick, self.download_dir, TuiEvents(self),
                                   port=self.port, **self.messenger_options)
        try:
            self.messenger.start()
        except OSError as e:
            self.messenger = None
            self.call_later(self.push_screen, MessageDialog(
                f"Can't listen on port {self.port}",
                f"{e}\n\nIs Simple Chat already running? Start it with another port: "
                "simplechat --port 5001", danger=True), lambda _: self.exit(None, 1))
            return
        # Change screens only after Textual has finished closing the unlock screen.
        self.call_later(self.show_main)

    async def show_main(self) -> None:
        self.main = MainScreen()
        await self.push_screen(self.main)
        if self.connect_to:
            self.messenger.add_by_address(*self.connect_to)

    async def action_quit(self) -> None:
        if self.messenger:
            # Say goodbye to everyone (on a worker thread, so the UI stays responsive).
            await asyncio.to_thread(self.messenger.stop)
        self.exit()
