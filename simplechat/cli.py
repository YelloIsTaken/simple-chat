"""Command line: parses arguments, runs the plain commands, or starts the TUI.

    simplechat [--port N]              the full-screen app (always reachable on port N)
    simplechat connect HOST[:PORT]     the app, adding a contact by address straight away
    simplechat fingerprint | peers | forget X   plain commands, no UI
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import __version__
from .identity import fingerprint, read_public_key
from .messenger import DEFAULT_PORT
from .textutil import MAX_NICK, clean_text, split_host_port
from .trust import KnownPeers


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="simplechat",
        description="End-to-end encrypted chat between two computers. "
                    "Run without a command for the full-screen app.",
    )
    p.add_argument("--version", action="version", version=f"simplechat {__version__}")
    p.add_argument("--home", type=Path,
                   help="data directory (default: $SIMPLECHAT_HOME or ~/.simplechat)")
    p.add_argument("--nick", help="your display name (default: your user name)")
    p.add_argument("--download-dir", type=Path, default=Path("received"),
                   help="where received files are saved (default ./received)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT,
                   help=f"TCP port others reach you on (default {DEFAULT_PORT})")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("listen", help="same as no command (the app always listens)")
    sp = sub.add_parser("connect", help="start the app and add a contact by address")
    sp.add_argument("host", help="IP address or host name (host:port also works)")

    sub.add_parser("fingerprint", help="show your own fingerprint")
    sub.add_parser("peers", help="list trusted peers")
    sp = sub.add_parser("forget", help="remove a trusted peer")
    sp.add_argument("peer", help="fingerprint (or its beginning) or saved name")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    home = Path(args.home or os.environ.get("SIMPLECHAT_HOME") or Path.home() / ".simplechat")

    if args.command == "fingerprint":
        path = home / "identity.json"
        if not path.exists():
            print("No identity yet. Run simplechat once to create one.")
            return 1
        print(fingerprint(read_public_key(path)))
        return 0
    if args.command == "peers":
        peers = KnownPeers(home / "known_peers.json").all()
        if not peers:
            print("No trusted peers yet.")
        for peer in peers:
            print(f"{peer.label:<20} {peer.fingerprint}   seen at: {', '.join(peer.hosts) or '-'}")
        return 0
    if args.command == "forget":
        removed = KnownPeers(home / "known_peers.json").forget(args.peer)
        for peer in removed:
            print(f"Forgot '{peer.label}' ({peer.fingerprint}).")
        if not removed:
            print("No matching peer.")
        return 0 if removed else 1

    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("simplechat needs an interactive terminal.", file=sys.stderr)
        return 1

    connect_to = split_host_port(args.host, DEFAULT_PORT) if args.command == "connect" else None

    # Imported here so the plain commands above start instantly.
    from .tui import SimpleChatApp

    nick = clean_text(args.nick or getpass.getuser()).strip()[:MAX_NICK] or "me"
    app = SimpleChatApp(home, nick, args.download_dir, args.port, connect_to)
    app.run()
    return app.return_code or 0
