"""Small helpers shared by the protocol code and the UI: cleaning peer text, sizes, addresses."""

from __future__ import annotations

import socket
import unicodedata
from datetime import datetime
from pathlib import Path

MAX_NICK = 32


def clean_text(text: str) -> str:
    """Strip control and invisible format characters from text a peer sent us.

    Without this, a peer could send terminal escape sequences that rewrite
    your screen, or Unicode direction overrides that disguise a file name
    ("report<RLO>gnp.exe" displays as "reportexe.png").
    """
    return "".join(
        ch for ch in text
        if ch in "\t‍" or not unicodedata.category(ch).startswith("C")
    )


def clean_nick(raw: bytes) -> str:
    nick = clean_text(raw.decode("utf-8", "replace")).strip()[:MAX_NICK]
    return nick or "peer"


def safe_filename(name: str) -> str:
    """Reduce a peer-supplied file name to a harmless base name (no paths, no dotfiles)."""
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = clean_text(name).strip().lstrip(".")[:200]
    return name or "file"


def unique_path(directory: Path, name: str) -> Path:
    """`name` in `directory`, or "name (1).ext", "name (2).ext"... if taken."""
    stem, dot, ext = name.rpartition(".")
    if not stem:
        stem, dot, ext = name, "", ""
    candidate, i = directory / name, 1
    while candidate.exists() or candidate.with_name(candidate.name + ".part").exists():
        candidate = directory / f"{stem} ({i}){dot}{ext}"
        i += 1
    return candidate


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def split_host_port(host: str, port: int) -> tuple[str, int]:
    """Accept "192.168.1.5:6000" as well as a bare host. IPv6 addresses (several colons) are left alone."""
    name, sep, maybe_port = host.rpartition(":")
    if sep and ":" not in name and maybe_port.isdigit():
        return name, int(maybe_port)
    return host, port


def local_ip() -> str | None:
    """Best guess at this machine's LAN address (no packets are actually sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            return s.getsockname()[0]
    except OSError:
        return None


def clock() -> str:
    return datetime.now().strftime("%H:%M")
