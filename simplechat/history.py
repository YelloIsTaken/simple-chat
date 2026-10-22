"""Encrypted, append-only chat history (one file per peer).

Each record is encrypted on its own, so we can append without rewriting the
file:

    [4-byte length][12-byte random nonce][ChaCha20-Poly1305 ciphertext + tag]

The key comes from Identity.history_key(), so only someone who knows your
password can read it. The peer's public key is included as associated data,
which binds every record to that conversation: records copied from one
peer's file into another's fail to decrypt.

Nonces here are random rather than a counter, because the counter would have
to be stored safely between runs. With 96-bit random nonces, the chance of a
repeat is negligible for any realistic amount of chat.
"""

import json
import os
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

AAD_LABEL = b"simplechat-v1 history"


class HistoryError(Exception):
    """The history file could not be decrypted (wrong key or corruption)."""


class History:
    def __init__(self, directory: Path, key: bytes, peer_public: bytes):
        self.path = directory / f"{peer_public.hex()[:32]}.log"
        self._aead = ChaCha20Poly1305(key)
        self._aad = AAD_LABEL + peer_public
        self._dir = directory

    def append(self, record: dict) -> None:
        self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        nonce = os.urandom(12)
        blob = nonce + self._aead.encrypt(nonce, json.dumps(record).encode(), self._aad)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "ab") as f:
            f.write(struct.pack(">I", len(blob)) + blob)

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        data = self.path.read_bytes()
        records, pos = [], 0
        while pos + 4 <= len(data):
            (length,) = struct.unpack_from(">I", data, pos)
            blob = data[pos + 4:pos + 4 + length]
            if len(blob) < length:
                break  # last record was cut short (e.g. crash while writing); ignore it
            try:
                plaintext = self._aead.decrypt(blob[:12], blob[12:], self._aad)
            except InvalidTag:
                raise HistoryError(f"cannot decrypt {self.path} (wrong key or corrupted)") from None
            records.append(json.loads(plaintext))
            pos += 4 + length
        return records
