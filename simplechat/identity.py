"""Long-term identity keys and their fingerprints.

Each installation has one Ed25519 key pair - its *identity*. The public half
is shown to other people as a short fingerprint; the private half is used to
sign every handshake (see handshake.py), proving "I am the owner of this
fingerprint".

The private key is stored on disk encrypted with a password:

    password --scrypt(salt)--> 32-byte wrapping key
    ChaCha20-Poly1305(wrapping key).encrypt(private key seed)

scrypt is a deliberately slow, memory-hungry key-derivation function. A
correct password costs you a fraction of a second once at startup, but an
attacker who steals the file has to pay that cost for every guess, which
makes brute-forcing a decent password impractical.
"""

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# scrypt cost: n=2^17, r=8 uses 128 MiB of RAM and roughly half a second.
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1

FINGERPRINT_LABEL = b"simplechat-v1 fingerprint"
HISTORY_KEY_LABEL = b"simplechat-v1 history key"


class WrongPassword(Exception):
    """The password did not decrypt the identity file."""


def raw_public_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(public_bytes: bytes) -> str:
    """Short, human-comparable digest of a public key.

    We hash the key (with a domain-separation label so this hash can never be
    confused with any other hash in the protocol) and keep 128 bits, shown as
    8 groups of 4 hex digits. 128 bits is far too many for an attacker to
    brute-force a different key with the same fingerprint.
    """
    digest = hashlib.sha256(FINGERPRINT_LABEL + public_bytes).digest()[:16]
    h = digest.hex().upper()
    return "-".join(h[i:i + 4] for i in range(0, len(h), 4))


@dataclass
class Identity:
    private_key: Ed25519PrivateKey

    @property
    def public_bytes(self) -> bytes:
        return raw_public_bytes(self.private_key.public_key())

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_bytes)

    def history_key(self) -> bytes:
        """Key for encrypting chat history on disk.

        Rather than asking for a second password, we derive it from the
        identity's private key with HKDF. Anyone who can unlock the identity
        (i.e. knows the password) can read the history; nobody else can.
        """
        seed = self.private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        return HKDF(hashes.SHA256(), 32, salt=None, info=HISTORY_KEY_LABEL).derive(seed)


def _wrapping_key(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8"))


def _write_private(path: Path, data: bytes) -> None:
    """Write a file readable only by the current user, atomically."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def create_identity(path: Path, password: str, scrypt_n: int = SCRYPT_N) -> Identity:
    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = raw_public_bytes(private_key.public_key())

    salt = os.urandom(16)   # random salt: identical passwords give different keys
    nonce = os.urandom(12)  # used once, for this single encryption
    key = _wrapping_key(password, salt, scrypt_n, SCRYPT_R, SCRYPT_P)
    # The public key is passed as "associated data": it is not encrypted, but
    # it is authenticated, so swapping it in the file is detected on load.
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, seed, public)

    doc = {
        "version": 1,
        "public_key": public.hex(),
        "kdf": {"name": "scrypt", "n": scrypt_n, "r": SCRYPT_R, "p": SCRYPT_P, "salt": salt.hex()},
        "cipher": "chacha20-poly1305",
        "nonce": nonce.hex(),
        "encrypted_private_key": ciphertext.hex(),
    }
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _write_private(path, json.dumps(doc, indent=2).encode())
    return Identity(private_key)


def read_public_key(path: Path) -> bytes:
    """The public key is stored in the clear, so no password is needed."""
    return bytes.fromhex(json.loads(path.read_text())["public_key"])


def load_identity(path: Path, password: str) -> Identity:
    doc = json.loads(path.read_text())
    kdf = doc["kdf"]
    public = bytes.fromhex(doc["public_key"])
    key = _wrapping_key(password, bytes.fromhex(kdf["salt"]), kdf["n"], kdf["r"], kdf["p"])
    try:
        seed = ChaCha20Poly1305(key).decrypt(
            bytes.fromhex(doc["nonce"]), bytes.fromhex(doc["encrypted_private_key"]), public
        )
    except InvalidTag:
        # The authentication tag doesn't match: wrong password (or a damaged file).
        raise WrongPassword("wrong password") from None
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    if raw_public_bytes(private_key.public_key()) != public:
        raise ValueError("identity file is inconsistent")
    return Identity(private_key)
