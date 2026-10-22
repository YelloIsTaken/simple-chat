"""The authenticated key exchange that opens every session.

Goal: both sides end up with the same secret session keys, and each side
knows for certain which long-term identity key the other side holds.

Ingredients
-----------
* X25519 (elliptic-curve Diffie-Hellman). Each side generates a fresh,
  throw-away ("ephemeral") key pair for this session only. After swapping the
  public halves, both sides can compute the same shared secret, but an
  eavesdropper who sees both public keys cannot. The ephemeral private keys
  are forgotten when the session ends, so recorded traffic stays safe even if
  a long-term key is stolen later. This is called *forward secrecy*.

* Ed25519 signatures. Diffie-Hellman alone doesn't tell you *who* you are
  talking to: a man-in-the-middle could run one exchange with each side. So
  each side signs a hash of everything exchanged so far (the *transcript*)
  with its long-term identity key. Nobody can forge that signature without
  the private key, and the user checks the identity key itself by comparing
  fingerprints (see trust.py).

* HKDF-SHA256 turns the raw Diffie-Hellman output into two independent
  32-byte keys, one for each direction.

Message flow
------------
    initiator (connect)                        responder (listen)
    HELLO = magic | id_pub | eph_pub   --->
                                       <---    HELLO = magic | id_pub | eph_pub
    transcript = SHA-256(label | HELLO_initiator | HELLO_responder)
    AUTH  = Sign(id_key, "I" | transcript) --->
                                       <---    AUTH = Sign(id_key, "R" | transcript)
    both: keys = HKDF(X25519(my_eph, peer_eph), salt = transcript)

The role letter ("I"/"R") inside the signed data stops an attacker from
reflecting a side's own signature back to it.
"""

import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .framing import read_frame, write_frame
from .identity import raw_public_bytes

MAGIC = b"SCHATv2\x00"  # identifies the protocol and its version (see PROTOCOL.md)
HELLO_LEN = len(MAGIC) + 32 + 32

ROLE_INITIATOR = b"I"
ROLE_RESPONDER = b"R"

TRANSCRIPT_LABEL = b"simplechat-v1 transcript"
AUTH_LABEL = b"simplechat-v1 auth"
KEYS_LABEL = b"simplechat-v1 session keys"


class HandshakeError(Exception):
    """The peer failed to authenticate or spoke an unexpected protocol."""


@dataclass(frozen=True)
class HandshakeResult:
    peer_public: bytes  # the peer's long-term Ed25519 public key (raw 32 bytes)
    send_key: bytes     # encrypts what we send
    recv_key: bytes     # decrypts what we receive


def perform_handshake(sock, identity_key: Ed25519PrivateKey, role: bytes) -> HandshakeResult:
    if role not in (ROLE_INITIATOR, ROLE_RESPONDER):
        raise ValueError("bad role")
    peer_role = ROLE_RESPONDER if role == ROLE_INITIATOR else ROLE_INITIATOR

    # 1. Fresh ephemeral key pair, used for this session only.
    ephemeral = X25519PrivateKey.generate()
    my_eph_pub = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    my_hello = MAGIC + raw_public_bytes(identity_key.public_key()) + my_eph_pub

    # 2. Swap HELLOs. Both sides send first and then read, which is fine:
    #    the messages are tiny and fit in the TCP buffers.
    write_frame(sock, my_hello)
    peer_hello = read_frame(sock)
    if len(peer_hello) != HELLO_LEN or not peer_hello.startswith(MAGIC):
        raise HandshakeError("the other side is not a simplechat peer (or uses another version)")
    peer_id_pub = peer_hello[len(MAGIC):len(MAGIC) + 32]
    peer_eph_pub = peer_hello[len(MAGIC) + 32:]
    if peer_eph_pub == my_eph_pub:
        raise HandshakeError("our own HELLO was reflected back to us")

    # 3. Hash of everything both sides said, in a fixed (initiator-first) order.
    #    Any tampering with either HELLO changes this hash and breaks step 4.
    hello_i, hello_r = (my_hello, peer_hello) if role == ROLE_INITIATOR else (peer_hello, my_hello)
    transcript = hashlib.sha256(TRANSCRIPT_LABEL + hello_i + hello_r).digest()

    # 4. Prove ownership of our identity key by signing the transcript, and
    #    check the peer's proof against the identity key it claimed.
    write_frame(sock, identity_key.sign(AUTH_LABEL + role + transcript))
    peer_sig = read_frame(sock)
    try:
        Ed25519PublicKey.from_public_bytes(peer_id_pub).verify(peer_sig, AUTH_LABEL + peer_role + transcript)
    except (InvalidSignature, ValueError):
        raise HandshakeError("the peer's signature is invalid - possible man-in-the-middle") from None

    # 5. Diffie-Hellman: combine our ephemeral private key with theirs.
    try:
        shared_secret = ephemeral.exchange(X25519PublicKey.from_public_bytes(peer_eph_pub))
    except ValueError:
        # e.g. a malicious "low-order" point that would force a predictable secret
        raise HandshakeError("the peer sent an invalid ephemeral key") from None

    # 6. Stretch the shared secret into one key per direction. Using the
    #    transcript as the salt ties the keys to this exact conversation.
    okm = HKDF(hashes.SHA256(), 64, salt=transcript, info=KEYS_LABEL).derive(shared_secret)
    key_i2r, key_r2i = okm[:32], okm[32:]
    if role == ROLE_INITIATOR:
        return HandshakeResult(peer_id_pub, send_key=key_i2r, recv_key=key_r2i)
    return HandshakeResult(peer_id_pub, send_key=key_r2i, recv_key=key_i2r)
