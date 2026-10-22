"""The encrypted message channel used after the handshake.

Every message is sealed with ChaCha20-Poly1305, an AEAD cipher
("authenticated encryption with associated data"): it encrypts the data and
attaches a 16-byte authentication tag. If even one bit of the ciphertext is
changed in transit, decryption fails instead of returning garbage.

Nonces: an AEAD needs a unique nonce for every message encrypted under the
same key, and reusing one is catastrophic. We use a plain counter
(0, 1, 2, ...), and since each direction has its own key the two sides can
never collide. The receiver keeps its own counter and expects exactly the
next number, so a message that an attacker replays, drops or reorders fails
to decrypt, and the connection is closed.

Plaintext layout: 1 byte message type | body
"""

import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .framing import read_frame, write_frame

# Message types
T_NICK = 2         # body: UTF-8 nickname
T_READY = 3        # body: JSON {"port"}; "I have verified your fingerprint, reach me here"
T_BYE = 4          # empty; orderly goodbye (app quitting)
T_PING = 5         # empty; keepalive, sent when the link has been quiet
T_PONG = 6         # empty; reply to PING
T_FILE_OFFER = 10  # body: JSON {"id", "name", "size"}
T_FILE_ACCEPT = 11  # body: JSON {"id"}
T_FILE_REJECT = 12  # body: JSON {"id", "reason"}
T_FILE_CHUNK = 13  # body: 4-byte transfer id | raw file bytes
T_FILE_END = 14    # body: JSON {"id", "sha256"}
T_FILE_CANCEL = 15  # body: JSON {"id", "reason"}
T_TEXT = 20        # body: JSON {"id", "sent", "text"}; a chat message
T_ACK = 21         # body: JSON {"id"}; "stored your TEXT" (queued delivery, see PROTOCOL.md)


class ChannelError(Exception):
    """A message failed authentication or was malformed."""


def _nonce(counter: int) -> bytes:
    # 96-bit nonce: 4 zero bytes followed by a 64-bit big-endian counter.
    return b"\x00\x00\x00\x00" + counter.to_bytes(8, "big")


class SecureChannel:
    def __init__(self, sock, send_key: bytes, recv_key: bytes):
        self._sock = sock
        self._send_aead = ChaCha20Poly1305(send_key)
        self._recv_aead = ChaCha20Poly1305(recv_key)
        self._send_counter = 0
        self._recv_counter = 0
        # Several threads may send (typing, file transfer). The lock keeps
        # "take the next counter value" and "write it to the socket" together,
        # so frames go out in the same order as their counters.
        self._send_lock = threading.Lock()

    def _seal(self, msg_type: int, body: bytes) -> bytes:
        frame = self._send_aead.encrypt(_nonce(self._send_counter), bytes([msg_type]) + body, None)
        self._send_counter += 1
        return frame

    def seal(self, msg_type: int, body: bytes = b"") -> bytes:
        """Encrypt one message without sending it (used by the tests)."""
        with self._send_lock:
            return self._seal(msg_type, body)

    def send(self, msg_type: int, body: bytes = b"") -> None:
        with self._send_lock:
            write_frame(self._sock, self._seal(msg_type, body))

    def open(self, frame: bytes) -> tuple[int, bytes]:
        try:
            plaintext = self._recv_aead.decrypt(_nonce(self._recv_counter), frame, None)
        except InvalidTag:
            raise ChannelError(
                "a message failed authentication (tampered with, replayed or out of order)"
            ) from None
        self._recv_counter += 1
        if not plaintext:
            raise ChannelError("empty message")
        return plaintext[0], plaintext[1:]

    def recv(self) -> tuple[int, bytes]:
        return self.open(read_frame(self._sock))
