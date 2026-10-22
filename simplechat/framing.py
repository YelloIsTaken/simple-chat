"""Length-prefixed framing over a TCP stream.

TCP delivers a stream of bytes with no message boundaries: one send() may
arrive as several recv()s, or two sends may arrive glued together. So every
frame is written as a 4-byte big-endian length followed by exactly that many
bytes, and the reader reassembles frames from the stream.
"""

import struct

MAX_FRAME = 1 << 20  # 1 MiB. Anything bigger is treated as a protocol error,
                     # so a hostile peer cannot make us allocate huge buffers.


class ConnectionClosed(Exception):
    """The peer closed the connection."""


class FrameError(Exception):
    """A frame was malformed or too large."""


def write_frame(sock, data: bytes) -> None:
    if len(data) > MAX_FRAME:
        raise FrameError(f"frame too large ({len(data)} bytes)")
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionClosed("peer closed the connection")
        buf += chunk
    return bytes(buf)


def read_frame(sock) -> bytes:
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    if length > MAX_FRAME:
        raise FrameError(f"peer announced a {length}-byte frame (limit {MAX_FRAME})")
    return _recv_exact(sock, length)
