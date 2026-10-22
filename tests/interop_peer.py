"""Protocol peer for the Android app's interop tests, built on the desktop code.

    interop_peer.py listen          -> prints "PORT <n>", waits for one connection
    interop_peer.py connect <port>  -> connects to 127.0.0.1:<port>
    interop_peer.py info <seed-hex> -> prints fingerprint and history key for that seed

After the handshake it prints "PEER <hex public key>". For every TEXT it sends
an ACK, then echoes the text back upper-cased as a new TEXT, until it receives BYE.
"""

import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import json  # noqa: E402

from simplechat.channel import T_ACK, T_BYE, T_TEXT, SecureChannel  # noqa: E402
from simplechat.handshake import ROLE_INITIATOR, ROLE_RESPONDER, perform_handshake  # noqa: E402
from simplechat.identity import Identity, raw_public_bytes  # noqa: E402


def main() -> None:
    mode = sys.argv[1]
    if mode == "info":
        identity = Identity(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sys.argv[2])))
        print(identity.public_bytes.hex(), identity.fingerprint, identity.history_key().hex())
        return

    key = Ed25519PrivateKey.generate()
    print("PUB", raw_public_bytes(key.public_key()).hex(), flush=True)
    if mode == "listen":
        server = socket.create_server(("127.0.0.1", 0))
        print("PORT", server.getsockname()[1], flush=True)
        sock, _ = server.accept()
        role = ROLE_RESPONDER
    else:
        sock = socket.create_connection(("127.0.0.1", int(sys.argv[2])))
        role = ROLE_INITIATOR

    result = perform_handshake(sock, key, role)
    print("PEER", result.peer_public.hex(), flush=True)
    channel = SecureChannel(sock, result.send_key, result.recv_key)
    while True:
        msg_type, body = channel.recv()
        if msg_type == T_BYE:
            print("BYE", flush=True)
            return
        if msg_type == T_TEXT:  # ACK it, then echo it back upper-cased as a new TEXT
            info = json.loads(body)
            channel.send(T_ACK, json.dumps({"id": info["id"]}).encode())
            reply = {"id": info["id"][::-1], "sent": info["sent"], "text": info["text"].upper()}
            channel.send(T_TEXT, json.dumps(reply).encode())


if __name__ == "__main__":
    main()
