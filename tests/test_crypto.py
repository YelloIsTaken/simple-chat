import hashlib
import socket
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from simplechat.channel import T_TEXT, ChannelError, SecureChannel
from simplechat.textutil import safe_filename, split_host_port
from simplechat.framing import read_frame, write_frame
from simplechat.handshake import (
    AUTH_LABEL, MAGIC, ROLE_INITIATOR, ROLE_RESPONDER, TRANSCRIPT_LABEL,
    HandshakeError, perform_handshake,
)
from simplechat.history import History, HistoryError
from simplechat.identity import (
    WrongPassword, create_identity, fingerprint, load_identity, raw_public_bytes,
)
from simplechat.trust import KnownPeers

FAST_N = 2**10  # cheap scrypt for tests


def run_pair(fn_a, fn_b):
    """Run two functions on the two ends of a socketpair, return both results."""
    a, b = socket.socketpair()
    results, errors = {}, {}

    def wrap(name, fn, sock):
        try:
            results[name] = fn(sock)
        except Exception as e:  # noqa: BLE001
            errors[name] = e

    t = threading.Thread(target=wrap, args=("b", fn_b, b), daemon=True)
    t.start()
    wrap("a", fn_a, a)
    if "a" in errors:
        a.shutdown(socket.SHUT_RDWR)  # unblock the other side if we gave up early
    t.join(5)
    assert not t.is_alive(), "peer thread hung"
    return results, errors, (a, b)


def test_handshake_agrees_on_keys_and_identities():
    ka, kb = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    res, err, _ = run_pair(
        lambda s: perform_handshake(s, ka, ROLE_INITIATOR),
        lambda s: perform_handshake(s, kb, ROLE_RESPONDER),
    )
    assert not err
    a, b = res["a"], res["b"]
    assert a.peer_public == raw_public_bytes(kb.public_key())
    assert b.peer_public == raw_public_bytes(ka.public_key())
    assert a.send_key == b.recv_key and a.recv_key == b.send_key
    assert a.send_key != a.recv_key


def test_encrypted_messages_roundtrip_and_are_not_plaintext():
    ka, kb = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    res, _, (sa, sb) = run_pair(
        lambda s: perform_handshake(s, ka, ROLE_INITIATOR),
        lambda s: perform_handshake(s, kb, ROLE_RESPONDER),
    )
    ca = SecureChannel(sa, res["a"].send_key, res["a"].recv_key)
    cb = SecureChannel(sb, res["b"].send_key, res["b"].recv_key)
    frame = ca.seal(T_TEXT, b"secret hello")
    assert b"secret hello" not in frame
    assert cb.open(frame) == (T_TEXT, b"secret hello")
    ca.send(T_TEXT, "zażółć 🔒".encode())
    assert cb.recv() == (T_TEXT, "zażółć 🔒".encode())


def _channel_pair():
    k1, k2 = bytes(range(32)), bytes(range(32, 64))
    return SecureChannel(None, k1, k2), SecureChannel(None, k2, k1)


def test_tampered_message_is_rejected():
    a, b = _channel_pair()
    frame = bytearray(a.seal(T_TEXT, b"pay alice 10"))
    frame[3] ^= 0x01
    with pytest.raises(ChannelError):
        b.open(bytes(frame))


def test_replayed_and_reordered_messages_are_rejected():
    a, b = _channel_pair()
    f1, f2 = a.seal(T_TEXT, b"one"), a.seal(T_TEXT, b"two")
    with pytest.raises(ChannelError):
        b.open(f2)  # out of order
    a2, b2 = _channel_pair()
    g1 = a2.seal(T_TEXT, b"one")
    assert b2.open(g1) == (T_TEXT, b"one")
    with pytest.raises(ChannelError):
        b2.open(g1)  # replay


def test_impersonation_with_wrong_signature_fails():
    """An attacker claims the victim's identity key but can't sign with it."""
    victim, attacker, honest = (Ed25519PrivateKey.generate() for _ in range(3))

    def attacker_side(sock):
        eph = X25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        hello = MAGIC + raw_public_bytes(victim.public_key()) + eph
        write_frame(sock, hello)
        peer_hello = read_frame(sock)
        transcript = hashlib.sha256(TRANSCRIPT_LABEL + hello + peer_hello).digest()
        write_frame(sock, attacker.sign(AUTH_LABEL + ROLE_INITIATOR + transcript))
        read_frame(sock)

    _, err, _ = run_pair(
        lambda s: perform_handshake(s, honest, ROLE_RESPONDER),
        attacker_side,
    )
    assert isinstance(err.get("a"), HandshakeError)


def test_reflected_signature_fails():
    """Sending back the responder's own HELLO and signature must not work."""
    honest = Ed25519PrivateKey.generate()

    def reflector(sock):
        hello = read_frame(sock)
        write_frame(sock, hello)
        sig = read_frame(sock)
        write_frame(sock, sig)

    _, err, _ = run_pair(lambda s: perform_handshake(s, honest, ROLE_RESPONDER), reflector)
    assert isinstance(err.get("a"), HandshakeError)


def test_identity_password(tmp_path):
    path = tmp_path / "identity.json"
    ident = create_identity(path, "correct horse", scrypt_n=FAST_N)
    assert load_identity(path, "correct horse").public_bytes == ident.public_bytes
    with pytest.raises(WrongPassword):
        load_identity(path, "wrong")
    assert path.stat().st_mode & 0o777 == 0o600
    assert ident.private_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    ).hex() not in path.read_text()


def test_fingerprint_format():
    fp = fingerprint(b"\x01" * 32)
    assert len(fp) == 39 and fp.count("-") == 7


def test_history_roundtrip_and_wrong_key(tmp_path):
    peer = b"\x02" * 32
    h = History(tmp_path, b"\x09" * 32, peer)
    h.append({"text": "hello there"})
    h.append({"text": "second"})
    assert [r["text"] for r in h.read_all()] == ["hello there", "second"]
    assert b"hello there" not in h.path.read_bytes()
    with pytest.raises(HistoryError):
        History(tmp_path, b"\x08" * 32, peer).read_all()


def test_known_peers_detects_changed_key(tmp_path):
    kp = KnownPeers(tmp_path / "known.json")
    old, new = b"\x01" * 32, b"\x02" * 32
    kp.trust(old, "alice", "10.0.0.5:5000")
    reloaded = KnownPeers(tmp_path / "known.json")
    assert reloaded.get(old).label == "alice"
    assert reloaded.others_for_host("10.0.0.5:5000", new)[0].public_key == old
    assert reloaded.others_for_host("10.0.0.5:5000", old) == []
    assert reloaded.forget(fingerprint(old)[:9])
    assert KnownPeers(tmp_path / "known.json").get(old) is None


@pytest.mark.parametrize("raw,expected", [
    ("../../etc/passwd", "passwd"),
    ("..\\..\\evil.exe", "evil.exe"),
    (".bashrc", "bashrc"),
    ("report‮gnp.exe", "reportgnp.exe"),
    ("\x1b[31mred.txt", "[31mred.txt"),
    ("", "file"),
    ("..", "file"),
])
def test_safe_filename(raw, expected):
    assert safe_filename(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("192.168.1.188", ("192.168.1.188", 5000)),
    ("192.168.1.188:6000", ("192.168.1.188", 6000)),
    ("desktop.lan:5001", ("desktop.lan", 5001)),
    ("fe80::1", ("fe80::1", 5000)),
])
def test_split_host_port(raw, expected):
    assert split_host_port(raw, 5000) == expected
