package wtf.yello.simplechat.protocol

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException

/*
 * The authenticated key exchange that opens every session. It is the same
 * protocol as handshake.py on the desktop, so the two interoperate.
 *
 *   initiator (connect)                         responder (listen)
 *   HELLO = magic | id_pub | eph_pub     --->
 *                                        <---   HELLO = magic | id_pub | eph_pub
 *   transcript = SHA-256(label | HELLO_initiator | HELLO_responder)
 *   AUTH  = Sign(id_key, "I" | transcript) --->
 *                                        <---   AUTH = Sign(id_key, "R" | transcript)
 *   both: keys = HKDF(X25519(my_eph, peer_eph), salt = transcript)
 *
 * - X25519 with fresh ephemeral keys gives a shared secret that an
 *   eavesdropper can't compute, and forward secrecy: the ephemeral keys are
 *   thrown away after the session.
 * - Signing the transcript with the long-term Ed25519 identity key proves who
 *   is on the other end, which defeats a man-in-the-middle (provided the user
 *   checked the fingerprint once; see KnownPeers).
 * - The role letter inside the signature stops a reflected signature from
 *   being accepted.
 */

private val MAGIC = "SCHATv2\u0000".toByteArray()  // protocol version 2, see PROTOCOL.md
private val HELLO_LEN = MAGIC.size + 32 + 32
private val TRANSCRIPT_LABEL = "simplechat-v1 transcript".toByteArray()
private val AUTH_LABEL = "simplechat-v1 auth".toByteArray()
private val KEYS_LABEL = "simplechat-v1 session keys".toByteArray()

enum class Role(val letter: Byte) {
    INITIATOR('I'.code.toByte()),
    RESPONDER('R'.code.toByte());

    val other: Role get() = if (this == INITIATOR) RESPONDER else INITIATOR
}

class HandshakeException(message: String) : IOException(message)

class HandshakeResult(
    /** The peer's long-term Ed25519 public key (raw 32 bytes). */
    val peerPublic: ByteArray,
    /** Encrypts what we send. */
    val sendKey: ByteArray,
    /** Decrypts what we receive. */
    val recvKey: ByteArray,
)

fun performHandshake(
    input: DataInputStream,
    output: DataOutputStream,
    identity: Identity,
    role: Role,
): HandshakeResult {
    // 1. Fresh ephemeral key pair, used for this session only.
    val ephemeral = X25519PrivateKeyParameters(secureRandom)
    val myEphPub = ephemeral.generatePublicKey().encoded
    val myHello = MAGIC + identity.publicKey + myEphPub

    // 2. Swap HELLOs. Both sides write first and then read; the messages are
    //    tiny and fit in the TCP buffers, so this can't deadlock.
    output.writeFrame(myHello)
    val peerHello = input.readFrame()
    if (peerHello.size != HELLO_LEN || !peerHello.copyOf(MAGIC.size).contentEquals(MAGIC)) {
        throw HandshakeException("the other side is not a simplechat peer (or uses another version)")
    }
    val peerIdPub = peerHello.copyOfRange(MAGIC.size, MAGIC.size + 32)
    val peerEphPub = peerHello.copyOfRange(MAGIC.size + 32, HELLO_LEN)
    if (peerEphPub.contentEquals(myEphPub)) throw HandshakeException("our own HELLO was reflected back to us")

    // 3. Hash of everything both sides said, in a fixed (initiator-first) order.
    val (helloI, helloR) = if (role == Role.INITIATOR) myHello to peerHello else peerHello to myHello
    val transcript = sha256(TRANSCRIPT_LABEL, helloI, helloR)

    // 4. Prove we own our identity key; check the peer's proof against the key it claimed.
    output.writeFrame(identity.sign(AUTH_LABEL + byteArrayOf(role.letter) + transcript))
    val peerSig = input.readFrame()
    if (!verifyEd25519(peerIdPub, AUTH_LABEL + byteArrayOf(role.other.letter) + transcript, peerSig)) {
        throw HandshakeException("the peer's signature is invalid - possible man-in-the-middle")
    }

    // 5. Diffie-Hellman: combine our ephemeral private key with theirs.
    val shared = ByteArray(32)
    try {
        X25519Agreement().run {
            init(ephemeral)
            calculateAgreement(X25519PublicKeyParameters(peerEphPub, 0), shared, 0)
        }
    } catch (_: IllegalStateException) {
        throw HandshakeException("the peer sent an invalid ephemeral key")
    }
    if (shared.all { it == 0.toByte() }) {
        // A malicious "low-order" point forces an all-zero, predictable secret.
        throw HandshakeException("the peer sent an invalid ephemeral key")
    }

    // 6. One key per direction; the transcript as salt ties them to this conversation.
    val okm = hkdf(shared, transcript, KEYS_LABEL, 64)
    val keyI2R = okm.copyOfRange(0, 32)
    val keyR2I = okm.copyOfRange(32, 64)
    return if (role == Role.INITIATOR) {
        HandshakeResult(peerIdPub, sendKey = keyI2R, recvKey = keyR2I)
    } else {
        HandshakeResult(peerIdPub, sendKey = keyR2I, recvKey = keyI2R)
    }
}
