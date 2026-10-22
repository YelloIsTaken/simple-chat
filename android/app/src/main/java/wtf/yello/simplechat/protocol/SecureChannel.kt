package wtf.yello.simplechat.protocol

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.nio.ByteBuffer

/*
 * The encrypted channel used after the handshake (same as channel.py).
 *
 * Each message is sealed with ChaCha20-Poly1305, which encrypts it and adds
 * an authentication tag; any change in transit makes decryption fail.
 *
 * Nonces are a plain counter (0, 1, 2, ...). Each direction has its own key,
 * so a nonce is never reused under the same key. The receiver expects
 * exactly the next counter value, so replayed, dropped or reordered messages
 * fail to decrypt and the connection is closed.
 *
 * Plaintext layout: 1 byte message type | body
 */

/** Message types of protocol v2 (PROTOCOL.md in the project root has the full description). */
object MessageType {
    const val NICK = 2          // UTF-8 nickname
    const val READY = 3         // JSON {"port"}: "I have verified your fingerprint, reach me here"
    const val BYE = 4           // empty: orderly goodbye (app quitting)
    const val PING = 5          // empty: keepalive, sent when the link has been quiet
    const val PONG = 6          // empty: reply to PING
    const val FILE_OFFER = 10   // JSON {"id", "name", "size"}
    const val FILE_ACCEPT = 11  // JSON {"id"}
    const val FILE_REJECT = 12  // JSON {"id", "reason"}
    const val FILE_CHUNK = 13   // 4-byte transfer id | raw file bytes
    const val FILE_END = 14     // JSON {"id", "sha256"}
    const val FILE_CANCEL = 15  // JSON {"id", "reason"}
    const val TEXT = 20         // JSON {"id", "sent", "text"}: a chat message
    const val ACK = 21          // JSON {"id"}: "stored your TEXT" (queued delivery)
}

class ChannelException(message: String) : IOException(message)

/** 96-bit nonce: 4 zero bytes followed by a 64-bit big-endian counter. */
private fun nonce(counter: Long): ByteArray = ByteBuffer.allocate(12).putInt(0).putLong(counter).array()

class SecureChannel(
    private val input: DataInputStream?,
    private val output: DataOutputStream?,
    private val sendKey: ByteArray,
    private val recvKey: ByteArray,
) {
    private var sendCounter = 0L
    private var recvCounter = 0L

    // Several threads may send (typing, file transfer). The lock keeps "take
    // the next counter value" and "write it to the socket" together, so
    // frames go out in counter order.
    private val sendLock = Any()

    private fun sealLocked(type: Int, body: ByteArray): ByteArray =
        aeadSeal(sendKey, nonce(sendCounter), byteArrayOf(type.toByte()) + body).also { sendCounter++ }

    /** Encrypt one message without sending it (used by the tests). */
    fun seal(type: Int, body: ByteArray = ByteArray(0)): ByteArray = synchronized(sendLock) { sealLocked(type, body) }

    fun send(type: Int, body: ByteArray = ByteArray(0)) {
        synchronized(sendLock) { output!!.writeFrame(sealLocked(type, body)) }
    }

    /** Called from one reader thread only. */
    fun open(frame: ByteArray): Pair<Int, ByteArray> {
        val plaintext = aeadOpen(recvKey, nonce(recvCounter), frame)
            ?: throw ChannelException("a message failed authentication (tampered with, replayed or out of order)")
        recvCounter++
        if (plaintext.isEmpty()) throw ChannelException("empty message")
        return (plaintext[0].toInt() and 0xff) to plaintext.copyOfRange(1, plaintext.size)
    }

    fun recv(): Pair<Int, ByteArray> = open(input!!.readFrame())
}
