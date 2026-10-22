package wtf.yello.simplechat.protocol

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException

/*
 * Length-prefixed framing over a TCP stream (same as framing.py on the desktop).
 *
 * TCP delivers a stream of bytes with no message boundaries, so every frame is
 * written as a 4-byte big-endian length followed by exactly that many bytes.
 */

/** Frames above 1 MiB are a protocol error, so a hostile peer can't make us allocate huge buffers. */
const val MAX_FRAME = 1 shl 20

/** The peer closed the connection. */
class ConnectionClosed(message: String = "peer closed the connection") : IOException(message)

/** The peer broke the protocol (bad frame, unexpected message). */
class ProtocolException(message: String) : IOException(message)

/** Not thread-safe: callers serialise writes (see SecureChannel). */
fun DataOutputStream.writeFrame(data: ByteArray) {
    if (data.size > MAX_FRAME) throw ProtocolException("frame too large (${data.size} bytes)")
    writeInt(data.size)
    write(data)
    flush()
}

fun DataInputStream.readFrame(): ByteArray {
    try {
        val length = readInt()
        if (length < 0 || length > MAX_FRAME) {
            throw ProtocolException("peer announced a $length-byte frame (limit $MAX_FRAME)")
        }
        return ByteArray(length).also { readFully(it) }
    } catch (_: EOFException) {
        throw ConnectionClosed()
    }
}
