package wtf.yello.simplechat.protocol

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.BufferedReader
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.TimeUnit

/**
 * Pure-Kotlin protocol checks, plus interop tests against the desktop app's
 * Python implementation (skipped if the desktop project's .venv is missing).
 */
class ProtocolTest {

    // ---- Kotlin only --------------------------------------------------------

    private fun channelPair(): Pair<SecureChannel, SecureChannel> {
        val k1 = ByteArray(32) { it.toByte() }
        val k2 = ByteArray(32) { (it + 32).toByte() }
        return SecureChannel(null, null, k1, k2) to SecureChannel(null, null, k2, k1)
    }

    @Test
    fun messageRoundTrip() {
        val (a, b) = channelPair()
        val frame = a.seal(MessageType.TEXT, "secret hello".toByteArray())
        assertEquals(-1, String(frame, Charsets.ISO_8859_1).indexOf("secret"))
        val (type, body) = b.open(frame)
        assertEquals(MessageType.TEXT, type)
        assertEquals("secret hello", String(body))
    }

    @Test
    fun tamperedMessageRejected() {
        val (a, b) = channelPair()
        val frame = a.seal(MessageType.TEXT, "pay alice 10".toByteArray())
        frame[3] = (frame[3].toInt() xor 1).toByte()
        assertThrows(ChannelException::class.java) { b.open(frame) }
    }

    @Test
    fun replayAndReorderRejected() {
        val (a, b) = channelPair()
        a.seal(MessageType.TEXT, "one".toByteArray())
        val second = a.seal(MessageType.TEXT, "two".toByteArray())
        assertThrows(ChannelException::class.java) { b.open(second) }

        val (c, d) = channelPair()
        val first = c.seal(MessageType.TEXT, "one".toByteArray())
        d.open(first)
        assertThrows(ChannelException::class.java) { d.open(first) }
    }

    @Test
    fun aeadOpenWithWrongKeyFails() {
        val key = ByteArray(32) { 1 }
        val sealed = aeadSeal(key, ByteArray(12), "x".toByteArray(), "aad".toByteArray())
        assertNotNull(aeadOpen(key, ByteArray(12), sealed, "aad".toByteArray()))
        assertNull(aeadOpen(ByteArray(32) { 2 }, ByteArray(12), sealed, "aad".toByteArray()))
        assertNull(aeadOpen(key, ByteArray(12), sealed, "other".toByteArray()))
    }

    // ---- Interop with the desktop (Python) implementation -------------------

    private val root = File(System.getProperty("simplechat.root") ?: "../..")
    private val python = File(root, ".venv/bin/python")
    private val peerScript = File(root, "tests/interop_peer.py")

    private fun startPeer(vararg args: String): Pair<Process, BufferedReader> {
        assumeTrue("desktop project venv not found at $python", python.canExecute())
        val process = ProcessBuilder(python.path, peerScript.path, *args)
            .redirectError(ProcessBuilder.Redirect.INHERIT)
            .start()
        return process to process.inputStream.bufferedReader()
    }

    private fun BufferedReader.expect(prefix: String): String {
        val line = readLine() ?: error("python peer exited before printing $prefix")
        assertEquals(prefix, line.substringBefore(' '))
        return line.substringAfter(' ')
    }

    /** Handshake with the Python peer over [socket], exchange messages, say goodbye. */
    private fun chatWithPython(socket: Socket, role: Role, out: BufferedReader, pythonPub: String, process: Process) {
        socket.use {
            val input = DataInputStream(BufferedInputStream(it.getInputStream()))
            val output = DataOutputStream(BufferedOutputStream(it.getOutputStream()))
            val me = Identity.generate()
            val result = performHandshake(input, output, me, role)

            assertEquals(pythonPub, result.peerPublic.toHex())
            assertEquals(me.publicKey.toHex(), out.expect("PEER"))

            val channel = SecureChannel(input, output, result.sendKey, result.recvKey)
            for ((i, text) in listOf("hello from kotlin", "zażółć gęślą jaźń 🔒").withIndex()) {
                val id = "%032x".format(i + 1)
                channel.send(MessageType.TEXT, JSONObject().put("id", id).put("sent", "2026-10-22T12:00:00")
                    .put("text", text).toString().toByteArray())
                val (ackType, ack) = channel.recv()
                assertEquals(MessageType.ACK, ackType)
                assertEquals(id, JSONObject(String(ack)).getString("id"))
                val (type, body) = channel.recv()
                assertEquals(MessageType.TEXT, type)
                assertEquals(text.uppercase(), JSONObject(String(body)).getString("text"))
            }
            channel.send(MessageType.BYE)
            assertEquals("BYE", out.readLine())
        }
        assertEquals(true, process.waitFor(10, TimeUnit.SECONDS))
        assertEquals(0, process.exitValue())
    }

    @Test
    fun kotlinConnectsToPython() {
        val (process, out) = startPeer("listen")
        val pythonPub = out.expect("PUB")
        val port = out.expect("PORT").toInt()
        chatWithPython(Socket("127.0.0.1", port), Role.INITIATOR, out, pythonPub, process)
    }

    @Test
    fun pythonConnectsToKotlin() {
        ServerSocket(0).use { server ->
            val (process, out) = startPeer("connect", server.localPort.toString())
            val pythonPub = out.expect("PUB")
            server.soTimeout = 10_000
            chatWithPython(server.accept(), Role.RESPONDER, out, pythonPub, process)
        }
    }

    @Test
    fun fingerprintAndHistoryKeyMatchPython() {
        val identity = Identity(ByteArray(32) { (it * 7).toByte() })
        val (process, out) = startPeer("info", identity.seedCopy().toHex())
        val (pub, fp, historyKey) = out.readLine().split(" ")
        process.waitFor(10, TimeUnit.SECONDS)
        assertEquals(pub, identity.publicKey.toHex())
        assertEquals(fp, identity.fingerprint)
        assertArrayEquals(historyKey.hexToBytes(), identity.historyKey())
    }
}
