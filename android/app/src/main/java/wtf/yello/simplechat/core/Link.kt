package wtf.yello.simplechat.core

import org.json.JSONException
import org.json.JSONObject
import wtf.yello.simplechat.protocol.ChannelException
import wtf.yello.simplechat.protocol.ConnectionClosed
import wtf.yello.simplechat.protocol.HandshakeException
import wtf.yello.simplechat.protocol.Identity
import wtf.yello.simplechat.protocol.MessageType
import wtf.yello.simplechat.protocol.ProtocolException
import wtf.yello.simplechat.protocol.Role
import wtf.yello.simplechat.protocol.SecureChannel
import wtf.yello.simplechat.protocol.fingerprint
import wtf.yello.simplechat.protocol.performHandshake
import wtf.yello.simplechat.protocol.toHex
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/*
 * A link: one authenticated, encrypted TCP connection to one contact
 * (link.py on the desktop). While it's up, the contact shows as online.
 * Messenger keeps one link per online contact and decides who to trust;
 * a Link only speaks the protocol and reports to [LinkEvents].
 *
 * Threads per link (all plain background threads, never the UI thread,
 * because Android forbids network calls on the main thread):
 *  - the receive loop ([run]): reads and handles frames in order;
 *  - the sender: sends queued frames one at a time, so callers never block;
 *  - the keepalive: PINGs a quiet link; a link silent for 60 s is dead;
 *  - one thread per outgoing file.
 */

const val HANDSHAKE_TIMEOUT_MS = 20_000
const val CHUNK_SIZE = 64 * 1024
const val MAX_MESSAGE_BYTES = 16 * 1024

/** Tunable for tests. */
object LinkTiming {
    @Volatile var pingAfterMs = 20_000L
    @Volatile var deadAfterMs = 60_000L
}

/** We dialled a contact, but someone with a different key answered. */
class WrongPeer : IOException("a different key answered")

data class FileOffer(val name: String, val size: Long)

/** Progress of one transfer. id is unique per link and direction ("in-3"). */
data class Transfer(val id: String, val name: String, val size: Long, val done: Long, val outgoing: Boolean)

interface LinkEvents {
    /** Called before READY: null to accept the peer, or why not ("" = already reported). */
    fun verify(link: Link): String?
    fun linkUp(link: Link)
    fun linkDown(link: Link, reason: String?)

    /** Store the message; the link ACKs it after this returns. */
    fun text(link: Link, id: String, sent: String, text: String)
    fun ack(link: Link, id: String)
    fun nick(link: Link, nick: String)
    fun fileOffer(link: Link, offer: FileOffer?)
    fun transfer(link: Link, progress: Transfer, finished: Boolean)
    fun fileDone(link: Link, text: String, ok: Boolean, saved: Saved?)
    fun notice(link: Link, text: String, error: Boolean)
}

/** Unsigned, byte-wise comparison of two keys, like Python's `bytes <`. */
fun compareKeys(a: ByteArray, b: ByteArray): Int {
    for (i in 0 until minOf(a.size, b.size)) {
        val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
        if (d != 0) return d
    }
    return a.size - b.size
}

class Link(
    private val socket: Socket,
    val role: Role,
    val address: String,                    // "ip:port" of the TCP connection
    private val identity: Identity,
    private val expectedKey: ByteArray?,    // set when we dialled a known contact
    nick: String,
    private val listenPort: Int,
    private val files: FileStore,
    private val events: LinkEvents,
    val manualHost: String? = null,         // "host:port" the user typed, for the changed-key check
) {
    var nick = nick
        private set
    private lateinit var channel: SecureChannel
    var peerPublic = ByteArray(0)
        private set
    val peerId: String get() = peerPublic.toHex()
    @Volatile var peerNick = "peer"
        private set
    var peerPort: Int? = null               // where the peer listens (from READY)
        private set
    @Volatile var up = false
        private set
    @Volatile var closing = false
        private set
    @Volatile var newlyTrusted = false      // set by Messenger: save as a contact once the link is up
    private val endedLatch = CountDownLatch(1)
    val ended: Boolean get() = endedLatch.count == 0L
    @Volatile private var lastSent = System.currentTimeMillis()

    // Work for the sender thread; STOP ends it.
    private val outbox = LinkedBlockingQueue<() -> Unit>()
    private val stop: () -> Unit = {}

    // File-transfer state. Rule: never call events while holding the lock.
    private val lock = Any()
    private var incoming: Incoming? = null
    private val outgoing = HashMap<Int, Outgoing>()
    private var nextFileId = 1

    private class Incoming(val id: Int, val name: String, val size: Long) {
        var target: IncomingFile? = null
        var received = 0L
        val digest: MessageDigest = MessageDigest.getInstance("SHA-256")
        var lastReport = 0L
    }

    private class Outgoing(val id: Int, val file: OutgoingFile) {
        @Volatile var cancelled = false
    }

    val peerFingerprint: String get() = if (peerPublic.isEmpty()) "" else fingerprint(peerPublic)

    /** Identity key of the side that dialled; used to pick between duplicate links. */
    val initiatorKey: ByteArray get() = if (role == Role.INITIATOR) identity.publicKey else peerPublic

    val peerHost: String get() = address.substringBeforeLast(':')

    fun awaitEnd(ms: Long) = endedLatch.await(ms, TimeUnit.MILLISECONDS)

    // ---- lifecycle ----------------------------------------------------------

    /** Set up the link and run it until it ends. Blocks; call on a background thread. */
    fun run() {
        var reason: String? = null
        try {
            val refusal = establish()
            if (refusal == null) {
                Thread({ senderLoop() }, "link-send").apply { isDaemon = true }.start()
                Thread({ keepaliveLoop() }, "link-keepalive").apply { isDaemon = true }.start()
                up = true
                events.linkUp(this)
                reason = receiveLoop()
            } else {
                reason = refusal.ifEmpty { null }
            }
        } catch (_: WrongPeer) {
            reason = null  // an automatic dial reached someone else: nothing to tell the user
        } catch (e: HandshakeException) {
            reason = "Security check failed: ${e.message}"
        } catch (e: ChannelException) {
            reason = "Security error: ${e.message}"
        } catch (_: SocketTimeoutException) {
            reason = when {
                closing -> null
                up -> "$peerNick went offline (no response)"
                else -> "The other side didn't respond."
            }
        } catch (e: IOException) {  // ConnectionClosed, reset, broken pipe, ...
            reason = when {
                closing -> null
                up -> "$peerNick went offline"
                e is ConnectionClosed || e is SocketException -> "The other side closed the connection (or didn't trust your key)."
                else -> "Connection error: ${e.message}"
            }
        } finally {
            cleanup()
        }
        events.linkDown(this, reason)
    }

    /** End the link; with bye=true the peer is told we're leaving. Safe from any thread. */
    fun close(bye: Boolean = true) {
        if (closing) return
        closing = true
        if (up) {
            outbox.put {
                if (bye) trySend(MessageType.BYE)
                runCatching { socket.close() }
            }
        } else {
            runCatching { socket.close() }
        }
    }

    private fun cleanup() {
        endedLatch.countDown()
        outbox.put(stop)
        val inc = synchronized(lock) {
            outgoing.values.forEach { it.cancelled = true }
            incoming.also { incoming = null }
        }
        if (inc != null) {
            inc.target?.discard()
            events.fileOffer(this, null)
            if (inc.target != null) reportTransfer(inc, finished = true)
        }
        runCatching { socket.close() }
    }

    // ---- set-up -------------------------------------------------------------

    private fun establish(): String? {
        socket.soTimeout = HANDSHAKE_TIMEOUT_MS
        val input = DataInputStream(BufferedInputStream(socket.getInputStream()))
        val output = DataOutputStream(BufferedOutputStream(socket.getOutputStream()))
        val result = performHandshake(input, output, identity, role)
        peerPublic = result.peerPublic
        if (expectedKey != null && !peerPublic.contentEquals(expectedKey)) throw WrongPeer()
        channel = SecureChannel(input, output, result.sendKey, result.recvKey)

        // Everything from here on is encrypted.
        channel.send(MessageType.NICK, nick.toByteArray())
        val (type, body) = channel.recv()
        if (type != MessageType.NICK) throw ProtocolException("unexpected first message")
        peerNick = cleanNick(body)

        // A trust question may wait for a human: no timeout while it's open.
        socket.soTimeout = 0
        events.verify(this)?.let { return it }

        channel.send(MessageType.READY, JSONObject().put("port", listenPort).toString().toByteArray())
        val (ready, readyBody) = channel.recv()
        if (ready != MessageType.READY) throw ProtocolException("unexpected message before READY")
        peerPort = runCatching { JSONObject(String(readyBody)).getInt("port") }.getOrNull()
        return null
    }

    // ---- receiving ----------------------------------------------------------

    private fun receiveLoop(): String {
        // With a read timeout, a peer that vanished without closing (e.g. Wi-Fi off)
        // is noticed: the keepalive guarantees traffic well within this time.
        socket.soTimeout = LinkTiming.deadAfterMs.toInt()
        while (true) {
            val (type, body) = channel.recv()
            if (type == MessageType.BYE) return "$peerNick went offline"
            try {
                handleFrame(type, body)
            } catch (_: JSONException) {
                throw ChannelException("malformed message")
            }
        }
    }

    private fun handleFrame(type: Int, body: ByteArray) {
        when (type) {
            MessageType.TEXT -> {
                val info = JSONObject(String(body))
                val id = info.getString("id").take(64)
                events.text(this, id, info.optString("sent").take(32), cleanText(info.getString("text")))
                // ACK after the message is stored, so a crash in between means a re-send, not a loss.
                queueSend(MessageType.ACK, JSONObject().put("id", id))
            }
            MessageType.ACK -> events.ack(this, JSONObject(String(body)).getString("id"))
            MessageType.PING -> outbox.put { trySend(MessageType.PONG) }
            MessageType.PONG -> Unit  // any traffic counts as a sign of life
            MessageType.NICK -> {
                peerNick = cleanNick(body)
                events.nick(this, peerNick)
            }
            MessageType.FILE_OFFER -> onOffer(JSONObject(String(body)))
            MessageType.FILE_ACCEPT -> {
                val o = synchronized(lock) { outgoing[JSONObject(String(body)).getInt("id")] } ?: return
                Thread({ sendFile(o) }, "link-file").apply { isDaemon = true }.start()
            }
            MessageType.FILE_REJECT -> {
                val o = synchronized(lock) { outgoing.remove(JSONObject(String(body)).getInt("id")) } ?: return
                events.notice(this, "$peerNick declined '${o.file.name}'.", error = false)
            }
            MessageType.FILE_CHUNK -> onChunk(body)
            MessageType.FILE_END -> onFileEnd(JSONObject(String(body)))
            MessageType.FILE_CANCEL -> onCancel(JSONObject(String(body)))
            // Unknown types are ignored, for forward compatibility.
        }
    }

    // Receiving a file: OFFER -> user accepts -> we create the file and send ACCEPT
    // -> CHUNKs -> END with the SHA-256 of the whole file -> compare and keep or delete.

    private fun onOffer(info: JSONObject) {
        val id = info.getInt("id")
        val offer = Incoming(id, safeFilename(info.getString("name")), info.getLong("size"))
        val busy = synchronized(lock) { (incoming != null).also { if (!it) incoming = offer } }
        if (busy) {
            queueSend(MessageType.FILE_REJECT, JSONObject().put("id", id).put("reason", "busy"))
        } else {
            events.fileOffer(this, FileOffer(offer.name, offer.size))
        }
    }

    private fun onChunk(body: ByteArray) {
        if (body.size < 4) throw ChannelException("short file chunk")
        val id = ByteBuffer.wrap(body, 0, 4).int
        var failure: String? = null
        val inc: Incoming
        synchronized(lock) {
            inc = incoming ?: return
            val target = inc.target ?: return
            if (inc.id != id) return
            inc.received += body.size - 4
            if (inc.received > inc.size) {
                failure = "more data than announced"
            } else {
                try {
                    target.output.write(body, 4, body.size - 4)
                    inc.digest.update(body, 4, body.size - 4)
                } catch (e: IOException) {
                    failure = "write error: ${e.message}"
                }
            }
            if (failure != null) {
                target.discard()
                incoming = null
            }
        }
        // Events only with the lock released: the UI may be waiting for it.
        if (failure == null) {
            reportTransfer(inc)
            return
        }
        reportTransfer(inc, finished = true)
        queueSend(MessageType.FILE_CANCEL, JSONObject().put("id", id).put("reason", failure))
        events.fileDone(this, "Receiving '${inc.name}' failed: $failure", ok = false, saved = null)
    }

    private fun onFileEnd(info: JSONObject) {
        val inc = synchronized(lock) {
            incoming?.takeIf { it.target != null && it.id == info.getInt("id") }?.also { incoming = null }
        } ?: return
        reportTransfer(inc, finished = true)
        val target = inc.target!!
        if (inc.received != inc.size || inc.digest.digest().toHex() != info.optString("sha256").lowercase()) {
            target.discard()
            events.fileDone(this, "'${inc.name}' arrived incomplete or corrupted and was discarded.", false, null)
            return
        }
        val saved = try {
            target.commit()
        } catch (e: IOException) {
            target.discard()
            events.fileDone(this, "Couldn't save '${inc.name}': ${e.message}", false, null)
            return
        }
        events.fileDone(this, "Received '${inc.name}' (${humanSize(inc.size)})", true, saved)
    }

    private fun onCancel(info: JSONObject) {
        val id = info.getInt("id")
        var name: String? = null
        var cancelledIncoming: Incoming? = null
        synchronized(lock) {
            outgoing.remove(id)?.let { it.cancelled = true; name = it.file.name }
            incoming?.takeIf { it.id == id }?.let {
                it.target?.discard()
                incoming = null
                cancelledIncoming = it
                name = it.name
            }
        }
        cancelledIncoming?.let {
            events.fileOffer(this, null)
            if (it.target != null) reportTransfer(it, finished = true)
        }
        name?.let { events.notice(this, "Transfer of '$it' cancelled by $peerNick: ${info.optString("reason")}", true) }
    }

    private fun reportTransfer(inc: Incoming, finished: Boolean = false) {
        val now = System.currentTimeMillis()  // at most ~10 progress updates a second
        if (finished || now - inc.lastReport >= 100) {
            inc.lastReport = now
            events.transfer(this, Transfer("in-${inc.id}", inc.name, inc.size, inc.received, false), finished)
        }
    }

    // ---- sending (callable from any thread) ---------------------------------

    private fun senderLoop() {
        while (true) {
            val job = outbox.take()
            if (job === stop) return
            job()
        }
    }

    private fun keepaliveLoop() {
        val check = minOf(5_000L, LinkTiming.pingAfterMs / 2)
        while (!endedLatch.await(check, TimeUnit.MILLISECONDS)) {
            if (System.currentTimeMillis() - lastSent >= LinkTiming.pingAfterMs) {
                outbox.put { trySend(MessageType.PING) }
            }
        }
    }

    /** Send, ignoring errors: a dead connection is reported by the receive loop. */
    private fun trySend(type: Int, body: ByteArray = ByteArray(0)) {
        try {
            channel.send(type, body)
            lastSent = System.currentTimeMillis()
        } catch (_: IOException) {
        }
    }

    private fun queueSend(type: Int, info: JSONObject) {
        val data = info.toString().toByteArray()
        outbox.put { trySend(type, data) }
    }

    fun sendText(id: String, sent: String, text: String) =
        queueSend(MessageType.TEXT, JSONObject().put("id", id).put("sent", sent).put("text", text))

    fun sendNick(newNick: String) {
        nick = newNick
        val data = newNick.toByteArray()
        outbox.put { trySend(MessageType.NICK, data) }
    }

    fun offerFile(file: OutgoingFile) {
        val o = synchronized(lock) { Outgoing(nextFileId++, file).also { outgoing[it.id] = it } }
        queueSend(MessageType.FILE_OFFER, JSONObject().put("id", o.id).put("name", file.name).put("size", file.size))
    }

    fun acceptOffer() {
        val inc = synchronized(lock) { incoming?.takeIf { it.target == null } } ?: return
        val target = try {
            files.create(inc.name)
        } catch (e: Exception) {
            synchronized(lock) { incoming = null }
            events.fileOffer(this, null)
            events.notice(this, "Can't save the file: ${e.message}", error = true)
            queueSend(MessageType.FILE_REJECT, JSONObject().put("id", inc.id).put("reason", "cannot save"))
            return
        }
        synchronized(lock) { inc.target = target }  // chunks only arrive after ACCEPT
        events.fileOffer(this, null)
        reportTransfer(inc)
        queueSend(MessageType.FILE_ACCEPT, JSONObject().put("id", inc.id))
    }

    fun rejectOffer() {
        val inc = synchronized(lock) { incoming?.takeIf { it.target == null }?.also { incoming = null } }
        events.fileOffer(this, null)
        if (inc != null) queueSend(MessageType.FILE_REJECT, JSONObject().put("id", inc.id).put("reason", "declined"))
    }

    /** Stream a file in 64 KB encrypted chunks, then send its SHA-256 so the receiver can verify it. */
    private fun sendFile(o: Outgoing) {
        val digest = MessageDigest.getInstance("SHA-256")
        var sent = 0L
        var lastReport = 0L
        fun report(finished: Boolean = false) =
            events.transfer(this, Transfer("out-${o.id}", o.file.name, o.file.size, sent, true), finished)

        report()
        try {
            o.file.open().use { input ->
                val buffer = ByteArray(CHUNK_SIZE)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    if (o.cancelled || ended) return
                    // Chunk body: 4-byte transfer id (big-endian, like Python's struct ">I") + data.
                    val header = ByteBuffer.allocate(4).putInt(o.id).array()
                    channel.send(MessageType.FILE_CHUNK, header + buffer.copyOf(n))
                    lastSent = System.currentTimeMillis()
                    digest.update(buffer, 0, n)
                    sent += n
                    if (System.currentTimeMillis() - lastReport >= 100) {
                        lastReport = System.currentTimeMillis()
                        report()
                    }
                }
            }
            if (sent != o.file.size) throw IOException("the file changed size while sending")
            channel.send(MessageType.FILE_END,
                JSONObject().put("id", o.id).put("sha256", digest.digest().toHex()).toString().toByteArray())
            events.fileDone(this, "Sent '${o.file.name}' (${humanSize(sent)})", ok = true, saved = null)
        } catch (e: IOException) {
            if (!ended) {
                events.fileDone(this, "Sending '${o.file.name}' failed: ${e.message}", ok = false, saved = null)
                trySend(MessageType.FILE_CANCEL,
                    JSONObject().put("id", o.id).put("reason", e.message ?: "error").toString().toByteArray())
            }
        } finally {
            report(finished = true)
            synchronized(lock) { outgoing.remove(o.id) }
        }
    }
}
