package wtf.yello.simplechat.core

import org.json.JSONObject
import wtf.yello.simplechat.protocol.randomBytes
import wtf.yello.simplechat.protocol.toHex
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

/**
 * The message log with one contact, including messages still waiting for
 * delivery (conversation.py on the desktop; same records):
 *
 *     {"k": "msg", "id", "t", "dir": "in"|"out", "who", "text"}   a message
 *     {"k": "ack", "id"}                                          our message `id` was delivered
 *     {"k": "note", "t", "text", "uri"?}                          e.g. "Received photo.jpg" (+ where to open it)
 *
 * Queued delivery: an outgoing message is stored first. Until an "ack"
 * record exists for its id it is *pending*, and it is re-sent every time a
 * link to the contact comes up. Incoming ids are remembered, so a message
 * that is re-sent (because its ack got lost) isn't shown twice.
 */
class Conversation(private val history: History) {

    data class Message(
        val id: String,
        val time: String,        // ISO 8601, local time
        val outgoing: Boolean,
        val who: String,
        val text: String,
        val delivered: Boolean,  // always true for incoming messages and notes
        val note: Boolean = false,
        val uri: String? = null,  // notes about received files: where to open the file
    ) {
        val clock: String get() = time.drop(11).take(5)
    }

    private val list = mutableListOf<Message>()
    private val byId = HashMap<String, Int>()  // id -> index in list
    var loadError: String? = null
        private set

    init {
        val records = try {
            history.readAll()
        } catch (e: IllegalStateException) {
            loadError = e.message
            emptyList()
        }
        val acked = records.filter { it.optString("k") == "ack" }.map { it.getString("id") }.toSet()
        for (r in records) {
            when (r.optString("k", "msg").ifEmpty { "msg" }) {
                "msg" -> {
                    val hasId = r.has("id")
                    val id = if (hasId) r.getString("id") else newMessageId()
                    val out = r.getString("dir") == "out"
                    add(Message(id, r.getString("t"), out, r.getString("who"), r.getString("text"),
                        delivered = !out || !hasId || id in acked))
                }
                "note" -> add(Message(newMessageId(), r.getString("t"), false, "", r.getString("text"), true,
                    note = true, uri = if (r.isNull("uri")) null else r.optString("uri").ifEmpty { null }))
            }
        }
    }

    private fun add(m: Message) {
        byId[m.id] = list.size
        list += m
    }

    @Synchronized fun messages(): List<Message> = list.toList()

    @Synchronized fun pending(): List<Message> = list.filter { it.outgoing && !it.delivered }

    @Synchronized
    fun addOutgoing(who: String, text: String): Message {
        val m = Message(newMessageId(), nowIso(), true, who, text, delivered = false)
        history.append(JSONObject().put("k", "msg").put("id", m.id).put("t", m.time).put("dir", "out")
            .put("who", who).put("text", text))
        add(m)
        return m
    }

    /** Store an incoming message; null if we already have it (a re-sent duplicate). */
    @Synchronized
    fun addIncoming(id: String, sent: String, who: String, text: String): Message? {
        if (id in byId) return null
        val m = Message(id, sent.ifEmpty { nowIso() }, false, who, text, delivered = true)
        history.append(JSONObject().put("k", "msg").put("id", id).put("t", m.time).put("dir", "in")
            .put("who", who).put("text", text))
        add(m)
        return m
    }

    @Synchronized
    fun markDelivered(id: String): Message? {
        val index = byId[id] ?: return null
        val m = list[index]
        if (!m.outgoing || m.delivered) return null
        history.append(JSONObject().put("k", "ack").put("id", id))
        return m.copy(delivered = true).also { list[index] = it }
    }

    @Synchronized
    fun addNote(text: String, uri: String? = null): Message {
        val m = Message(newMessageId(), nowIso(), false, "", text, true, note = true, uri = uri)
        history.append(JSONObject().put("k", "note").put("t", m.time).put("text", text).apply { uri?.let { put("uri", it) } })
        add(m)
        return m
    }

    companion object {
        private val ISO_SECONDS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")
        fun nowIso(): String = LocalDateTime.now().format(ISO_SECONDS)
        fun newMessageId(): String = randomBytes(16).toHex()
    }
}
