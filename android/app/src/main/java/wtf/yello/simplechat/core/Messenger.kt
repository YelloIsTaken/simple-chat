package wtf.yello.simplechat.core

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import wtf.yello.simplechat.protocol.Identity
import wtf.yello.simplechat.protocol.Role
import wtf.yello.simplechat.protocol.fingerprint
import wtf.yello.simplechat.protocol.hexToBytes
import wtf.yello.simplechat.protocol.toHex
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/*
 * The messenger: you, your contacts, and the links between you
 * (messenger.py on the desktop). No Android code in here, so it also runs in
 * plain JVM unit tests against the Python version.
 *
 * In the background, the whole time the app is online, it:
 *  - listens for incoming connections on the TCP port;
 *  - announces itself on the LAN and hears others (Discovery), which fills
 *    "Nearby" and says where contacts are right now;
 *  - dials offline contacts: where they were just announced from, or their
 *    last working address, retrying with back-off;
 *  - keeps one Link per online contact (online == has a link);
 *  - queues messages to offline contacts and sends them when a link comes up.
 *
 * The UI observes its state as Kotlin StateFlows (contacts, nearby,
 * messages, trust questions...). These are updated from background threads,
 * and Compose re-draws whatever reads them.
 *
 * Contacts are identified by their public key in hex ("contact id"): unlike
 * ByteArray, a String compares by value, so it works as a map key.
 */

const val DEFAULT_PORT = 5000
private const val DIAL_TIMEOUT_MS = 5_000
private const val RETRY_FIRST_MS = 10_000L
private const val RETRY_MAX_MS = 60_000L
private const val RETRY_AFTER_DROP_MS = 2_000L
private const val NEARBY_TTL_MS = 20_000L
private const val YIELD_DIAL_MS = 3_000L

data class ContactView(
    val id: String,
    val nick: String,
    val fingerprint: String,
    val online: Boolean,
    val unread: Int,
    val pending: Int,
    val lastMessage: String?,
)

data class NearbyPeer(val id: String, val nick: String, val fingerprint: String, val address: String)

data class TrustRequest(
    val peerNick: String,
    val address: String,
    val peerFingerprint: String,
    val myFingerprint: String,
    val incoming: Boolean,  // true: they contacted us (a contact request)
)

/** A trust question waiting for the user; the link's thread waits on [answer]. */
class PendingTrust(val request: TrustRequest) {
    internal val future = CompletableFuture<Boolean>()
    fun answer(trusted: Boolean) {
        future.complete(trusted)
    }
}

sealed interface Alert {
    /** Something the user must see (e.g. a changed key). */
    data class Warning(val title: String, val text: String) : Alert

    /** A short message, about a contact (contactId) or general (null). */
    data class Notice(val contactId: String?, val text: String, val error: Boolean) : Alert
}

data class ActiveTransfer(val contactId: String, val transfer: Transfer)

class Messenger(
    val identity: Identity,
    home: File,
    nick: String,
    private val files: FileStore,
    private val requestedPort: Int = DEFAULT_PORT,
    private val bindAddress: InetAddress? = null,
    private val discoveryPort: Int = DISCOVERY_PORT,
    private val discoveryTargets: List<InetSocketAddress>? = null,
) : LinkEvents {
    @Volatile var nick = nick
        private set
    val contactStore = Contacts(File(home, "known_peers.json"))
    private val historyDir = File(home, "history")
    private val historyKey = identity.historyKey()
    private val myId = identity.publicKey.toHex()

    // ---- state the UI observes ---------------------------------------------
    private val _contacts = MutableStateFlow<List<ContactView>>(emptyList())
    val contacts: StateFlow<List<ContactView>> = _contacts.asStateFlow()
    private val _nearby = MutableStateFlow<List<NearbyPeer>>(emptyList())
    val nearby: StateFlow<List<NearbyPeer>> = _nearby.asStateFlow()
    private val _trustRequests = MutableStateFlow<List<PendingTrust>>(emptyList())
    val trustRequests: StateFlow<List<PendingTrust>> = _trustRequests.asStateFlow()
    private val _offers = MutableStateFlow<Map<String, FileOffer>>(emptyMap())
    val offers: StateFlow<Map<String, FileOffer>> = _offers.asStateFlow()
    private val _transfers = MutableStateFlow<Map<String, ActiveTransfer>>(emptyMap())
    val transfers: StateFlow<Map<String, ActiveTransfer>> = _transfers.asStateFlow()
    private val _alerts = MutableSharedFlow<Alert>(extraBufferCapacity = 32)
    val alerts: SharedFlow<Alert> = _alerts.asSharedFlow()
    private val messageFlows = HashMap<String, MutableStateFlow<List<Conversation.Message>>>()

    /** Called (on a background thread) for every new incoming message; the service posts notifications. */
    @Volatile var onIncomingMessage: ((contactId: String, nick: String, message: Conversation.Message) -> Unit)? = null

    // ---- internal state, guarded by `lock` (no callbacks while holding it) ---
    private val lock = Any()
    private val links = HashMap<String, Link>()           // the active link per online contact
    private val dialing = HashSet<String>()
    private val asking = HashSet<String>()                // keys with an open trust question
    private val nextDial = HashMap<String, Long>()
    private val backoff = HashMap<String, Long>()
    private data class Seen(val nick: String, val host: String, val port: Int, val at: Long)
    private val seen = HashMap<String, Seen>()            // announcements heard
    private val conversations = HashMap<String, Conversation>()
    private val unread = HashMap<String, Int>()
    @Volatile var activeContact: String? = null           // the conversation on screen
        private set

    @Volatile var port = 0
        private set
    /** The UDP port discovery listens on (differs from DISCOVERY_PORT only in tests). */
    val discoveryListenPort: Int? get() = discovery?.port
    @Volatile var running = false
        private set
    private var server: ServerSocket? = null
    private var discovery: Discovery? = null

    init {
        refreshContacts()
    }

    // ---- start / stop -------------------------------------------------------

    /** Start listening, announcing and dialling. Throws IOException if the port is taken. */
    fun start() {
        val s = ServerSocket()
        s.reuseAddress = true
        s.bind(InetSocketAddress(bindAddress, requestedPort))
        server = s
        port = s.localPort
        running = true
        val d = Discovery(identity.publicKey, port, { nick }, ::onAnnounce, discoveryPort,
            discoveryTargets ?: broadcastTargets(discoveryPort))
        discovery = d
        thread("accept") { acceptLoop(s) }
        thread("dialer") { dialLoop() }
        d.start()
    }

    /** Say goodbye on every link and shut everything down. */
    fun stop(waitMs: Long = 1_000) {
        running = false
        runCatching { server?.close() }
        discovery?.stop()
        val all = synchronized(lock) { links.values.toList() }
        all.forEach { it.close(bye = true) }
        val deadline = System.currentTimeMillis() + waitMs
        all.forEach { it.awaitEnd(maxOf(0, deadline - System.currentTimeMillis())) }
        _trustRequests.value.forEach { it.answer(false) }
        refreshContacts()
    }

    // ---- what the UI reads --------------------------------------------------

    fun conversation(id: String): Conversation = synchronized(lock) {
        conversations.getOrPut(id) { Conversation(History(historyDir, historyKey, id.hexToBytes())) }
    }

    /** The messages with a contact, as a flow the chat screen observes. */
    fun messages(id: String): StateFlow<List<Conversation.Message>> {
        val conv = conversation(id)
        return synchronized(lock) { messageFlows.getOrPut(id) { MutableStateFlow(conv.messages()) } }
    }

    private fun publishMessages(id: String) {
        val flow = synchronized(lock) { messageFlows[id] } ?: return
        flow.value = conversation(id).messages()
    }

    fun isOnline(id: String) = synchronized(lock) { id in links }

    /** The UI now shows this conversation (null: none); its messages count as read. */
    fun openConversation(id: String?) {
        synchronized(lock) {
            activeContact = id
            if (id != null) unread.remove(id)
        }
        refreshContacts()
    }

    private fun refreshContacts() {
        val (online, counts) = synchronized(lock) { links.keys.toSet() to HashMap(unread) }
        _contacts.value = contactStore.all().map { c ->
            val conv = conversation(c.id)
            ContactView(c.id, c.label, c.fingerprint, c.id in online, counts[c.id] ?: 0, conv.pending().size,
                conv.messages().lastOrNull { !it.note }?.text)
        }.sortedWith(compareBy({ !it.online }, { it.nick.lowercase() }))
    }

    private fun refreshNearby() {
        val now = System.currentTimeMillis()
        val entries = synchronized(lock) { seen.toMap() }
        _nearby.value = entries.filter { (id, s) -> now - s.at < NEARBY_TTL_MS && contactStore.get(id) == null }
            .map { (id, s) -> NearbyPeer(id, s.nick, fingerprint(id.hexToBytes()), "${s.host}:${s.port}") }
            .sortedBy { it.nick.lowercase() }
    }

    // ---- what the user does -------------------------------------------------

    /** Send (or queue) a message. Returns an error to show, or null. */
    fun sendText(id: String, text: String): String? {
        if (text.toByteArray().size > MAX_MESSAGE_BYTES) return "Message too long (limit ${MAX_MESSAGE_BYTES / 1024} KB)."
        val m = conversation(id).addOutgoing("you", text)
        synchronized(lock) { links[id] }?.sendText(m.id, m.time, text)
        publishMessages(id)
        refreshContacts()
        return null
    }

    fun addByAddress(host: String, port: Int = DEFAULT_PORT) =
        thread("dial") { dial(null, host, port, "$host:$port") }

    fun addNearby(id: String) {
        val s = synchronized(lock) { seen[id] } ?: return
        thread("dial") { dial(id, s.host, s.port, "${s.host}:${s.port}") }
    }

    fun removeContact(id: String) {
        contactStore.remove(id)
        val link = synchronized(lock) {
            unread.remove(id)
            links.remove(id)
        }
        link?.close(bye = true)
        refreshContacts()
        refreshNearby()
    }

    fun changeNick(newNick: String) {
        val clean = cleanText(newNick).trim().take(MAX_NICK)
        if (clean.isEmpty()) return
        nick = clean
        synchronized(lock) { links.values.toList() }.forEach { it.sendNick(clean) }
        discovery?.announce()
    }

    /** Offer a file (online contacts only). Returns an error to show, or null. */
    fun sendFile(id: String, file: OutgoingFile): String? {
        val link = synchronized(lock) { links[id] } ?: return "Files can only be sent while the contact is online."
        link.offerFile(file)
        _alerts.tryEmit(Alert.Notice(id, "Offered '${file.name}'. Waiting for ${link.peerNick} to accept…", false))
        return null
    }

    fun acceptOffer(id: String) = thread("accept-file") { synchronized(lock) { links[id] }?.acceptOffer() }

    fun rejectOffer(id: String) = thread("reject-file") { synchronized(lock) { links[id] }?.rejectOffer() }

    // ---- connections --------------------------------------------------------

    private fun acceptLoop(s: ServerSocket) {
        while (running) {
            val conn = try {
                s.accept()
            } catch (_: Exception) {
                return  // server closed: we're stopping
            }
            val link = Link(conn, Role.RESPONDER, "${conn.inetAddress.hostAddress}:${conn.port}", identity, null,
                nick, port, files, this)
            thread("link") { link.run() }
        }
    }

    /** Dial host:port. expected: the contact we want (null: whoever answers, an address the user typed). */
    private fun dial(expected: String?, host: String, port: Int, manualHost: String?) {
        val sock = Socket()
        try {
            sock.connect(InetSocketAddress(host, port), DIAL_TIMEOUT_MS)
        } catch (e: Exception) {
            runCatching { sock.close() }
            if (manualHost != null) _alerts.tryEmit(Alert.Notice(null, "Could not connect to $manualHost: ${e.message}", true))
            return
        }
        Link(sock, Role.INITIATOR, "$host:$port", identity, expected?.hexToBytes(), nick, this.port, files, this,
            manualHost).run()
    }

    private fun dialLoop() {
        while (running) {
            Thread.sleep(1_000)
            val now = System.currentTimeMillis()
            val due = mutableListOf<Pair<String, Pair<String, Int>>>()
            var expired = false
            synchronized(lock) {
                for (c in contactStore.all()) {
                    if (c.id in links || c.id in dialing || now < (nextDial[c.id] ?: 0)) continue
                    val address = addressFor(c, now) ?: continue
                    dialing += c.id
                    due += c.id to address
                }
                val old = seen.filterValues { now - it.at >= NEARBY_TTL_MS }.keys
                expired = old.isNotEmpty()
                old.forEach { seen.remove(it) }
            }
            for ((id, address) in due) thread("dial") { autoDial(id, address.first, address.second) }
            if (expired) refreshNearby()
        }
    }

    private fun autoDial(id: String, host: String, port: Int) {
        try {
            dial(id, host, port, null)
        } finally {
            synchronized(lock) {
                dialing -= id
                // No link came up and nobody scheduled the next try (a dropped link does): back off.
                if (id !in links && (nextDial[id] ?: 0) <= System.currentTimeMillis()) {
                    val b = minOf(RETRY_MAX_MS, (backoff[id] ?: (RETRY_FIRST_MS / 2)) * 2)
                    backoff[id] = b
                    nextDial[id] = System.currentTimeMillis() + b
                }
            }
        }
    }

    /** Where to dial a contact: where it was just announced from, else its last working address. */
    private fun addressFor(c: Contacts.Contact, now: Long): Pair<String, Int>? {
        seen[c.id]?.takeIf { now - it.at < NEARBY_TTL_MS }?.let { return it.host to it.port }
        val last = c.lastAddress ?: return null
        val portPart = last.substringAfterLast(':', "").toIntOrNull()
        return if (portPart != null) last.substringBeforeLast(':') to portPart else last to DEFAULT_PORT
    }

    private fun onAnnounce(pk: ByteArray, peerNick: String, host: String, port: Int) {
        val id = pk.toHex()
        val now = System.currentTimeMillis()
        val isContact = contactStore.get(id) != null
        val wasNew: Boolean
        synchronized(lock) {
            val before = seen[id]
            wasNew = before == null
            val moved = before == null || before.host != host || before.port != port
            seen[id] = Seen(peerNick, host, port, now)
            if (isContact && id !in links && id !in dialing && moved) {
                // A contact appeared or moved: dial now. If both sides would dial at
                // once, the one with the larger key waits a little (PROTOCOL.md).
                val delay = if (compareKeys(identity.publicKey, pk) < 0) 0 else YIELD_DIAL_MS
                nextDial[id] = minOf(nextDial[id] ?: Long.MAX_VALUE, now + delay)
                backoff.remove(id)
            }
        }
        if (!isContact && wasNew) refreshNearby()
    }

    // ---- LinkEvents (called on link threads) --------------------------------

    override fun verify(link: Link): String? {
        val id = link.peerId
        if (id == myId) return "That's this app itself."
        if (contactStore.get(id) != null) return null
        link.manualHost?.let { host ->
            contactStore.othersForHost(host, id).firstOrNull()?.let { old ->
                _alerts.tryEmit(Alert.Warning("WARNING: the identity key at this address has changed!",
                    "$host used to be '${old.label}' (${old.fingerprint}), but now presents a different key:\n" +
                        "${link.peerFingerprint}\n\nSomeone may be intercepting this connection " +
                        "(man-in-the-middle), or your contact reinstalled the app. Confirm with them " +
                        "directly. If it's legitimate, remove '${old.label}' and add them again.\n\n" +
                        "Connection refused."))
                return ""
            }
        }
        synchronized(lock) {
            if (id in asking || !running) return "busy"  // one question per key: no dialog floods
            asking += id
        }
        val pending = PendingTrust(TrustRequest(link.peerNick, link.address, link.peerFingerprint,
            identity.fingerprint, incoming = link.role == Role.RESPONDER))
        _trustRequests.update { it + pending }
        val trusted = try {
            // Wait for the user, but give up if the other side hangs up meanwhile.
            var answer: Boolean? = null
            while (answer == null && running && !link.closing) {
                answer = runCatching { pending.future.get(500, TimeUnit.MILLISECONDS) }.getOrNull()
            }
            answer == true
        } finally {
            _trustRequests.update { list -> list.filter { it !== pending } }
            synchronized(lock) { asking -= id }
        }
        if (!trusted) return "Not trusted."
        link.newlyTrusted = true  // saved as a contact in linkUp, once the other side said yes too
        return null
    }

    override fun linkUp(link: Link) {
        val id = link.peerId
        var loser: Link? = null
        synchronized(lock) {
            val existing = links[id]
            if (existing != null && !existing.ended) {
                // Two links to one contact (both dialled at once): keep the one whose
                // initiator has the smaller key. The other side decides the same way.
                if (compareKeys(link.initiatorKey, existing.initiatorKey) < 0) {
                    loser = existing
                    links[id] = link
                } else {
                    loser = link
                }
            } else {
                links[id] = link
            }
            backoff.remove(id)
            nextDial.remove(id)
            dialing -= id
        }
        loser?.close(bye = false)
        if (loser === link) return
        if (link.newlyTrusted) contactStore.trust(link.peerPublic, link.peerNick, link.manualHost)
        link.peerPort?.let { contactStore.setLastAddress(id, "${link.peerHost}:$it") }
        contactStore.rename(id, link.peerNick)
        for (m in conversation(id).pending()) link.sendText(m.id, m.time, m.text)
        refreshContacts()
        refreshNearby()
    }

    override fun linkDown(link: Link, reason: String?) {
        val id = link.peerId
        val wasActive = synchronized(lock) {
            (links[id] === link).also {
                if (it) {
                    links.remove(id)
                    nextDial[id] = System.currentTimeMillis() + RETRY_AFTER_DROP_MS
                }
            }
        }
        when {
            wasActive -> {
                _offers.update { it - id }
                if (reason?.startsWith("Security") == true) _alerts.tryEmit(Alert.Notice(id, reason, true))
                refreshContacts()
            }
            !link.up && link.manualHost != null && running ->
                _alerts.tryEmit(Alert.Notice(null,
                    reason ?: "Could not add ${link.manualHost}: a different key answered.", reason != "Not trusted."))
            !link.up && reason?.startsWith("Security") == true ->
                _alerts.tryEmit(Alert.Notice(null, "${link.address}: $reason", true))
        }
    }

    override fun text(link: Link, id: String, sent: String, text: String) {
        val contact = link.peerId
        val m = conversation(contact).addIncoming(id, sent, link.peerNick, text) ?: return  // a re-sent duplicate
        synchronized(lock) {
            if (contact != activeContact) unread[contact] = (unread[contact] ?: 0) + 1
        }
        publishMessages(contact)
        refreshContacts()
        onIncomingMessage?.invoke(contact, link.peerNick, m)
    }

    override fun ack(link: Link, id: String) {
        conversation(link.peerId).markDelivered(id) ?: return
        publishMessages(link.peerId)
        refreshContacts()
    }

    override fun nick(link: Link, nick: String) {
        if (link.up) {
            contactStore.rename(link.peerId, nick)
            refreshContacts()
        }
    }

    override fun fileOffer(link: Link, offer: FileOffer?) {
        _offers.update { if (offer == null) it - link.peerId else it + (link.peerId to offer) }
    }

    override fun transfer(link: Link, progress: Transfer, finished: Boolean) {
        val key = "${link.peerId}/${progress.id}"
        _transfers.update { if (finished) it - key else it + (key to ActiveTransfer(link.peerId, progress)) }
    }

    override fun fileDone(link: Link, text: String, ok: Boolean, saved: Saved?) {
        if (ok) {
            val note = if (saved != null) "$text → ${saved.description}" else text
            conversation(link.peerId).addNote(note, saved?.uri)
            publishMessages(link.peerId)
        } else {
            _alerts.tryEmit(Alert.Notice(link.peerId, text, true))
        }
    }

    override fun notice(link: Link, text: String, error: Boolean) {
        _alerts.tryEmit(Alert.Notice(link.peerId, text, error))
    }

    private fun thread(name: String, block: () -> Unit) =
        Thread(block, name).apply { isDaemon = true }.start()
}
