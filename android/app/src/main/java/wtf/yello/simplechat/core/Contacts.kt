package wtf.yello.simplechat.core

import org.json.JSONArray
import org.json.JSONObject
import wtf.yello.simplechat.protocol.fingerprint
import wtf.yello.simplechat.protocol.hexToBytes
import wtf.yello.simplechat.protocol.toHex
import java.io.File

/**
 * Contacts: a trust-on-first-use store, like SSH's known_hosts (trust.py on
 * the desktop, same file format).
 *
 * The handshake proves the peer owns *some* key; only a human can tell it's
 * the *right* one. The first time you meet someone, you both compare
 * fingerprints over another channel, and the key is saved as a contact.
 * After that:
 *  - the same key connecting again is recognised automatically;
 *  - the app dials contacts by itself, but only accepts the exact saved key;
 *  - if an address *you typed* used to belong to a contact with a different
 *    key, the app refuses and warns you (a possible man-in-the-middle).
 *
 * Contacts are keyed by the public key in hex, which makes a convenient,
 * comparable id ("contact id") everywhere else in the app.
 */
class Contacts(private val file: File) {

    data class Contact(
        val id: String,                 // public key, hex
        val label: String,              // their nickname, kept up to date
        val hosts: List<String>,        // "host:port" addresses they were reached at
        val lastAddress: String?,       // where to dial them next
    ) {
        val publicKey: ByteArray get() = id.hexToBytes()
        val fingerprint: String get() = fingerprint(publicKey)
    }

    private val contacts = LinkedHashMap<String, Contact>()

    init {
        if (file.exists()) {
            val array = JSONArray(file.readText())
            for (i in 0 until array.length()) {
                val o = array.getJSONObject(i)
                val hosts = o.optJSONArray("hosts")?.let { h -> List(h.length()) { h.getString(it) } } ?: emptyList()
                val id = o.getString("public_key")
                // isNull: org.json's optString would turn a JSON null into the text "null".
                val last = if (o.isNull("last_address")) null else o.getString("last_address")
                contacts[id] = Contact(id, o.getString("label"), hosts, last)
            }
        }
    }

    @Synchronized fun all(): List<Contact> = contacts.values.toList()

    @Synchronized fun get(id: String): Contact? = contacts[id]

    /** Contacts *other than* [id] previously reached at [host]. */
    @Synchronized
    fun othersForHost(host: String, id: String): List<Contact> =
        contacts.values.filter { host in it.hosts && it.id != id }

    @Synchronized
    fun trust(publicKey: ByteArray, label: String, host: String?) {
        val id = publicKey.toHex()
        val existing = contacts[id] ?: Contact(id, label, emptyList(), null)
        contacts[id] = if (host != null) existing.copy(hosts = remember(existing.hosts, host)) else existing
        save()
    }

    @Synchronized
    fun setLastAddress(id: String, address: String) {
        val c = contacts[id] ?: return
        if (c.lastAddress != address) {
            contacts[id] = c.copy(lastAddress = address, hosts = remember(c.hosts, address))
            save()
        }
    }

    @Synchronized
    fun rename(id: String, label: String) {
        val c = contacts[id] ?: return
        if (c.label != label) {
            contacts[id] = c.copy(label = label)
            save()
        }
    }

    @Synchronized
    fun remove(id: String) {
        if (contacts.remove(id) != null) save()
    }

    private fun remember(hosts: List<String>, host: String) =
        if (host in hosts) hosts else (hosts + host).takeLast(MAX_HOSTS)

    private fun save() {
        val array = JSONArray()
        for (c in contacts.values) {
            array.put(JSONObject().put("public_key", c.id).put("label", c.label)
                .put("hosts", JSONArray(c.hosts)).put("last_address", c.lastAddress ?: JSONObject.NULL))
        }
        file.parentFile?.mkdirs()
        val tmp = File(file.path + ".tmp")
        tmp.writeText(array.toString(2))
        tmp.renameTo(file)
    }

    private companion object {
        const val MAX_HOSTS = 10
    }
}
