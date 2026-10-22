package wtf.yello.simplechat.core

import org.json.JSONObject
import wtf.yello.simplechat.protocol.aeadOpen
import wtf.yello.simplechat.protocol.aeadSeal
import wtf.yello.simplechat.protocol.randomBytes
import wtf.yello.simplechat.protocol.toHex
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer

/**
 * Encrypted, append-only log of JSON records, one file per contact. It's the
 * same format as history.py on the desktop:
 *
 *     [4-byte length][12-byte random nonce][ChaCha20-Poly1305 ciphertext + tag]
 *
 * The key comes from the identity (Identity.historyKey). The contact's
 * public key is authenticated with every record ("associated data"), so
 * records can't be moved from one conversation's file into another's.
 * What the records mean is up to [Conversation].
 */
class History(directory: File, private val key: ByteArray, contact: ByteArray) {
    private val file = File(directory, contact.toHex().take(32) + ".log")
    private val aad = "simplechat-v1 history".toByteArray() + contact

    init {
        directory.mkdirs()
    }

    @Synchronized
    fun append(record: JSONObject) {
        val nonce = randomBytes(12)
        val blob = nonce + aeadSeal(key, nonce, record.toString().toByteArray(), aad)
        val bytes = ByteArrayOutputStream().also { DataOutputStream(it).run { writeInt(blob.size); write(blob) } }
        FileOutputStream(file, true).use { it.write(bytes.toByteArray()) }
    }

    /** All records. Stops quietly at a cut-off last record (e.g. a crash mid-write). */
    @Synchronized
    fun readAll(): List<JSONObject> {
        if (!file.exists()) return emptyList()
        val data = ByteBuffer.wrap(file.readBytes())
        val records = mutableListOf<JSONObject>()
        while (data.remaining() >= 4) {
            val length = data.int
            if (length < 12 || length > data.remaining()) break
            val blob = ByteArray(length).also { data.get(it) }
            val plain = aeadOpen(key, blob.copyOf(12), blob.copyOfRange(12, blob.size), aad)
                ?: throw IllegalStateException("cannot decrypt the history file (wrong key or corrupted)")
            records += JSONObject(String(plain))
        }
        return records
    }
}
