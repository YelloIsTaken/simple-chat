package wtf.yello.simplechat.core

import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/*
 * How the core reads and writes files, without knowing about Android.
 * On the phone, AndroidFileStore (chat/FileStore.kt) implements these with
 * the system file picker and MediaStore; tests use plain directories.
 */

/** A file the user chose to send. */
interface OutgoingFile {
    val name: String
    val size: Long
    fun open(): InputStream
}

/** A received file being written; it only becomes visible after [commit]. */
interface IncomingFile {
    val output: OutputStream

    /** Finish the file and say where it was saved. */
    fun commit(): Saved

    fun discard()
}

/** Where a received file ended up: a description for the user, plus a URI to open it (if any). */
data class Saved(val description: String, val uri: String? = null)

fun interface FileStore {
    fun create(name: String): IncomingFile
}

/** A FileStore that saves into a directory (desktop-style; used by the tests). */
class DirectoryFileStore(private val dir: File) : FileStore {
    override fun create(name: String): IncomingFile {
        dir.mkdirs()
        var target = File(dir, name)
        var i = 1
        val dot = name.lastIndexOf('.').takeIf { it > 0 }
        while (target.exists() || File(target.path + ".part").exists()) {
            target = File(dir, if (dot == null) "$name ($i)" else "${name.take(dot)} ($i)${name.drop(dot)}")
            i++
        }
        val part = File(target.path + ".part")
        val out = part.outputStream()
        return object : IncomingFile {
            override val output = out
            override fun commit(): Saved {
                out.close()
                if (!part.renameTo(target)) throw IOException("cannot rename $part")
                return Saved(target.path)
            }
            override fun discard() {
                runCatching { out.close() }
                part.delete()
            }
        }
    }
}

/** An OutgoingFile backed by a plain file (tests). */
class PlainOutgoingFile(private val file: File) : OutgoingFile {
    override val name: String get() = file.name
    override val size: Long get() = file.length()
    override fun open(): InputStream = file.inputStream()
}
