package wtf.yello.simplechat.chat

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Environment
import android.provider.MediaStore
import android.provider.OpenableColumns
import android.webkit.MimeTypeMap
import wtf.yello.simplechat.core.FileStore
import wtf.yello.simplechat.core.IncomingFile
import wtf.yello.simplechat.core.OutgoingFile
import wtf.yello.simplechat.core.Saved
import java.io.IOException
import java.io.InputStream

/*
 * Files on Android, behind the core's FileStore / OutgoingFile interfaces.
 *
 * Modern Android ("scoped storage") doesn't let apps roam the file system:
 *  - to *send*, the user picks a file in the system picker, and we get a
 *    content:// Uri granting access to that one file only (UriOutgoingFile);
 *  - to *receive*, we ask MediaStore (Android's index of shared files) to
 *    create a new entry in Downloads/SimpleChat. Apps may always add their
 *    own files there, so no storage permission is needed (AndroidFileStore).
 */

class UriOutgoingFile private constructor(
    private val context: Context,
    private val uri: Uri,
    override val name: String,
    override val size: Long,
) : OutgoingFile {
    override fun open(): InputStream =
        context.contentResolver.openInputStream(uri) ?: throw IOException("cannot open the file")

    companion object {
        /** null if the file's name or size can't be determined. */
        fun from(context: Context, uri: Uri): UriOutgoingFile? =
            context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
                null, null, null)?.use { c ->
                if (!c.moveToFirst() || c.isNull(1)) null
                else UriOutgoingFile(context, uri, c.getString(0) ?: "file", c.getLong(1))
            }
    }
}

class AndroidFileStore(private val context: Context) : FileStore {
    private val resolver get() = context.contentResolver

    override fun create(name: String): IncomingFile {
        val mime = MimeTypeMap.getSingleton()
            .getMimeTypeFromExtension(name.substringAfterLast('.', "").lowercase()) ?: "application/octet-stream"
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, name)
            put(MediaStore.Downloads.MIME_TYPE, mime)
            put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/SimpleChat")
            put(MediaStore.Downloads.IS_PENDING, 1)  // hidden from other apps until complete
        }
        val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            ?: throw IOException("cannot create a file in Downloads")
        val out = resolver.openOutputStream(uri) ?: run {
            resolver.delete(uri, null, null)
            throw IOException("cannot write to Downloads")
        }
        return object : IncomingFile {
            override val output = out

            override fun commit(): Saved {
                out.close()
                resolver.update(uri, ContentValues().apply { put(MediaStore.Downloads.IS_PENDING, 0) }, null, null)
                // MediaStore may have renamed it, e.g. "photo (1).jpg" if the name was taken.
                val saved = resolver.query(uri, arrayOf(MediaStore.Downloads.DISPLAY_NAME), null, null, null)
                    ?.use { if (it.moveToFirst()) it.getString(0) else null } ?: name
                return Saved("Downloads/SimpleChat/$saved", uri.toString())
            }

            override fun discard() {
                runCatching { out.close() }
                resolver.delete(uri, null, null)
            }
        }
    }
}
