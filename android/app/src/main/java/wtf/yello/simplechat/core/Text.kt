package wtf.yello.simplechat.core

import java.util.Locale

/*
 * Cleaning of text that comes from the peer (same rules as cli.py), so a
 * peer can't smuggle in invisible characters, direction overrides that
 * disguise file names, or path tricks like "../../".
 */

const val MAX_NICK = 32
const val MAX_MESSAGE = 16 * 1024

private const val ZERO_WIDTH_JOINER = 0x200D

/**
 * Keep letters, digits, punctuation, symbols and emoji; drop Unicode "other" categories:
 * control characters, invisible format characters (like the right-to-left override that
 * can make "gnp.exe" display as "exe.png"), private-use and unassigned code points.
 * We walk *code points*, not chars: an emoji is two Kotlin chars (a surrogate pair).
 */
fun cleanText(text: String): String {
    val sb = StringBuilder()
    text.codePoints().forEach { cp ->
        val type = Character.getType(cp)
        val isOther = type == Character.CONTROL.toInt() || type == Character.FORMAT.toInt() ||
            type == Character.PRIVATE_USE.toInt() || type == Character.SURROGATE.toInt() ||
            type == Character.UNASSIGNED.toInt()
        if (cp == '\t'.code || cp == ZERO_WIDTH_JOINER || !isOther) sb.appendCodePoint(cp)
    }
    return sb.toString()
}

fun cleanNick(raw: ByteArray): String = cleanText(String(raw, Charsets.UTF_8)).trim().take(MAX_NICK).ifEmpty { "peer" }

fun safeFilename(name: String): String =
    cleanText(name.replace('\\', '/').substringAfterLast('/')).trim().trimStart('.').take(200).ifEmpty { "file" }

fun humanSize(bytes: Long): String {
    var n = bytes.toDouble()
    for (unit in listOf("B", "KB", "MB", "GB")) {
        if (n < 1024 || unit == "GB") return if (unit == "B") "${n.toLong()} B" else "%.1f %s".format(Locale.ROOT, n, unit)
        n /= 1024
    }
    return "%.1f TB".format(Locale.ROOT, n)
}
