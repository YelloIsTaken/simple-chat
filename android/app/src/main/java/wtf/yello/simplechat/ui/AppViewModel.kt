package wtf.yello.simplechat.ui

import android.app.Application
import android.net.Uri
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import wtf.yello.simplechat.ChatService
import wtf.yello.simplechat.SimpleChatApplication
import wtf.yello.simplechat.chat.UriOutgoingFile
import wtf.yello.simplechat.core.Alert
import wtf.yello.simplechat.core.DEFAULT_PORT
import wtf.yello.simplechat.core.MAX_NICK
import wtf.yello.simplechat.core.cleanText
import wtf.yello.simplechat.core.localIpv4

/**
 * What the screens need, on top of the Messenger's own state.
 *
 * The Messenger lives in [SimpleChatApplication] and exposes its state as
 * StateFlows (contacts, nearby, messages, trust questions, file offers...);
 * the screens collect those directly with `collectAsState()`. This ViewModel
 * adds the purely UI-side state (which conversation is open, a warning
 * dialog) and turns button presses into Messenger calls.
 *
 * A ViewModel survives screen rotation, so an open conversation stays open.
 */
class AppViewModel(app: Application) : AndroidViewModel(app) {
    private val chatApp = app as SimpleChatApplication
    val messenger = chatApp.messenger
    val online = chatApp.online
    val startError = chatApp.startError

    /** The contact whose conversation is shown (null: the contact list). */
    var openContact by mutableStateOf<String?>(null)
        private set

    /** A warning that needs an OK (e.g. a changed key). */
    var warning by mutableStateOf<Alert.Warning?>(
        if (chatApp.identityWasReset) Alert.Warning("New identity created",
            "Your previous identity key could not be unlocked, so a new one was made. " +
                "Contacts will see a new fingerprint and must verify you again.") else null
    )

    var nick by mutableStateOf(messenger.nick)
        private set

    val myAddress: String get() = "${localIpv4() ?: "?"}:${if (messenger.port != 0) messenger.port else DEFAULT_PORT}"

    fun goOnline() = ChatService.goOnline(getApplication())

    fun goOffline() = ChatService.goOffline(getApplication())

    fun open(contactId: String?) {
        openContact = contactId
        chatApp.visibleContact = contactId
        messenger.openConversation(contactId)
    }

    fun send(text: String): String? = openContact?.let { messenger.sendText(it, text) }

    fun sendFile(uri: Uri): String? {
        val contact = openContact ?: return null
        val file = UriOutgoingFile.from(getApplication(), uri) ?: return "Can't read that file."
        return messenger.sendFile(contact, file)
    }

    /** "192.168.1.5" or "192.168.1.5:5001". */
    fun addByAddress(address: String) {
        val text = address.trim()
        val port = text.substringAfterLast(':', "").toIntOrNull()
        val host = if (port != null) text.substringBeforeLast(':') else text
        if (host.isNotEmpty()) messenger.addByAddress(host, port ?: DEFAULT_PORT)
    }

    fun changeNick(value: String) {
        val clean = cleanText(value).trim().take(MAX_NICK)
        if (clean.isEmpty()) return
        messenger.changeNick(clean)
        chatApp.saveNick(clean)
        nick = clean
    }

    fun remove(contactId: String) {
        messenger.removeContact(contactId)
        if (openContact == contactId) open(null)
    }
}
