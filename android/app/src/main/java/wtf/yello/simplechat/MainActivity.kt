package wtf.yello.simplechat

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import wtf.yello.simplechat.ui.AppViewModel
import wtf.yello.simplechat.ui.SimpleChatRoot
import wtf.yello.simplechat.ui.theme.SimpleChatTheme

/**
 * The app's single screen-holder ("Activity"). Android re-creates it on
 * rotation or a dark-mode switch, so it holds no state of its own: screen
 * state lives in [AppViewModel], and the messenger with its connections in
 * [SimpleChatApplication], kept alive in the background by [ChatService].
 *
 * Code map (each file explains itself in more detail):
 *   protocol/  the cryptography: Framing, Crypto, Handshake, SecureChannel
 *   core/      the messenger, a port of the desktop's Python (no Android code):
 *              Contacts, History, Conversation, Link, Discovery, Messenger
 *   chat/      Android file access (picker, Downloads)
 *   data/      the identity key, sealed by the Android Keystore
 *   ui/        AppViewModel and the Compose screens
 *   ChatService.kt, SimpleChatApplication.kt   staying online; owning the messenger
 */
class MainActivity : ComponentActivity() {
    private val vm: AppViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Draw behind the status and navigation bars; the screens add padding where needed.
        enableEdgeToEdge()
        openFromNotification(intent)
        setContent {
            SimpleChatTheme {
                SimpleChatRoot(vm)
            }
        }
    }

    /** launchMode="singleTop": tapping a notification while the app is open arrives here. */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        openFromNotification(intent)
    }

    override fun onResume() {
        super.onResume()
        (application as SimpleChatApplication).visibleContact = vm.openContact
    }

    private fun openFromNotification(intent: Intent?) {
        intent?.getStringExtra(EXTRA_CONTACT)?.let { vm.open(it) }
    }

    companion object {
        const val EXTRA_CONTACT = "contact"
    }
}
