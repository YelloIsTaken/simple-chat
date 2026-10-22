package wtf.yello.simplechat.ui

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.launch
import wtf.yello.simplechat.core.Alert
import wtf.yello.simplechat.core.ContactView
import wtf.yello.simplechat.core.Conversation
import wtf.yello.simplechat.core.NearbyPeer
import wtf.yello.simplechat.core.PendingTrust
import wtf.yello.simplechat.core.humanSize

/*
 * The screens, written with Jetpack Compose.
 *
 * A @Composable function describes what the UI looks like for the current
 * state. `collectAsState()` subscribes to one of the Messenger's StateFlows:
 * when it changes (on any thread), Compose calls the function again and
 * updates what changed ("recomposition"). Buttons call the ViewModel, which
 * calls the Messenger, which updates its flows: a one-way loop.
 *
 * `Modifier.testTag(...)` names elements for tests/android_e2e.py.
 */

private val Mono = FontFamily.Monospace
private val Online = Color(0xFF2E7D32)

/** Lets UI automation find elements by test tag. Dialogs are separate windows, so they need it too. */
@OptIn(ExperimentalComposeUiApi::class)
private val Tags = Modifier.semantics { testTagsAsResourceId = true }

private const val LOCAL_NETWORK = "android.permission.ACCESS_LOCAL_NETWORK"
private const val LOCAL_NETWORK_SDK = 37  // Android 17

@Composable
fun SimpleChatRoot(vm: AppViewModel) {
    val context = LocalContext.current
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    // Permissions, asked once at start: from Android 17 the local network needs
    // "Nearby devices" access (without it, connections silently time out), and
    // from Android 13 notifications need permission (optional for us).
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { result ->
        if (result[LOCAL_NETWORK] == false) {
            vm.warning = Alert.Warning("Local network access needed",
                "Simple Chat talks directly to other devices on your network. Allow \"Nearby devices\" " +
                    "in Settings > Apps > Simple Chat > Permissions, then tap \"Go online\".")
        } else {
            vm.goOnline()
        }
    }
    LaunchedEffect(Unit) {
        val wanted = buildList {
            if (Build.VERSION.SDK_INT >= LOCAL_NETWORK_SDK) add(LOCAL_NETWORK)
            if (Build.VERSION.SDK_INT >= 33) add(Manifest.permission.POST_NOTIFICATIONS)
        }
        val missing = wanted.filter { ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED }
        if (missing.isEmpty()) vm.goOnline() else launcher.launch(missing.toTypedArray())
    }

    // Short notices go to the snackbar (if they concern the open chat, or nobody in particular).
    LaunchedEffect(Unit) {
        vm.messenger.alerts.collect { alert ->
            when (alert) {
                is Alert.Warning -> vm.warning = alert
                is Alert.Notice -> if (alert.contactId == null || alert.contactId == vm.openContact) {
                    scope.launch { snackbar.showSnackbar(alert.text) }
                }
            }
        }
    }

    Box(Tags) {
        val open = vm.openContact
        if (open == null) ContactsScreen(vm, snackbar) else ChatScreen(vm, open, snackbar)
    }

    // Dialogs that can pop up anywhere.
    val trust by vm.messenger.trustRequests.collectAsState()
    trust.firstOrNull()?.let { TrustDialog(it) }
    val offers by vm.messenger.offers.collectAsState()
    val contacts by vm.messenger.contacts.collectAsState()
    offers.entries.firstOrNull()?.let { (contactId, offer) ->
        val nick = contacts.firstOrNull { it.id == contactId }?.nick ?: "Someone"
        AlertDialog(
            modifier = Tags,
            onDismissRequest = {},
            title = { Text("Incoming file") },
            text = { Text("$nick wants to send you '${offer.name}' (${humanSize(offer.size)}). It will be saved in Downloads/SimpleChat.") },
            confirmButton = { Button({ vm.messenger.acceptOffer(contactId) }, Modifier.testTag("accept")) { Text("Accept") } },
            dismissButton = { TextButton({ vm.messenger.rejectOffer(contactId) }, Modifier.testTag("reject")) { Text("Decline") } },
        )
    }
    vm.warning?.let { w ->
        AlertDialog(
            modifier = Tags,
            onDismissRequest = { vm.warning = null },
            title = { Text(w.title) },
            text = { Text(w.text) },
            confirmButton = { TextButton({ vm.warning = null }, Modifier.testTag("alert_ok")) { Text("OK") } },
        )
    }
}

/**
 * First contact: the heart of the security model. The handshake proved the peer owns the key with
 * this fingerprint; only a human can confirm it's the *right* key. Dismissing counts as "no".
 */
@Composable
private fun TrustDialog(pending: PendingTrust) {
    val r = pending.request
    AlertDialog(
        modifier = Tags,
        onDismissRequest = {},
        title = { Text(if (r.incoming) "Contact request from '${r.peerNick}'" else "Add '${r.peerNick}' as a contact?") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Connection: ${r.address}", style = MaterialTheme.typography.bodySmall)
                Text("Their fingerprint", style = MaterialTheme.typography.labelMedium)
                Text(r.peerFingerprint, fontFamily = Mono, modifier = Modifier.testTag("peer_fingerprint"))
                Text("Your fingerprint", style = MaterialTheme.typography.labelMedium)
                Text(r.myFingerprint, fontFamily = Mono)
                Text("Compare BOTH fingerprints with them over a channel you trust (in person, a phone call). " +
                    "The nickname proves nothing.", style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { Button({ pending.answer(true) }, Modifier.testTag("trust_yes")) { Text("They match") } },
        dismissButton = { TextButton({ pending.answer(false) }, Modifier.testTag("trust_no")) { Text("Decline") } },
    )
}

// ---------------------------------------------------------------------------
// Contact list
// ---------------------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ContactsScreen(vm: AppViewModel, snackbar: SnackbarHostState) {
    val contacts by vm.messenger.contacts.collectAsState()
    val nearby by vm.messenger.nearby.collectAsState()
    val online by vm.online.collectAsState()
    val startError by vm.startError.collectAsState()
    var adding by rememberSaveable { mutableStateOf(false) }
    var profile by rememberSaveable { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Simple Chat") },
                actions = {
                    TextButton({ adding = true }, Modifier.testTag("add")) { Text("Add") }
                    TextButton({ profile = true }, Modifier.testTag("profile")) { Text("Me") }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        LazyColumn(Modifier.padding(padding).fillMaxSize().testTag("contacts"), contentPadding = PaddingValues(bottom = 16.dp)) {
            if (!online) {
                item {
                    Card(Modifier.fillMaxWidth().padding(16.dp),
                        colors = CardDefaults.cardColors(MaterialTheme.colorScheme.errorContainer)) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("You're offline", fontWeight = FontWeight.Bold)
                            Text(startError ?: "Contacts can't reach you, and messages wait until you go online.")
                            Button(vm::goOnline, Modifier.testTag("go_online")) { Text("Go online") }
                        }
                    }
                }
            }
            item { SectionHeader("Contacts") }
            if (contacts.isEmpty()) {
                item {
                    Text("No contacts yet. People on your Wi-Fi who run Simple Chat appear under Nearby; " +
                        "or tap Add to enter an address.", Modifier.padding(16.dp),
                        style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            items(contacts, key = { it.id }) { c -> ContactRow(c) { vm.open(c.id) } }
            if (nearby.isNotEmpty()) {
                item { SectionHeader("Nearby") }
                items(nearby, key = { "n" + it.id }) { p -> NearbyRow(p) { vm.messenger.addNearby(p.id) } }
            }
        }
    }

    if (adding) AddContactDialog(vm.myAddress, onDismiss = { adding = false }) {
        adding = false
        vm.addByAddress(it)
    }
    if (profile) ProfileDialog(vm, online) { profile = false }
}

@Composable
private fun SectionHeader(text: String) {
    Text(text.uppercase(), Modifier.padding(start = 16.dp, top = 16.dp, bottom = 4.dp),
        style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
}

/** A round avatar with the first letter; a green dot when online, faded when offline. */
@Composable
private fun Avatar(name: String, online: Boolean) {
    Box(Modifier.size(44.dp)) {
        Box(
            Modifier.size(44.dp).alpha(if (online) 1f else 0.4f).background(colorFor(name), CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Text(name.take(1).uppercase(), color = Color.White, fontWeight = FontWeight.Bold)
        }
        if (online) {
            Box(Modifier.align(Alignment.BottomEnd).size(14.dp)
                .border(2.dp, MaterialTheme.colorScheme.surface, CircleShape).background(Online, CircleShape))
        }
    }
}

private fun colorFor(name: String): Color {
    val palette = listOf(0xFF5C6BC0, 0xFF26A69A, 0xFFEF6C00, 0xFF8E24AA, 0xFF1E88E5, 0xFFD81B60, 0xFF6D4C41)
    return Color(palette[Math.floorMod(name.hashCode(), palette.size)])
}

@Composable
private fun ContactRow(c: ContactView, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 10.dp)
            .testTag("contact:${c.nick}"),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Avatar(c.nick, c.online)
        Column(Modifier.weight(1f).alpha(if (c.online) 1f else 0.6f)) {
            Text(c.nick, fontWeight = if (c.unread > 0) FontWeight.Bold else FontWeight.Medium)
            Text(
                when {
                    c.pending > 0 -> "⏳ ${c.pending} waiting to be delivered"
                    c.lastMessage != null -> c.lastMessage
                    c.online -> "online"
                    else -> "offline"
                },
                style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (c.unread > 0) Badge(Modifier.testTag("unread:${c.nick}")) { Text("${c.unread}") }
    }
}

@Composable
private fun NearbyRow(p: NearbyPeer, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 10.dp)
            .testTag("nearby:${p.nick}"),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(Modifier.size(44.dp).border(2.dp, MaterialTheme.colorScheme.primary, CircleShape), contentAlignment = Alignment.Center) {
            Text("+", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
        }
        Column(Modifier.weight(1f)) {
            Text(p.nick, fontWeight = FontWeight.Medium)
            Text("${p.address} · tap to add", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun AddContactDialog(myAddress: String, onDismiss: () -> Unit, onAdd: (String) -> Unit) {
    var address by rememberSaveable { mutableStateOf("") }
    AlertDialog(
        modifier = Tags,
        onDismissRequest = onDismiss,
        title = { Text("Add a contact") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Their address (IP, or host:port):")
                OutlinedTextField(address, { address = it }, singleLine = true,
                    placeholder = { Text("192.168.1.20") }, modifier = Modifier.fillMaxWidth().testTag("add_address"))
                Text("Yours, for them: $myAddress", style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { Button({ onAdd(address) }, Modifier.testTag("add_ok"), enabled = address.isNotBlank()) { Text("Connect") } },
        dismissButton = { TextButton(onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun ProfileDialog(vm: AppViewModel, online: Boolean, onDismiss: () -> Unit) {
    var nick by rememberSaveable { mutableStateOf(vm.nick) }
    AlertDialog(
        modifier = Tags,
        onDismissRequest = onDismiss,
        title = { Text("You") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(nick, { nick = it }, label = { Text("Nickname") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("nick"))
                Text("Your fingerprint", style = MaterialTheme.typography.labelMedium)
                Text(vm.messenger.identity.fingerprint, fontFamily = Mono, modifier = Modifier.testTag("my_fingerprint"))
                Text("Others can add you at ${vm.myAddress}", style = MaterialTheme.typography.bodySmall)
                if (online) {
                    TextButton({ vm.goOffline(); onDismiss() }, Modifier.testTag("go_offline")) { Text("Go offline") }
                }
            }
        },
        confirmButton = { Button({ vm.changeNick(nick); onDismiss() }, Modifier.testTag("save_profile")) { Text("Save") } },
        dismissButton = { TextButton(onDismiss) { Text("Close") } },
    )
}

// ---------------------------------------------------------------------------
// Conversation
// ---------------------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ChatScreen(vm: AppViewModel, contactId: String, snackbar: SnackbarHostState) {
    val contacts by vm.messenger.contacts.collectAsState()
    val contact = contacts.firstOrNull { it.id == contactId }
    val messages by remember(contactId) { vm.messenger.messages(contactId) }.collectAsState()
    val transfers by vm.messenger.transfers.collectAsState()
    var showInfo by remember { mutableStateOf(false) }
    var confirmRemove by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    // Opens the system file picker; the lambda receives the chosen file (or null if cancelled).
    val pickFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { vm.sendFile(it)?.let { error -> scope.launch { snackbar.showSnackbar(error) } } }
    }
    BackHandler { vm.open(null) }
    if (contact == null) {  // removed meanwhile
        LaunchedEffect(Unit) { vm.open(null) }
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                navigationIcon = { TextButton({ vm.open(null) }, Modifier.testTag("back")) { Text("‹ Back") } },
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Avatar(contact.nick, contact.online)
                        Column {
                            Text(contact.nick, modifier = Modifier.testTag("peer_nick"), style = MaterialTheme.typography.titleMedium)
                            Text(if (contact.online) "online · end-to-end encrypted" else "offline · messages will be queued",
                                style = MaterialTheme.typography.labelSmall, modifier = Modifier.testTag("peer_status"))
                        }
                    }
                },
                actions = { TextButton({ showInfo = true }) { Text("Info") } },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            Column(Modifier.navigationBarsPadding().imePadding()) {
                transfers.values.filter { it.contactId == contactId }.forEach { t ->
                    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp)) {
                        Text("${if (t.transfer.outgoing) "↑" else "↓"} ${t.transfer.name} (${humanSize(t.transfer.size)})",
                            style = MaterialTheme.typography.bodySmall)
                        LinearProgressIndicator(
                            progress = { if (t.transfer.size > 0) t.transfer.done.toFloat() / t.transfer.size else 1f },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                }
                Composer(
                    canAttach = contact.online,
                    onSend = { text -> vm.send(text)?.let { scope.launch { snackbar.showSnackbar(it) } } == null },
                    onAttach = { pickFile.launch(arrayOf("*/*")) },
                )
            }
        },
    ) { padding ->
        val listState = rememberLazyListState()
        // Scroll to the newest message whenever the count changes.
        LaunchedEffect(messages.size) { if (messages.isNotEmpty()) listState.animateScrollToItem(messages.lastIndex) }
        LazyColumn(
            state = listState,
            modifier = Modifier.padding(padding).fillMaxSize().testTag("messages"),
            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            if (messages.isEmpty()) {
                item {
                    Text("Say hi to ${contact.nick}! Messages are end-to-end encrypted" +
                        (if (contact.online) "." else ", and delivered when they come online."),
                        Modifier.fillMaxWidth().padding(24.dp), textAlign = TextAlign.Center,
                        style = MaterialTheme.typography.bodySmall)
                }
            }
            items(messages, key = { it.id }) { m -> if (m.note) NoteLine(m) else Bubble(m) }
        }
    }

    if (showInfo) {
        AlertDialog(
            modifier = Tags,
            onDismissRequest = { showInfo = false },
            title = { Text(contact.nick) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Their fingerprint", style = MaterialTheme.typography.labelMedium)
                    Text(contact.fingerprint, fontFamily = Mono)
                    Text("Your fingerprint", style = MaterialTheme.typography.labelMedium)
                    Text(vm.messenger.identity.fingerprint, fontFamily = Mono)
                    HorizontalDivider()
                    TextButton({ showInfo = false; confirmRemove = true }) {
                        Text("Remove contact", color = MaterialTheme.colorScheme.error)
                    }
                }
            },
            confirmButton = { TextButton({ showInfo = false }) { Text("Close") } },
        )
    }
    if (confirmRemove) {
        AlertDialog(
            modifier = Tags,
            onDismissRequest = { confirmRemove = false },
            title = { Text("Remove ${contact.nick}?") },
            text = { Text("You'd have to compare fingerprints again to re-add them. Your message history stays on this phone.") },
            confirmButton = { Button({ confirmRemove = false; vm.remove(contactId) }) { Text("Remove") } },
            dismissButton = { TextButton({ confirmRemove = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun Composer(canAttach: Boolean, onSend: (String) -> Boolean, onAttach: () -> Unit) {
    var text by rememberSaveable { mutableStateOf("") }
    Row(
        Modifier.fillMaxWidth().padding(8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        TextButton(onAttach, enabled = canAttach, modifier = Modifier.testTag("attach")) { Text("File") }
        OutlinedTextField(text, { text = it }, placeholder = { Text("Message") }, maxLines = 4,
            modifier = Modifier.weight(1f).testTag("input"))
        Button({ if (onSend(text)) text = "" }, enabled = text.isNotBlank(), modifier = Modifier.testTag("send")) { Text("Send") }
    }
}

@Composable
private fun Bubble(m: Conversation.Message) {
    Box(Modifier.fillMaxWidth()) {
        Surface(
            shape = RoundedCornerShape(16.dp),
            color = if (m.outgoing) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
            modifier = Modifier.align(if (m.outgoing) Alignment.CenterEnd else Alignment.CenterStart).widthIn(max = 300.dp),
        ) {
            Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                Text(m.text)
                Text(
                    m.clock + if (m.outgoing) (if (m.delivered) "  ✓" else "  ⏳") else "",
                    style = MaterialTheme.typography.labelSmall,
                    modifier = Modifier.align(Alignment.End).alpha(0.7f),
                )
            }
        }
    }
}

@Composable
private fun NoteLine(m: Conversation.Message) {
    val context = LocalContext.current
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        Text(m.text, style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        m.uri?.let { uri ->
            TextButton({
                val u = Uri.parse(uri)
                try {
                    context.startActivity(Intent(Intent.ACTION_VIEW).setDataAndType(u, context.contentResolver.getType(u))
                        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION))
                } catch (_: ActivityNotFoundException) {
                }
            }) { Text("Open") }
        }
    }
}
