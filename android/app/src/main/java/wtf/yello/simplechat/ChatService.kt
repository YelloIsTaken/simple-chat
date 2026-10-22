package wtf.yello.simplechat

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.IBinder
import androidx.core.app.NotificationCompat
import wtf.yello.simplechat.core.Conversation
import wtf.yello.simplechat.core.DEFAULT_PORT
import kotlin.concurrent.thread

/**
 * Keeps you online while the app is in the background.
 *
 * Android stops the network activity of apps that aren't visible. A
 * *foreground service* is the sanctioned way to keep working: it must show a
 * permanent notification ("Simple Chat is online"), so the user always knows
 * it's running and can stop it. The type "remoteMessaging" declares what
 * it's for: passing messages between devices.
 *
 * The service also:
 *  - holds a Wi-Fi *multicast lock*, without which Android drops incoming
 *    broadcast packets (LAN discovery) to save battery;
 *  - posts a notification for each incoming message that isn't on screen.
 */
class ChatService : Service() {
    private val app get() = application as SimpleChatApplication
    private var multicastLock: WifiManager.MulticastLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_GO_OFFLINE) {
            stopSelf()
            return START_NOT_STICKY
        }
        createChannels()
        startForeground(ONGOING_ID, ongoingNotification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING)
        if (multicastLock == null) {
            multicastLock = getSystemService(WifiManager::class.java)
                .createMulticastLock("simplechat-discovery").apply { setReferenceCounted(false); acquire() }
        }
        val messenger = app.messenger
        if (!messenger.running) {
            // start() binds sockets; keep it off the main thread like all network work.
            thread(name = "messenger-start") {
                try {
                    messenger.onIncomingMessage = ::notifyMessage
                    messenger.start()
                    app.startError.value = null
                    app.online.value = true
                } catch (e: Exception) {
                    app.startError.value = "Can't listen on port $DEFAULT_PORT: ${e.message}"
                    stopSelf()
                }
            }
        }
        return START_STICKY  // if Android kills the process, restart the service when it can
    }

    override fun onDestroy() {
        app.online.value = false
        multicastLock?.release()
        multicastLock = null
        val messenger = app.messenger
        thread(name = "messenger-stop") { messenger.stop() }  // says goodbye to every contact
        super.onDestroy()
    }

    private fun createChannels() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL_ONLINE, "Online status", NotificationManager.IMPORTANCE_MIN))
        nm.createNotificationChannel(NotificationChannel(CHANNEL_MESSAGES, "Messages", NotificationManager.IMPORTANCE_HIGH))
    }

    private fun openAppIntent(contactId: String? = null): PendingIntent {
        val intent = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            .apply { contactId?.let { putExtra(MainActivity.EXTRA_CONTACT, it) } }
        return PendingIntent.getActivity(this, contactId?.hashCode() ?: 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }

    private fun ongoingNotification(): Notification {
        val goOffline = PendingIntent.getService(this, 1,
            Intent(this, ChatService::class.java).setAction(ACTION_GO_OFFLINE), PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, CHANNEL_ONLINE)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentTitle("Simple Chat is online")
            .setContentText("Contacts can reach you. Messages are end-to-end encrypted.")
            .setOngoing(true)
            .setContentIntent(openAppIntent())
            .addAction(0, "Go offline", goOffline)
            .build()
    }

    /** Called on a messenger thread for every new incoming message. */
    private fun notifyMessage(contactId: String, nick: String, message: Conversation.Message) {
        if (app.inForeground && app.visibleContact == contactId) return  // it's on screen already
        val notification = NotificationCompat.Builder(this, CHANNEL_MESSAGES)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentTitle(nick)
            .setContentText(message.text)
            .setAutoCancel(true)
            .setContentIntent(openAppIntent(contactId))
            .build()
        runCatching {  // without the notification permission this is silently skipped
            getSystemService(NotificationManager::class.java).notify(contactId.hashCode(), notification)
        }
    }

    companion object {
        private const val ONGOING_ID = 1
        private const val CHANNEL_ONLINE = "online"
        private const val CHANNEL_MESSAGES = "messages"
        private const val ACTION_GO_OFFLINE = "wtf.yello.simplechat.GO_OFFLINE"

        fun goOnline(context: Context) =
            context.startForegroundService(Intent(context, ChatService::class.java))

        fun goOffline(context: Context) =
            context.stopService(Intent(context, ChatService::class.java))
    }
}
