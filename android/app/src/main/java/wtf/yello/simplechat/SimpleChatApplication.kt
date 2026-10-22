package wtf.yello.simplechat

import android.app.Activity
import android.app.Application
import android.content.Context
import android.os.Build
import android.os.Bundle
import kotlinx.coroutines.flow.MutableStateFlow
import wtf.yello.simplechat.chat.AndroidFileStore
import wtf.yello.simplechat.core.MAX_NICK
import wtf.yello.simplechat.core.Messenger
import wtf.yello.simplechat.data.IdentityStore

/**
 * The process-wide state. Android creates one Application object per app
 * process, before any screen or service, and it lives as long as the process.
 * That makes it the right owner for the single [Messenger]: the screens
 * come and go (rotation, back button), and the [ChatService] keeps the
 * process - and with it the messenger's connections - alive in the background.
 *
 * It must be named in AndroidManifest.xml (android:name=".SimpleChatApplication").
 */
class SimpleChatApplication : Application() {

    private val prefs by lazy { getSharedPreferences("settings", Context.MODE_PRIVATE) }

    /** True if an old identity couldn't be unlocked and a new one was made (shown to the user once). */
    var identityWasReset = false
        private set

    val messenger: Messenger by lazy {
        val store = IdentityStore(this)
        val identity = store.loadOrCreate()
        identityWasReset = store.wasReset
        Messenger(identity, filesDir, savedNick, AndroidFileStore(this))
    }

    val savedNick: String get() = prefs.getString("nick", null) ?: Build.MODEL.take(MAX_NICK)

    fun saveNick(nick: String) = prefs.edit().putString("nick", nick).apply()

    /** Whether the user wants to be online (the service is running), and why starting failed, if it did. */
    val online = MutableStateFlow(false)
    val startError = MutableStateFlow<String?>(null)

    // Which conversation is on screen right now, so the service only notifies about others.
    @Volatile var visibleContact: String? = null
    @Volatile private var resumedActivities = 0
    val inForeground: Boolean get() = resumedActivities > 0

    override fun onCreate() {
        super.onCreate()
        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityResumed(activity: Activity) { resumedActivities++ }
            override fun onActivityPaused(activity: Activity) { resumedActivities-- }
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit
            override fun onActivityStarted(activity: Activity) = Unit
            override fun onActivityStopped(activity: Activity) = Unit
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
            override fun onActivityDestroyed(activity: Activity) = Unit
        })
    }
}
