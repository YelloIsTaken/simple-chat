package wtf.yello.simplechat.core

import org.json.JSONObject
import wtf.yello.simplechat.protocol.hexToBytes
import wtf.yello.simplechat.protocol.toHex
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/*
 * Finding other Simple Chat apps on the local network with UDP broadcast
 * (discovery.py on the desktop). Every few seconds each app sends
 *
 *     "SCHAT-ANNOUNCE v2\n" + JSON {"pk": <identity key, hex>, "port": <TCP port>, "nick": <nickname>}
 *
 * to the whole LAN, and listens for everyone else's. That's how a contact
 * whose IP address changed is found again, and how strangers appear under
 * "Nearby".
 *
 * Announcements are NOT authenticated: anyone can claim any key. That's fine,
 * because an announcement only says where to dial; the handshake on the
 * connection proves who's really there.
 *
 * On a phone, receiving broadcasts also needs a Wi-Fi "multicast lock",
 * which the ChatService holds while the app is online.
 */

const val DISCOVERY_PORT = 50505
private const val ANNOUNCE_EVERY_MS = 5_000L
private const val PREFIX = "SCHAT-ANNOUNCE v2\n"

/** This device's LAN IPv4 address, found by asking the OS which address it would use (no packet is sent). */
fun localIpv4(): String? = try {
    DatagramSocket().use {
        it.connect(InetAddress.getByName("192.0.2.1"), 9)
        (it.localAddress as? Inet4Address)?.hostAddress?.takeIf { ip -> ip != "0.0.0.0" }
    }
} catch (_: Exception) {
    null
}

fun broadcastTargets(port: Int = DISCOVERY_PORT): List<InetSocketAddress> {
    val targets = mutableListOf(InetSocketAddress("255.255.255.255", port))
    localIpv4()?.let { targets += InetSocketAddress(it.substringBeforeLast('.') + ".255", port) }
    return targets
}

class Discovery(
    private val publicKey: ByteArray,
    private val tcpPort: Int,
    private val nick: () -> String,
    private val onAnnounce: (publicKey: ByteArray, nick: String, host: String, port: Int) -> Unit,
    listenPort: Int = DISCOVERY_PORT,
    @Volatile var targets: List<InetSocketAddress> = broadcastTargets(listenPort),
) {
    // reuseAddress: several apps (or tests) on one machine can all bind the port.
    private val socket = DatagramSocket(null).apply {
        reuseAddress = true
        broadcast = true
        bind(InetSocketAddress(listenPort))
    }
    val port: Int get() = socket.localPort
    private val stopped = CountDownLatch(1)

    fun start() {
        Thread({ listen() }, "discovery-listen").apply { isDaemon = true }.start()
        Thread({
            do announce() while (!stopped.await(ANNOUNCE_EVERY_MS, TimeUnit.MILLISECONDS))
        }, "discovery-announce").apply { isDaemon = true }.start()
    }

    fun stop() {
        stopped.countDown()
        socket.close()
    }

    fun announce() {
        val json = JSONObject().put("pk", publicKey.toHex()).put("port", tcpPort).put("nick", nick())
        val payload = (PREFIX + json).toByteArray()
        for (target in targets) {
            try {
                socket.send(DatagramPacket(payload, payload.size, target))
            } catch (_: Exception) {
                // e.g. no network right now; try again next round
            }
        }
    }

    private fun listen() {
        val buffer = ByteArray(1024)
        while (stopped.count > 0) {
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                socket.receive(packet)
            } catch (_: Exception) {
                return  // socket closed by stop()
            }
            val text = String(packet.data, 0, packet.length)
            if (!text.startsWith(PREFIX)) continue
            try {
                val info = JSONObject(text.removePrefix(PREFIX))
                val pk = info.getString("pk").hexToBytes()
                val port = info.getInt("port")
                val peerNick = cleanText(info.optString("nick")).take(32).trim().ifEmpty { "unknown" }
                if (pk.size != 32 || port !in 1..65535 || pk.contentEquals(publicKey)) continue
                onAnnounce(pk, peerNick, packet.address.hostAddress ?: continue, port)
            } catch (_: Exception) {
                // malformed: ignore
            }
        }
    }
}
