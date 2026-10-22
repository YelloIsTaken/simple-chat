package wtf.yello.simplechat.core

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import wtf.yello.simplechat.protocol.Identity
import java.io.BufferedReader
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.file.Files
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.random.Random

/**
 * The Kotlin Messenger against the desktop's Python Messenger (tests/interop_messenger.py):
 * LAN discovery, trust, messages and acks, files both ways, presence, and queued delivery.
 * Skipped if the desktop project's .venv is missing.
 */
class MessengerInteropTest {
    private val root = File(System.getProperty("simplechat.root") ?: "../..")
    private val python = File(root, ".venv/bin/python")
    private val script = File(root, "tests/interop_messenger.py")
    private val tmp: File = Files.createTempDirectory("interop").toFile()
    private val processes = mutableListOf<Process>()
    private var kotlin: Messenger? = null

    @After
    fun tearDown() {
        kotlin?.stop(0)
        processes.forEach { it.destroyForcibly() }
        tmp.deleteRecursively()
    }

    /** The Python peer: its stdout lines go to a queue we can wait on. */
    private inner class PythonPeer(home: File, port: Int, announceTo: Int) {
        val process: Process = ProcessBuilder(python.path, script.path, home.path, port.toString(), announceTo.toString())
            .redirectError(ProcessBuilder.Redirect.INHERIT).start().also { processes += it }
        val lines = LinkedBlockingQueue<String>()
        private val stdin = process.outputStream.bufferedWriter()

        init {
            Thread {
                process.inputStream.bufferedReader().use { r: BufferedReader ->
                    r.lineSequence().forEach { lines.put(it) }
                }
            }.apply { isDaemon = true }.start()
        }

        fun expect(prefix: String, timeoutS: Long = 20): String {
            val deadline = System.currentTimeMillis() + timeoutS * 1000
            while (true) {
                val left = deadline - System.currentTimeMillis()
                check(left > 0) { "python peer never printed $prefix" }
                val line = lines.poll(left, TimeUnit.MILLISECONDS) ?: continue
                if (line.startsWith("$prefix ") || line == prefix) return line.removePrefix(prefix).trim()
            }
        }

        fun command(line: String) {
            stdin.write(line + "\n")
            stdin.flush()
        }
    }

    private fun freePort() = ServerSocket(0).use { it.localPort }

    private fun waitUntil(what: String, timeoutS: Long = 20, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutS * 1000
        while (!condition()) {
            check(System.currentTimeMillis() < deadline) { "timed out waiting for $what" }
            Thread.sleep(50)
        }
    }

    @Test
    fun kotlinAndPythonMessengersTalk() {
        assumeTrue("desktop project venv not found at $python", python.canExecute())

        val downloads = File(tmp, "kotlin-downloads")
        val k = Messenger(Identity.generate(), File(tmp, "kotlin"), "android-kt", DirectoryFileStore(downloads),
            requestedPort = 0, bindAddress = InetAddress.getLoopbackAddress(), discoveryPort = 0,
            discoveryTargets = emptyList())
        kotlin = k
        k.start()
        // A scripted user: trusts everyone and accepts every file.
        Thread {
            while (k.running) {
                k.trustRequests.value.forEach { it.answer(true) }
                k.offers.value.keys.forEach { k.acceptOffer(it) }
                Thread.sleep(50)
            }
        }.apply { isDaemon = true }.start()

        // The Python messenger announces itself to our discovery port: it shows up as "nearby".
        val pyHome = File(tmp, "python")
        val pyPort = freePort()
        var py = PythonPeer(pyHome, pyPort, k.discoveryListenPort!!)
        val pyId = py.expect("READY").split(" ")[1]
        waitUntil("python in nearby") { k.nearby.value.any { it.id == pyId } }
        assertEquals("desktop-py", k.nearby.value.first { it.id == pyId }.nick)

        // Add it: both sides trust, the link comes up.
        k.addNearby(pyId)
        waitUntil("python online") { k.contacts.value.any { it.id == pyId && it.online } }
        py.expect("ONLINE")

        // A message goes over, is acknowledged (delivered), and comes back as an echo.
        assertEquals(null, k.sendText(pyId, "hello from kotlin, zażółć 🔒"))
        assertEquals("hello from kotlin, zażółć 🔒", py.expect("TEXT").substringAfter(' '))
        waitUntil("echo") { k.messages(pyId).value.any { it.text == "echo: hello from kotlin, zażółć 🔒" } }
        assertTrue(k.messages(pyId).value.first { it.outgoing }.delivered)

        // Files both ways.
        val fromPython = File(tmp, "from-python.bin").apply { writeBytes(Random.nextBytes(200_000)) }
        py.command("file ${k.identity.publicKey.joinToString("") { "%02x".format(it) }} ${fromPython.path}")
        waitUntil("file from python") { File(downloads, "from-python.bin").exists() }
        assertArrayEquals(fromPython.readBytes(), File(downloads, "from-python.bin").readBytes())

        val fromKotlin = File(tmp, "from-kotlin.bin").apply { writeBytes(Random.nextBytes(150_000)) }
        assertEquals(null, k.sendFile(pyId, PlainOutgoingFile(fromKotlin)))
        val saved = File(py.expect("FILE"))
        assertArrayEquals(fromKotlin.readBytes(), saved.readBytes())

        // Python quits: offline. A message to it is queued...
        py.command("quit")
        py.expect("STOPPED")
        waitUntil("python offline") { k.contacts.value.any { it.id == pyId && !it.online } }
        k.sendText(pyId, "are you there?")
        assertEquals(1, k.contacts.value.first { it.id == pyId }.pending)

        // ...and delivered when it comes back: we redial its last address by ourselves.
        py = PythonPeer(pyHome, pyPort, k.discoveryListenPort!!)
        py.expect("READY")
        assertEquals("are you there?", py.expect("TEXT", timeoutS = 30).substringAfter(' '))
        waitUntil("ack") { k.contacts.value.first { it.id == pyId }.pending == 0 }
        py.command("quit")
    }
}
