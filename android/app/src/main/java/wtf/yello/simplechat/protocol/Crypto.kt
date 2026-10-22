package wtf.yello.simplechat.protocol

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.MessageDigest
import java.security.SecureRandom

/*
 * Cryptographic building blocks shared by the handshake, the channel and the
 * history file. Bouncy Castle provides the primitives so they behave the
 * same on every Android version (and in plain-JVM unit tests).
 *
 * Every label below is byte-for-byte the one the desktop app uses. They're
 * "domain separation" strings: each hash or key derivation gets its own
 * label, so an output from one step can never be mistaken for another.
 */

val FINGERPRINT_LABEL = "simplechat-v1 fingerprint".toByteArray()
val HISTORY_KEY_LABEL = "simplechat-v1 history key".toByteArray()

val secureRandom = SecureRandom()

fun randomBytes(n: Int): ByteArray = ByteArray(n).also { secureRandom.nextBytes(it) }

fun sha256(vararg parts: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-256").run {
        parts.forEach { update(it) }
        digest()
    }

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

/**
 * Short, human-comparable digest of a public key: 128 bits of a labelled
 * SHA-256, shown as 8 groups of 4 hex digits. Far too many bits for an
 * attacker to brute-force another key with the same fingerprint.
 */
fun fingerprint(publicKey: ByteArray): String =
    sha256(FINGERPRINT_LABEL, publicKey).copyOf(16).toHex().uppercase().chunked(4).joinToString("-")

/** HKDF-SHA256: stretches one secret into independent keys. A null salt means 32 zero bytes, as in RFC 5869. */
fun hkdf(secret: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
    val generator = HKDFBytesGenerator(SHA256Digest())
    generator.init(HKDFParameters(secret, salt, info))
    return ByteArray(length).also { generator.generateBytes(it, 0, length) }
}

/** ChaCha20-Poly1305 encryption: returns ciphertext followed by the 16-byte authentication tag. */
fun aeadSeal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray? = null): ByteArray {
    val cipher = ChaCha20Poly1305()
    cipher.init(true, AEADParameters(KeyParameter(key), 128, nonce, aad))
    val out = ByteArray(cipher.getOutputSize(plaintext.size))
    val n = cipher.processBytes(plaintext, 0, plaintext.size, out, 0)
    cipher.doFinal(out, n)
    return out
}

/** ChaCha20-Poly1305 decryption. Returns null if the tag doesn't verify (tampered or wrong key). */
fun aeadOpen(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray? = null): ByteArray? {
    val cipher = ChaCha20Poly1305()
    cipher.init(false, AEADParameters(KeyParameter(key), 128, nonce, aad))
    val out = ByteArray(cipher.getOutputSize(ciphertext.size))
    return try {
        val n = cipher.processBytes(ciphertext, 0, ciphertext.size, out, 0)
        cipher.doFinal(out, n)
        out
    } catch (_: InvalidCipherTextException) {
        null
    } catch (_: IllegalArgumentException) {
        null // shorter than a tag
    }
}

/**
 * Long-term Ed25519 identity. The 32-byte seed is the private key (the same
 * "raw" format the desktop app stores); the public key is derived from it.
 */
class Identity(private val seed: ByteArray) {
    init {
        require(seed.size == 32) { "Ed25519 seed must be 32 bytes" }
    }

    private val privateKey = Ed25519PrivateKeyParameters(seed, 0)
    val publicKey: ByteArray = privateKey.generatePublicKey().encoded
    val fingerprint: String get() = fingerprint(publicKey)

    fun seedCopy(): ByteArray = seed.copyOf()

    fun sign(message: ByteArray): ByteArray =
        Ed25519Signer().run {
            init(true, privateKey)
            update(message, 0, message.size)
            generateSignature()
        }

    /** Key for the on-disk history, derived from the identity exactly like the desktop app does. */
    fun historyKey(): ByteArray = hkdf(seed, null, HISTORY_KEY_LABEL, 32)

    companion object {
        fun generate() = Identity(randomBytes(32))
    }
}

fun verifyEd25519(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
    try {
        Ed25519Signer().run {
            init(false, Ed25519PublicKeyParameters(publicKey, 0))
            update(message, 0, message.size)
            verifySignature(signature)
        }
    } catch (_: IllegalArgumentException) {
        false // not a valid public key at all
    }
