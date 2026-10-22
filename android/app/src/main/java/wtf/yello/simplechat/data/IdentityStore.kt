package wtf.yello.simplechat.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import wtf.yello.simplechat.protocol.Identity
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stores the identity seed encrypted ("wrapped") by a key in the Android Keystore.
 *
 * The desktop app protects its identity with a password. On a phone the
 * usual approach is the Keystore: the wrapping key is generated inside it
 * (in secure hardware on most devices) and can never be exported. The app
 * can ask the Keystore to decrypt, but the key itself can't be copied off
 * the device. The file on disk is useless anywhere else.
 */
class IdentityStore(context: Context) {
    private val file = File(context.filesDir, "identity.bin")

    /** True if an identity existed but could not be unlocked, so a new one was created. */
    var wasReset = false
        private set

    fun loadOrCreate(): Identity {
        if (file.exists()) {
            try {
                return Identity(unwrap(file.readBytes()))
            } catch (_: Exception) {
                // The Keystore key is gone (e.g. app data restored without it). Start fresh.
                wasReset = true
            }
        }
        val identity = Identity.generate()
        val tmp = File(file.path + ".tmp")
        tmp.writeBytes(wrap(identity.seedCopy()))
        tmp.renameTo(file)
        return identity
    }

    private fun keystoreKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    /** AES-256-GCM; the Keystore picks a random 12-byte IV, stored in front of the ciphertext. */
    private fun wrap(seed: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, keystoreKey())
        return cipher.iv + cipher.doFinal(seed)
    }

    private fun unwrap(blob: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, keystoreKey(), GCMParameterSpec(128, blob, 0, 12))
        return cipher.doFinal(blob, 12, blob.size - 12)
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "simplechat-identity-wrap"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
