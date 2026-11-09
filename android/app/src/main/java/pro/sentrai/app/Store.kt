package pro.sentrai.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * What the app keeps on the phone: the panel's address and pinned certificate, and the sign-in key. The key is
 * encrypted with a key held in Android's keystore, so it can't be copied off the phone. Nothing is backed up.
 */
class Store(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("sentrai", Context.MODE_PRIVATE)

    var apiRoot: String?
        get() = prefs.getString("api_root", null)
        set(v) = prefs.edit().putString("api_root", v).apply()

    var pin: String?
        get() = prefs.getString("pin", null)
        set(v) = prefs.edit().putString("pin", v).apply()

    var email: String?
        get() = prefs.getString("email", null)
        set(v) = prefs.edit().putString("email", v).apply()

    var key: String?
        get() = prefs.getString("key", null)?.let { decrypt(it) }
        set(v) = prefs.edit().putString("key", v?.let { encrypt(it) }).apply()

    /** Notes and alerts already shown as a phone notification, so each is shown once. */
    var notified: Set<String>
        get() = prefs.getStringSet("notified", emptySet()) ?: emptySet()
        set(v) = prefs.edit().putStringSet("notified", v.toList().takeLast(200).toSet()).apply()

    val signedIn: Boolean get() = apiRoot != null && key != null

    fun client(): PanelClient = PanelClient(apiRoot ?: "", pin, key)

    fun signOut() {
        prefs.edit().remove("key").remove("notified").apply()
    }

    fun forgetPanel() {
        prefs.edit().clear().apply()
    }

    // ---------------------------------------------------------------- the keystore
    private fun secret(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .build())
        return gen.generateKey()
    }

    private fun encrypt(plain: String): String {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, secret()) }
        val out = c.iv + c.doFinal(plain.toByteArray())
        return Base64.encodeToString(out, Base64.NO_WRAP)
    }

    private fun decrypt(stored: String): String? = try {
        val all = Base64.decode(stored, Base64.NO_WRAP)
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, secret(), GCMParameterSpec(128, all.copyOfRange(0, 12)))
        }
        String(c.doFinal(all.copyOfRange(12, all.size)))
    } catch (e: Exception) {
        null // the keystore key is gone (e.g. the phone was reset): sign in again
    }

    private companion object {
        const val ALIAS = "sentrai_sign_in"
    }
}
