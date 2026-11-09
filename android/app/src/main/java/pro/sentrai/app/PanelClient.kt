package pro.sentrai.app

import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/** Something the panel said no to, in its own words. */
class PanelError(message: String, val status: Int) : IOException(message)

/** The panel's certificate isn't from a known authority. The person may trust it after checking [fingerprint]. */
class UntrustedPanel(val fingerprint: String) : IOException("This panel's certificate isn't from a known authority.")

/**
 * Talks to the panel's /mobile/* endpoints over HTTPS only.
 *
 * A panel with a certificate from a known authority just works. A panel with its own certificate (the installer
 * makes a self-signed one) is trusted only when its SHA-256 fingerprint matches [pin], which the person accepted
 * once after checking it with their admin, the same way the panel's agents pin it.
 */
class PanelClient(private val apiRoot: String, private val pin: String?, private val key: String?) {

    companion object {
        /** "panel.example.com" -> "https://panel.example.com/api"; a typed path is kept. */
        fun apiRootOf(typed: String): String {
            var t = typed.trim().trimEnd('/')
            if (t.isEmpty()) throw IllegalArgumentException("Type your company's SentrAI address.")
            if (t.startsWith("http://", ignoreCase = true)) throw IllegalArgumentException("SentrAI needs a secure (https) address.")
            if (!t.startsWith("https://", ignoreCase = true)) t = "https://$t"
            val uri = try { URI(t) } catch (e: Exception) { throw IllegalArgumentException("That doesn't look like a web address.") }
            if (uri.host.isNullOrEmpty()) throw IllegalArgumentException("That doesn't look like a web address.")
            val path = (uri.rawPath ?: "").trimEnd('/')
            val port = if (uri.port > 0) ":${uri.port}" else ""
            return "https://${uri.host}$port${path.ifEmpty { "/api" }}"
        }

        fun fingerprint(cert: X509Certificate): String =
            "sha256:" + MessageDigest.getInstance("SHA-256").digest(cert.encoded).joinToString("") { "%02x".format(it) }

        /** sha256:ab12... -> AB:12:... for people to compare with what their admin reads out. */
        fun pretty(fp: String): String = fp.removePrefix("sha256:").uppercase().chunked(2).joinToString(":")
    }

    private val system: X509TrustManager by lazy {
        val f = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        f.init(null as KeyStore?)
        f.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    fun get(path: String): JSONObject = call("GET", path, null)
    fun post(path: String, body: JSONObject = JSONObject()): JSONObject = call("POST", path, body)

    fun call(method: String, path: String, body: JSONObject?): JSONObject {
        var seen: X509Certificate? = null
        var pinned = false
        val trust = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = system.checkClientTrusted(chain, authType)
            override fun getAcceptedIssuers(): Array<X509Certificate> = system.acceptedIssuers
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                seen = chain.firstOrNull()
                try {
                    system.checkServerTrusted(chain, authType)
                } catch (e: CertificateException) {
                    val leaf = chain.firstOrNull() ?: throw e
                    if (pin != null && MessageDigest.isEqual(fingerprint(leaf).toByteArray(), pin.toByteArray())) {
                        pinned = true
                        return
                    }
                    throw e
                }
            }
        }
        val ssl = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }
        val conn = URL(apiRoot + path).openConnection() as HttpsURLConnection
        val default = HttpsURLConnection.getDefaultHostnameVerifier()
        conn.sslSocketFactory = ssl.socketFactory
        // A pinned certificate is the one the person checked, whatever name is in it.
        conn.hostnameVerifier = HostnameVerifier { host, session -> pinned || default.verify(host, session) }
        conn.requestMethod = method
        conn.connectTimeout = 15_000
        conn.readTimeout = 30_000
        conn.instanceFollowRedirects = false
        conn.setRequestProperty("Accept", "application/json")
        if (key != null) conn.setRequestProperty("Authorization", "Bearer $key")
        try {
            if (body != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.outputStream.use { it.write(body.toString().toByteArray()) }
            }
            val code = conn.responseCode
            val text = (if (code in 200..299) conn.inputStream else conn.errorStream)?.bufferedReader()?.use { it.readText() } ?: ""
            if (code !in 200..299) {
                val detail = try { JSONObject(text).opt("detail") } catch (e: Exception) { null }
                val words = when {
                    detail is String -> detail
                    code == 404 -> "SentrAI isn't answering at this address. Check it with your admin."
                    else -> "The panel answered with an error ($code). Try again in a minute."
                }
                throw PanelError(words, code)
            }
            return if (text.isBlank()) JSONObject() else JSONObject(text)
        } catch (e: SSLHandshakeException) {
            val cert = seen
            if (cert != null && !pinned) throw UntrustedPanel(fingerprint(cert))
            throw IOException("A secure connection to the panel failed.", e)
        } finally {
            conn.disconnect()
        }
    }
}

fun JSONArray.objects(): List<JSONObject> = (0 until length()).map { getJSONObject(it) }
fun JSONArray.strings(): List<String> = (0 until length()).map { getString(it) }
fun JSONObject.str(key: String, fallback: String = ""): String = if (isNull(key)) fallback else optString(key, fallback)
