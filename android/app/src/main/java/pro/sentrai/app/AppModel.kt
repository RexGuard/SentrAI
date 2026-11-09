package pro.sentrai.app

import android.content.Context
import android.os.Build
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException

enum class Screen { ADDRESS, SIGN_IN, HOME, PHONE, LINKS, ALERTS, MORE, LESSON, NOTICE, REPORT, MY_DATA }

/** The app's state and everything it asks the panel. One per activity; work runs off the main thread. */
class AppModel(private val context: Context, private val scope: CoroutineScope) {
    val store = Store(context)

    var screen by mutableStateOf(if (store.signedIn) Screen.HOME else if (store.apiRoot != null) Screen.SIGN_IN else Screen.ADDRESS)
    var busy by mutableStateOf(false)
    var error by mutableStateOf("")
    var info by mutableStateOf("")

    // sign-in
    var address by mutableStateOf(store.apiRoot?.removePrefix("https://")?.removeSuffix("/api") ?: "")
    var untrusted by mutableStateOf<String?>(null) // a fingerprint waiting for the person's yes
    var needCode by mutableStateOf(false)
    var inviteMode by mutableStateOf(false)

    // signed in
    var me by mutableStateOf<JSONObject?>(null)
    var lessons by mutableStateOf<List<JSONObject>>(emptyList())
    var lesson by mutableStateOf<JSONObject?>(null)
    var lessonResult by mutableStateOf<JSONObject?>(null)
    var notice by mutableStateOf("")
    var alerts by mutableStateOf<JSONObject?>(null)
    var findings by mutableStateOf<List<Finding>>(emptyList())
    var checkedAt by mutableStateOf("")
    var linkText by mutableStateOf("")
    var linkResult by mutableStateOf<LinkCheck.Result?>(null)
    var myData by mutableStateOf("")

    private val deviceName: String = "${Build.MANUFACTURER.replaceFirstChar { it.uppercase() }} ${Build.MODEL}".take(60)

    private fun act(work: suspend () -> Unit) {
        error = ""; info = ""; busy = true
        scope.launch {
            try {
                work()
            } catch (e: UntrustedPanel) {
                untrusted = e.fingerprint
            } catch (e: PanelError) {
                if (e.status == 401 && store.signedIn) {
                    store.signOut(); screen = Screen.SIGN_IN; error = "You were signed out. Please sign in again."
                } else error = e.message ?: "Something went wrong."
            } catch (e: IllegalArgumentException) {
                error = e.message ?: "Please check what you typed."
            } catch (e: IOException) {
                error = "Can't reach your company's SentrAI right now. Check your internet and try again."
            } finally {
                busy = false
            }
        }
    }

    private suspend fun <T> io(block: () -> T): T = withContext(Dispatchers.IO) { block() }

    // ---------------------------------------------------------------- address and sign-in
    fun findPanel() = act {
        val root = PanelClient.apiRootOf(address)
        val hello = io { PanelClient(root, store.pin.takeIf { store.apiRoot == root }, null).get("/mobile/hello") }
        if (hello.str("app") != "sentrai") throw IllegalArgumentException("That address isn't a SentrAI panel.")
        if (store.apiRoot != root) store.pin = null
        store.apiRoot = root
        screen = Screen.SIGN_IN
    }

    fun trust(fingerprint: String) {
        store.pin = fingerprint
        untrusted = null
        if (store.apiRoot == null) {
            store.apiRoot = PanelClient.apiRootOf(address)
        }
        findPanel()
    }

    fun changePanel() {
        store.forgetPanel(); me = null; screen = Screen.ADDRESS; needCode = false; inviteMode = false
    }

    fun signIn(email: String, password: String, code: String) = act {
        val body = JSONObject().put("email", email.trim()).put("password", password).put("device", deviceName)
        if (needCode) body.put("code", code.trim())
        val out = io { store.client().post("/mobile/login", body) }
        if (out.optBoolean("need_code")) {
            needCode = true; info = "Now type the 6-digit code from your authenticator app."
            return@act
        }
        signedIn(out)
    }

    fun acceptInvite(code: String, password: String, again: String) = act {
        if (password != again) throw IllegalArgumentException("The two passwords don't match.")
        val body = JSONObject().put("code", code).put("password", password).put("device", deviceName)
        signedIn(io { store.client().post("/mobile/invite/accept", body) })
    }

    private fun signedIn(out: JSONObject) {
        store.key = out.str("key")
        val m = out.getJSONObject("me")
        store.email = m.str("email")
        me = m; needCode = false; inviteMode = false
        SyncWorker.schedule(context)
        screen = Screen.HOME
        refresh()
    }

    fun signOut() = act {
        try { io { store.client().post("/mobile/logout") } } catch (e: IOException) { /* signed out here anyway */ }
        SyncWorker.cancel(context)
        store.signOut(); me = null; alerts = null; screen = Screen.SIGN_IN
    }

    // ---------------------------------------------------------------- signed in
    fun refresh() = act {
        val m = io { store.client().get("/mobile/me") }
        me = m
        if (lessons.isEmpty()) lessons = io { store.client().get("/mobile/lessons") }.getJSONArray("lessons").objects()
        if (m.optBoolean("sees_alerts")) alerts = io { store.client().get("/mobile/alerts") }
    }

    fun answer(note: JSONObject, button: String) {
        if (button == "One-minute lesson") return openLesson(note.str("lesson"))
        val answer = when (button) {
            "Yes, that was me" -> "was_me"
            "No, that wasn't me" -> "not_me"
            else -> "fixed"
        }
        act {
            me = io { store.client().post("/mobile/moments/${note.str("moment")}", JSONObject().put("answer", answer)) }
                .getJSONObject("me")
            info = if (answer == "not_me") "Thanks. Your admin has been told and will help you secure your account."
            else "Thanks, that's noted."
        }
    }

    fun openLesson(id: String) {
        lesson = lessons.firstOrNull { it.str("id") == id }
        lessonResult = null
        if (lesson != null) screen = Screen.LESSON
    }

    fun answerLesson(choices: List<Int>) = act {
        val l = lesson ?: return@act
        lessonResult = io {
            store.client().post("/mobile/lessons/${l.str("id")}/answer", JSONObject().put("answers", JSONArray(choices)))
        }
        me = io { store.client().get("/mobile/me") }
    }

    fun readNotice() = act {
        notice = io { store.client().get("/mobile/notice") }.str("text")
        screen = Screen.NOTICE
    }

    fun confirmNotice() = act {
        me = io { store.client().post("/mobile/notice") }
        screen = Screen.HOME
        info = "Thanks. Your notes from SentrAI now show here."
    }

    fun checkPhone() = act {
        val facts = io { PhoneCheck.run(context) }
        findings = CheckRules.findings(facts)
        checkedAt = java.text.DateFormat.getTimeInstance(java.text.DateFormat.SHORT).format(java.util.Date())
        val out = io { store.client().post("/mobile/check", JSONObject(CheckRules.report(facts))) }
        if (out.optInt("coached") > 0) me = io { store.client().get("/mobile/me") }
    }

    fun checkLink(text: String = linkText) {
        linkText = text
        linkResult = LinkCheck.check(text)
    }

    fun report(text: String, where: String, done: () -> Unit) = act {
        io { store.client().post("/mobile/report", JSONObject().put("text", text).put("where", where)) }
        info = "Sent. Someone will look at it soon. Thank you for speaking up."
        done()
        screen = Screen.MORE
    }

    fun loadMyData() = act {
        myData = io { store.client().get("/mobile/my-data") }.toString(2)
        screen = Screen.MY_DATA
    }

    fun loadAlerts() = act { alerts = io { store.client().get("/mobile/alerts") } }

    fun go(s: Screen) {
        error = ""; info = ""; screen = s
        when (s) {
            Screen.PHONE -> if (findings.isEmpty()) checkPhone()
            Screen.ALERTS -> loadAlerts()
            Screen.HOME -> refresh()
            else -> {}
        }
    }
}
