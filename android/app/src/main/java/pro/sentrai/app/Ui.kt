package pro.sentrai.app

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.json.JSONObject

private val Brand = Color(0xFF4612E0)
private val BrandLight = Color(0xFFA68CFF)
private val Good = Color(0xFF1E8E5A)
private val Warn = Color(0xFFB7791F)
private val Bad = Color(0xFFC53030)

@Composable
fun SentrAIApp(model: AppModel) {
    val dark = isSystemInDarkTheme()
    val colors = if (dark) darkColorScheme(primary = BrandLight, secondary = BrandLight, background = Color(0xFF120E24),
        surface = Color(0xFF120E24), surfaceVariant = Color(0xFF221B44))
    else lightColorScheme(primary = Brand, secondary = Brand, surfaceVariant = Color(0xFFF0ECFF))
    MaterialTheme(colorScheme = colors) {
        when (model.screen) {
            Screen.ADDRESS -> AddressScreen(model)
            Screen.SIGN_IN -> SignInScreen(model)
            else -> SignedIn(model)
        }
        model.untrusted?.let { fp -> TrustDialog(model, fp) }
    }
}

// ------------------------------------------------------------------ building blocks
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun Page(title: String, model: AppModel, bottom: @Composable () -> Unit = {}, back: (() -> Unit)? = null,
                 content: @Composable ColumnScope.() -> Unit) {
    if (back != null) BackHandler(onBack = back)
    Scaffold(
        topBar = {
            TopAppBar(title = { Text(title) }, navigationIcon = {
                if (back != null) TextButton(onClick = back) { Text("Back") }
            })
        },
        bottomBar = bottom,
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (model.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            if (model.error.isNotEmpty()) Banner(model.error, Bad)
            if (model.info.isNotEmpty()) Banner(model.info, Good)
            content()
        }
    }
}

@Composable
private fun Banner(text: String, color: Color) {
    Card(colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.12f)), modifier = Modifier.fillMaxWidth()) {
        Text(text, Modifier.padding(12.dp), color = MaterialTheme.colorScheme.onSurface)
    }
}

@Composable
private fun Section(content: @Composable ColumnScope.() -> Unit) {
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp), content = content)
    }
}

@Composable
private fun Muted(text: String) = Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

@Composable
private fun Heading(text: String) = Text(text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)

@Composable
private fun Field(value: String, onChange: (String) -> Unit, label: String, password: Boolean = false,
                  keyboard: KeyboardType = KeyboardType.Text, lines: Int = 1) {
    OutlinedTextField(value, onChange, label = { Text(label) }, singleLine = lines == 1, minLines = lines,
        visualTransformation = if (password) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
        keyboardOptions = KeyboardOptions(keyboardType = if (password) KeyboardType.Password else keyboard),
        modifier = Modifier.fillMaxWidth())
}

// ------------------------------------------------------------------ before sign-in
@Composable
private fun AddressScreen(model: AppModel) = Page("Welcome to SentrAI", model) {
    Text("SentrAI helps you stay safe at work: short tips when something looks risky, a check of this phone, and a link checker.")
    Field(model.address, { model.address = it }, "Your company's SentrAI address", keyboard = KeyboardType.Uri)
    Muted("The same address you or your admin use for the SentrAI website, like panel.yourcompany.com.")
    Button(onClick = { model.findPanel() }, enabled = !model.busy && model.address.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
        Text("Continue")
    }
}

@Composable
private fun TrustDialog(model: AppModel, fingerprint: String) = AlertDialog(
    onDismissRequest = { model.untrusted = null },
    title = { Text("Check this panel's fingerprint") },
    text = {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("This address uses its own security certificate, which is normal for a company's own SentrAI. " +
                "Ask your admin to read you the fingerprint and only continue if it matches:")
            Text(PanelClient.pretty(fingerprint), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
        }
    },
    confirmButton = { TextButton(onClick = { model.trust(fingerprint) }) { Text("It matches") } },
    dismissButton = { TextButton(onClick = { model.untrusted = null }) { Text("Cancel") } },
)

@Composable
private fun SignInScreen(model: AppModel) {
    var email by rememberSaveable { mutableStateOf(model.store.email ?: "") }
    var password by rememberSaveable { mutableStateOf("") }
    var code by rememberSaveable { mutableStateOf("") }
    var again by rememberSaveable { mutableStateOf("") }
    Page(if (model.inviteMode) "Set up with your invite" else "Sign in", model) {
        Muted("Panel: " + (model.store.apiRoot ?: "").removePrefix("https://"))
        if (model.inviteMode) {
            Text("Type the invite code your admin gave you and choose a password for this app.")
            Field(code, { code = it }, "Invite code")
            Field(password, { password = it }, "New password (at least 10 characters)", password = true)
            Field(again, { again = it }, "Type it again", password = true)
            Button(onClick = { model.acceptInvite(code, password, again) }, enabled = !model.busy, modifier = Modifier.fillMaxWidth()) {
                Text("Set up")
            }
            TextButton(onClick = { model.inviteMode = false }) { Text("I already have a password") }
        } else {
            Field(email, { email = it }, "Work email", keyboard = KeyboardType.Email)
            Field(password, { password = it }, "Password", password = true)
            if (model.needCode) Field(code, { code = it }, "6-digit code from your authenticator app", keyboard = KeyboardType.Number)
            Button(onClick = { model.signIn(email, password, code) }, enabled = !model.busy, modifier = Modifier.fillMaxWidth()) {
                Text("Sign in")
            }
            Muted("Owners and admins: use your SentrAI website email, password and authenticator code.")
            TextButton(onClick = { model.inviteMode = true; model.needCode = false }) { Text("I have an invite") }
        }
        TextButton(onClick = { model.changePanel() }) { Text("Use a different address") }
    }
}

// ------------------------------------------------------------------ signed in
private data class Tab(val screen: Screen, val label: String, val icon: ImageVector)

@Composable
private fun SignedIn(model: AppModel) {
    val owner = model.me?.optBoolean("sees_alerts") == true
    val tabs = listOfNotNull(Tab(Screen.HOME, "Home", Icons.Filled.Home), Tab(Screen.PHONE, "Phone", Icons.Filled.Check),
        Tab(Screen.LINKS, "Links", Icons.Filled.Search), if (owner) Tab(Screen.ALERTS, "Alerts", Icons.Filled.Notifications) else null,
        Tab(Screen.MORE, "More", Icons.Filled.Menu))
    val bar: @Composable () -> Unit = {
        NavigationBar {
            tabs.forEach { t ->
                NavigationBarItem(selected = model.screen == t.screen, onClick = { model.go(t.screen) },
                    icon = { Icon(t.icon, contentDescription = null) }, label = { Text(t.label) })
            }
        }
    }
    when (model.screen) {
        Screen.HOME -> HomeScreen(model, bar)
        Screen.PHONE -> PhoneScreen(model, bar)
        Screen.LINKS -> LinksScreen(model, bar)
        Screen.ALERTS -> AlertsScreen(model, bar)
        Screen.MORE -> MoreScreen(model, bar)
        Screen.LESSON -> LessonScreen(model)
        Screen.NOTICE -> NoticeScreen(model)
        Screen.REPORT -> ReportScreen(model)
        Screen.MY_DATA -> MyDataScreen(model)
        else -> {}
    }
}

@Composable
private fun HomeScreen(model: AppModel, bar: @Composable () -> Unit) {
    val me = model.me
    Page("SentrAI", model, bar) {
        if (me == null) {
            if (!model.busy) Button(onClick = { model.refresh() }) { Text("Try again") }
            return@Page
        }
        val coach = me.optJSONObject("coach") ?: JSONObject()
        Text("Hi ${me.str("name").split(" ").first()}", style = MaterialTheme.typography.headlineSmall)
        Muted(listOf(me.str("organisation"), me.str("role")).filter { it.isNotBlank() }.joinToString(" · "))
        if (!coach.optBoolean("in_coach")) {
            Section { Text("Your company hasn't added you to SentrAI's coaching yet. You can still check this phone and any link.") }
            return@Page
        }
        val level = coach.optJSONObject("level") ?: JSONObject()
        Section {
            Heading("Safe habits: ${level.str("name")}")
            Muted("${coach.optInt("points")} points · ${coach.optJSONArray("lessons_done")?.length() ?: 0} lessons done")
            val step = level.optInt("step", 1); val of = level.optInt("of", 5)
            LinearProgressIndicator(progress = { step.toFloat() / of }, modifier = Modifier.fillMaxWidth())
        }
        if (!coach.optBoolean("notice_confirmed")) {
            Section {
                Heading("First, how SentrAI works")
                Text("Your company uses SentrAI to keep work accounts safe. Read what it looks at and what it never sees, then your tips will show here.")
                Button(onClick = { model.readNotice() }) { Text("Read the notice") }
            }
            return@Page
        }
        val notes = coach.optJSONArray("notes")?.objects().orEmpty()
        if (notes.isEmpty()) Section { Text("Nothing for you right now. Nice work.") }
        notes.forEach { NoteCard(model, it) }
    }
}

@Composable
private fun NoteCard(model: AppModel, n: JSONObject) {
    val color = when (n.str("level")) { "urgent" -> Bad; "fix_soon" -> Warn; else -> Brand }
    val open = n.str("status") in setOf("new", "needs help")
    Section {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(if (n.str("level") == "tip") Icons.Filled.Info else Icons.Filled.Warning, null, tint = color, modifier = Modifier.size(18.dp))
            Spacer(Modifier.size(6.dp))
            Text(n.str("level_word"), color = color, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.weight(1f))
            Muted(n.str("at").take(10))
        }
        n.str("text").split("\n\n").drop(1).forEach { Text(it) }
        if (open) {
            n.optJSONArray("buttons")?.strings()?.forEach { b ->
                OutlinedButton(onClick = { model.answer(n, b) }, enabled = !model.busy, modifier = Modifier.fillMaxWidth()) { Text(b) }
            }
        } else {
            Muted("Done: ${n.str("status")}.")
            if (!n.optBoolean("lesson_done")) TextButton(onClick = { model.openLesson(n.str("lesson")) }) { Text("One-minute lesson") }
        }
    }
}

@Composable
private fun LessonScreen(model: AppModel) {
    val l = model.lesson ?: return
    val picks = remember(l.str("id")) { mutableStateListOf<Int>().apply { repeat(l.getJSONArray("questions").length()) { add(-1) } } }
    Page(l.str("title"), model, back = { model.go(Screen.HOME) }) {
        Text(l.str("card"))
        Heading("What to do")
        l.getJSONArray("steps").strings().forEachIndexed { i, s -> Text("${i + 1}. $s") }
        HorizontalDivider()
        Heading("Quick check")
        l.getJSONArray("questions").objects().forEachIndexed { qi, q ->
            Text(q.str("q"), fontWeight = FontWeight.Medium)
            q.getJSONArray("options").strings().forEachIndexed { oi, o ->
                Row(Modifier.fillMaxWidth().selectable(picks[qi] == oi, onClick = { picks[qi] = oi }, role = Role.RadioButton),
                    verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(selected = picks[qi] == oi, onClick = null)
                    Spacer(Modifier.size(8.dp))
                    Text(o)
                }
            }
        }
        val result = model.lessonResult
        if (result != null) {
            if (result.optBoolean("passed")) Banner("Well done, that's right. +10 points.", Good)
            else Banner(result.str("tip", "Not quite. Have another look and try again."), Warn)
        }
        Button(onClick = { model.answerLesson(picks.toList()) }, enabled = !model.busy && picks.none { it < 0 },
            modifier = Modifier.fillMaxWidth()) { Text("Check my answers") }
    }
}

@Composable
private fun NoticeScreen(model: AppModel) = Page("How SentrAI works", model, back = { model.go(Screen.HOME) }) {
    model.notice.lines().forEach { line ->
        val t = line.trim()
        when {
            t.startsWith("#") -> Heading(t.trimStart('#', ' '))
            t.startsWith("- ") || t.startsWith("* ") -> Text("•  " + t.drop(2).replace("**", ""))
            t.isNotEmpty() -> Text(t.replace("**", ""))
        }
    }
    Button(onClick = { model.confirmNotice() }, enabled = !model.busy, modifier = Modifier.fillMaxWidth()) { Text("I've read this") }
}

@Composable
private fun PhoneScreen(model: AppModel, bar: @Composable () -> Unit) {
    val context = LocalContext.current
    Page("Phone check", model, bar) {
        Muted("Only yes or no answers go to your company. App names and everything else stay on this phone.")
        val bad = model.findings.count { !it.ok }
        if (model.findings.isNotEmpty()) {
            Banner(if (bad == 0) "All good. Checked at ${model.checkedAt}." else
                "${CheckRules.plural(bad, "thing")} to fix. Checked at ${model.checkedAt}.", if (bad == 0) Good else Warn)
        }
        model.findings.forEach { f ->
            Section {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(if (f.ok) Icons.Filled.Check else Icons.Filled.Warning, null, tint = if (f.ok) Good else Warn,
                        modifier = Modifier.size(18.dp))
                    Spacer(Modifier.size(8.dp))
                    Heading(f.title)
                }
                if (f.detail.isNotEmpty()) Text(f.detail)
                if (f.apps.isNotEmpty()) Muted("On this phone: " + f.apps.joinToString(", "))
                if (f.fix != null && f.fixLabel != null) {
                    OutlinedButton(onClick = { PhoneCheck.open(context, f.fix) }) { Text(f.fixLabel) }
                }
            }
        }
        Button(onClick = { model.checkPhone() }, enabled = !model.busy, modifier = Modifier.fillMaxWidth()) { Text("Check again") }
    }
}

@Composable
private fun LinksScreen(model: AppModel, bar: @Composable () -> Unit) = Page("Link checker", model, bar) {
    Text("Got a link in a message and not sure? Paste it here, or share it to SentrAI from any app.")
    Field(model.linkText, { model.linkText = it }, "Link", keyboard = KeyboardType.Uri, lines = 2)
    Button(onClick = { model.checkLink() }, enabled = model.linkText.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
        Text("Check")
    }
    Muted("The link is checked on this phone and isn't sent anywhere.")
    model.linkResult?.let { r ->
        val color = when (r.verdict) {
            LinkCheck.Verdict.LOOKS_OK -> Good
            LinkCheck.Verdict.CAREFUL -> Warn
            LinkCheck.Verdict.LOOKS_FAKE -> Bad
            LinkCheck.Verdict.NOT_A_LINK -> Warn
        }
        Section {
            Text(r.headline, color = color, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            if (r.host.isNotEmpty()) Muted("Goes to: ${r.host}")
            r.reasons.forEach { Text("•  $it") }
            if (r.verdict == LinkCheck.Verdict.LOOKS_FAKE) {
                Text("Don't open it, and don't type anything there. If you already did, change that password and tell IT.",
                    fontWeight = FontWeight.Medium)
                TextButton(onClick = { model.go(Screen.REPORT) }) { Text("Tell my company about it") }
            }
        }
    }
}

@Composable
private fun AlertsScreen(model: AppModel, bar: @Composable () -> Unit) = Page("Alerts", model, bar) {
    val a = model.alerts ?: return@Page
    Section {
        Heading("Risk: ${a.optInt("risk_index")} (${a.str("band")})")
        Muted("${a.optInt("open")} open · ${a.optInt("staff_reports_new")} new staff reports · " +
            "${a.optJSONObject("coach")?.optInt("urgent_open") ?: 0} urgent coaching moments")
        val ph = a.optJSONObject("phones")
        if (ph != null) Muted("Phones: ${ph.optInt("phones_checked")} checked, ${ph.optInt("all_good")} with nothing to fix")
    }
    val list = a.optJSONArray("alerts")?.objects().orEmpty()
    if (list.isEmpty()) Section { Text("No open alerts. All quiet.") }
    list.forEach { al ->
        Section {
            val color = when (al.str("severity")) { "critical", "high" -> Bad; "medium" -> Warn; else -> Brand }
            Text(al.str("title"), color = color, fontWeight = FontWeight.SemiBold)
            Text(al.str("what"))
            if (al.str("fix").isNotBlank()) Muted("What to do: " + al.str("fix"))
            Muted(al.str("opened_at").replace('T', ' ').take(16) + if (al.optBoolean("needs_review")) " · waiting for you" else "")
        }
    }
    Muted("To act on an alert, open the SentrAI website.")
}

@Composable
private fun MoreScreen(model: AppModel, bar: @Composable () -> Unit) = Page("More", model, bar) {
    val me = model.me
    if (me != null) Muted("Signed in as ${me.str("email")} on ${me.str("device")}")
    OutlinedButton(onClick = { model.go(Screen.REPORT) }, modifier = Modifier.fillMaxWidth()) { Text("Something looks wrong") }
    OutlinedButton(onClick = { model.readNotice() }, modifier = Modifier.fillMaxWidth()) { Text("How SentrAI works (the notice)") }
    OutlinedButton(onClick = { model.loadMyData() }, modifier = Modifier.fillMaxWidth()) { Text("What SentrAI holds about me") }
    Spacer(Modifier.height(8.dp))
    Button(onClick = { model.signOut() }, enabled = !model.busy, modifier = Modifier.fillMaxWidth()) { Text("Sign out") }
    Muted("SentrAI app ${BuildConfig.VERSION_NAME}")
}

@Composable
private fun ReportScreen(model: AppModel) {
    var text by rememberSaveable { mutableStateOf(if (model.linkResult?.verdict == LinkCheck.Verdict.LOOKS_FAKE)
        "I got a message with a link that looks fake: ${model.linkResult?.host}" else "") }
    var where by rememberSaveable { mutableStateOf("") }
    Page("Something looks wrong", model, back = { model.go(Screen.MORE) }) {
        Text("Tell your company what you saw: an odd email or call, a strange pop-up, a computer acting up. A few sentences is enough.")
        Field(text, { text = it }, "What happened", lines = 4)
        Field(where, { where = it }, "Where (optional), like front desk or my laptop")
        Button(onClick = { model.report(text, where) { text = ""; where = "" } }, enabled = !model.busy && text.length >= 10,
            modifier = Modifier.fillMaxWidth()) { Text("Send") }
    }
}

@Composable
private fun MyDataScreen(model: AppModel) = Page("What SentrAI holds about me", model, back = { model.go(Screen.MORE) }) {
    Muted("This is everything your company's SentrAI keeps about you, exactly as stored.")
    if (model.busy) CircularProgressIndicator()
    Text(model.myData, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
}
