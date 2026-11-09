package pro.sentrai.app

import java.net.IDN
import java.net.URI
import java.util.Locale

/**
 * Checks a link on the phone itself. Nothing about the link leaves the phone.
 *
 * It looks for the tricks fake links use: a look-alike of a well-known name (rnicrosoft, paypa1), a real name
 * tucked in front of someone else's address (paypal.com.secure-login.top), a bare number instead of a name,
 * hidden foreign letters (xn--), link shorteners that hide where a link goes, and so on.
 */
object LinkCheck {
    enum class Verdict { LOOKS_OK, CAREFUL, LOOKS_FAKE, NOT_A_LINK }

    data class Result(val verdict: Verdict, val host: String, val reasons: List<String>) {
        val headline: String
            get() = when (verdict) {
                Verdict.LOOKS_OK -> "Nothing suspicious found"
                Verdict.CAREFUL -> "Be careful with this link"
                Verdict.LOOKS_FAKE -> "This link looks fake"
                Verdict.NOT_A_LINK -> "That doesn't look like a link"
            }
    }

    /** Well-known names people are tricked with, and their real addresses. */
    val BRANDS: Map<String, List<String>> = mapOf(
        "google" to listOf("google.com"), "gmail" to listOf("gmail.com", "google.com"),
        "microsoft" to listOf("microsoft.com", "live.com", "office.com", "microsoftonline.com"),
        "office" to listOf("office.com", "microsoft.com"), "outlook" to listOf("outlook.com", "live.com", "office.com"),
        "apple" to listOf("apple.com", "icloud.com"), "icloud" to listOf("icloud.com", "apple.com"),
        "paypal" to listOf("paypal.com"), "amazon" to listOf("amazon.com", "amazon.sg", "amazon.co.uk"),
        "facebook" to listOf("facebook.com", "fb.com"), "instagram" to listOf("instagram.com"),
        "whatsapp" to listOf("whatsapp.com", "whatsapp.net"), "netflix" to listOf("netflix.com"),
        "linkedin" to listOf("linkedin.com"), "dropbox" to listOf("dropbox.com"), "docusign" to listOf("docusign.com", "docusign.net"),
        "dhl" to listOf("dhl.com"), "fedex" to listOf("fedex.com"), "singpost" to listOf("singpost.com"),
        "dbs" to listOf("dbs.com.sg", "dbs.com"), "ocbc" to listOf("ocbc.com"), "uob" to listOf("uob.com.sg", "uobgroup.com"),
        "maybank" to listOf("maybank.com", "maybank2u.com.my"), "shopee" to listOf("shopee.sg", "shopee.com.my", "shopee.com"),
        "lazada" to listOf("lazada.sg", "lazada.com.my", "lazada.com"), "grab" to listOf("grab.com"),
        "singpass" to listOf("singpass.gov.sg"), "slack" to listOf("slack.com"), "zoom" to listOf("zoom.us"),
        "github" to listOf("github.com"), "steam" to listOf("steampowered.com", "steamcommunity.com"),
    )

    private val SHORTENERS = setOf("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
        "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id")
    private val RISKY_ENDINGS = setOf("zip", "mov", "top", "xyz", "click", "link", "work", "support", "rest", "cam",
        "icu", "buzz", "monster", "quest", "cfd", "sbs", "lol", "gq", "tk", "ml", "cf", "ga")
    private val BAIT_WORDS = listOf("login", "log-in", "signin", "sign-in", "verify", "verification", "secure", "account",
        "update", "unlock", "wallet", "reward", "prize", "refund", "invoice", "password", "suspend")
    // Two-part endings where the name sits one step further left (dbs.com.sg, bbc.co.uk).
    private val TWO_PART = setOf("com.sg", "edu.sg", "gov.sg", "org.sg", "net.sg", "co.uk", "org.uk", "gov.uk",
        "com.my", "gov.my", "com.au", "net.au", "org.au", "co.id", "go.id", "com.ph", "gov.ph", "co.jp", "com.br", "co.in")

    /** Finds the first link in shared text (a share often carries a title before the link). */
    fun findLink(text: String): String? =
        Regex("""(?i)\b((?:https?://|www\.)[^\s<>"']+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>"']*)?)""")
            .find(text.trim())?.value?.trimEnd('.', ',', ')', ']', '!', '?')

    /** The part of a host people read as "the site": example.com, dbs.com.sg. */
    fun siteOf(host: String): String {
        val parts = host.split('.').filter { it.isNotEmpty() }
        if (parts.size <= 2) return parts.joinToString(".")
        val lastTwo = parts.takeLast(2).joinToString(".")
        return if (lastTwo in TWO_PART) parts.takeLast(3).joinToString(".") else lastTwo
    }

    /** Letters and numbers swapped in to fool the eye, folded back to the letters they imitate. */
    fun unconfuse(s: String): String = s.lowercase(Locale.ROOT)
        .replace("rn", "m").replace("vv", "w").replace("cl", "d")
        .replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('4', 'a').replace('5', 's').replace('7', 't')
        .replace('8', 'b').replace('9', 'g').replace('!', 'i').replace('|', 'l').replace('$', 's').replace('@', 'a')
        .replace("-", "")

    fun editDistance(a: String, b: String): Int {
        val d = IntArray(b.length + 1) { it }
        for (i in 1..a.length) {
            var prev = d[0]
            d[0] = i
            for (j in 1..b.length) {
                val tmp = d[j]
                d[j] = minOf(d[j] + 1, d[j - 1] + 1, prev + if (a[i - 1] == b[j - 1]) 0 else 1)
                prev = tmp
            }
        }
        return d[b.length]
    }

    fun check(input: String): Result {
        val raw = findLink(input) ?: return Result(Verdict.NOT_A_LINK, "", listOf("Paste or share a whole link, like https://example.com/page."))
        val withScheme = if (Regex("(?i)^[a-z][a-z0-9+.-]*://").containsMatchIn(raw)) raw else "https://$raw"
        val uri = try { URI(withScheme.replace(" ", "%20")) } catch (e: Exception) { null }
        val rawHost = uri?.rawAuthority?.substringAfterLast('@')?.substringBefore(':')?.lowercase(Locale.ROOT)
            ?: return Result(Verdict.NOT_A_LINK, "", listOf("This link is broken, so it can't be checked."))
        if (rawHost.isEmpty()) return Result(Verdict.NOT_A_LINK, "", listOf("This link has no website name in it."))
        val host = rawHost.trimEnd('.')
        val shown = try { IDN.toUnicode(host) } catch (e: Exception) { host }

        val fake = mutableListOf<String>()
        val careful = mutableListOf<String>()

        if (uri.rawAuthority?.contains('@') == true) {
            fake += "The part before \"@\" is a decoy. The link really goes to $shown."
        }
        val isIp = Regex("""^\d{1,3}(\.\d{1,3}){3}$""").matches(host) || host.startsWith("[")
        if (isIp) fake += "It goes to a bare number instead of a website name. Real companies don't do that."
        if (host.split('.').any { it.startsWith("xn--") }) {
            fake += "The name uses letters from another alphabet that can look like normal ones ($shown)."
        }
        if (uri.scheme?.lowercase(Locale.ROOT) == "http") careful += "It isn't secure (http, not https). Never type a password there."

        if (!isIp) {
            val site = siteOf(host)
            val siteName = site.substringBefore('.')
            val label = unconfuse(siteName)
            val countryEnding = site.substringAfter('.').let { it.length == 2 || it in TWO_PART }
            for ((brand, homes) in BRANDS) {
                if (homes.any { host == it || host.endsWith(".$it") }) continue
                if (siteName == brand && countryEnding) continue  // the brand's own site in another country
                val b = unconfuse(brand)
                val name = brand.replaceFirstChar { it.titlecase(Locale.ROOT) }
                val words = host.removeSuffix(site).split('.', '-').filter { it.isNotEmpty() }
                when {
                    label == b || (brand.length >= 5 && editDistance(label, b) == 1) ||
                        (brand.length >= 4 && label.contains(b) && !siteName.replace("-", "").contains(brand)) -> {
                        fake += "It pretends to be $name, but the real site is ${homes.first()}. This one is $site."
                        break
                    }
                    words.any { unconfuse(it) == b } -> {
                        fake += "\"$brand\" is only in the front part. The site you'd really be on is $site."
                        break
                    }
                    brand.length >= 4 && label.contains(b) -> {
                        careful += "It uses the name $name but isn't their site (${homes.first()})."
                        break
                    }
                }
            }
            if (site in SHORTENERS || host in SHORTENERS) careful += "It's a short link, which hides where it really goes."
            val ending = host.substringAfterLast('.')
            if (ending in RISKY_ENDINGS) careful += "Its ending (.$ending) is popular with scam sites."
            if (host.count { it == '.' } >= 4) careful += "It has an unusually long chain of names in front."
            if (host.count { it == '-' } >= 3) careful += "Its name has many dashes, a common trick in fake addresses."
        }
        val rest = ((uri.rawPath ?: "") + "?" + (uri.rawQuery ?: "")).lowercase(Locale.ROOT)
        val bait = BAIT_WORDS.filter { host.contains(it) || rest.contains(it) }
        if (bait.isNotEmpty() && (fake.isNotEmpty() || careful.isNotEmpty())) {
            careful += "It asks you to ${bait.first().replace("-", " ")}, which scam links often do."
        }
        if (raw.length > 300) careful += "It's very long, which can hide where it goes."

        val verdict = when {
            fake.isNotEmpty() -> Verdict.LOOKS_FAKE
            careful.isNotEmpty() -> Verdict.CAREFUL
            else -> Verdict.LOOKS_OK
        }
        val reasons = (fake + careful).ifEmpty {
            listOf("The address looks normal. That doesn't prove it's safe: if a message rushes you or asks for a " +
                "password or payment, check with the sender another way first.")
        }
        return Result(verdict, shown, reasons)
    }
}
