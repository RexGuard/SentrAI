package pro.sentrai.app

import java.time.LocalDate
import java.time.temporal.ChronoUnit

/** What the phone check looked at. App names stay in [outsideAppNames] and never leave the phone. */
data class PhoneFacts(
    val screenLock: Boolean,
    val usbDebugging: Boolean,
    val rooted: Boolean,
    val encrypted: Boolean,
    val outsideAppNames: List<String>,
    val screenReadingAppNames: List<String>,
    val android: Int,
    val patch: String,
    val appVersion: String,
)

/** One line of the phone check's result, in plain words. */
data class Finding(
    val key: String,
    val ok: Boolean,
    val title: String,
    val detail: String,
    val fixLabel: String? = null,
    val fix: Fix? = null,
    val apps: List<String> = emptyList(),
)

enum class Fix { SECURITY_SETTINGS, UPDATE_SETTINGS, ACCESSIBILITY_SETTINGS, DEVELOPER_SETTINGS, APPS_SETTINGS }

object CheckRules {
    const val OUT_OF_DATE_DAYS = 120 // the panel uses the same limit

    fun patchDays(patch: String, today: LocalDate = LocalDate.now()): Int? =
        try { ChronoUnit.DAYS.between(LocalDate.parse(patch), today).toInt().coerceAtLeast(0) } catch (e: Exception) { null }

    /** The worst problems first, then what is fine. */
    fun findings(f: PhoneFacts, today: LocalDate = LocalDate.now()): List<Finding> {
        val out = mutableListOf<Finding>()
        out += if (f.rooted) Finding("rooted", false, "This phone's safety locks are off",
            "The phone has been changed (rooted) so apps can go around Android's protections. Talk to IT before using work apps on it.")
        else Finding("rooted", true, "Android's safety locks are on", "Apps can't reach each other's data.")
        out += if (!f.screenLock) Finding("screen_lock", false, "No screen lock",
            "Anyone who picks up this phone can open your work email and chats. Set a PIN, fingerprint or face unlock.",
            "Set a screen lock", Fix.SECURITY_SETTINGS)
        else Finding("screen_lock", true, "Screen lock is on", "Only you can open this phone.")
        if (f.screenReadingAppNames.isNotEmpty()) out += Finding("screen_reading_apps", false,
            plural(f.screenReadingAppNames.size, "app") + " from outside the Play Store can read your screen",
            "These apps have accessibility access, so they can see everything on screen, including codes and passwords. " +
                "Turn it off unless you really need it.", "Review screen access", Fix.ACCESSIBILITY_SETTINGS, f.screenReadingAppNames)
        val days = patchDays(f.patch, today)
        out += if (days != null && days > OUT_OF_DATE_DAYS) Finding("patch", false, "Months behind on updates",
            "The last security update is from ${f.patch} (${days / 30} months ago). Install what's waiting, or ask IT if none comes.",
            "Check for updates", Fix.UPDATE_SETTINGS)
        else Finding("patch", true, "Security updates are recent", if (f.patch.isNotEmpty()) "Last update: ${f.patch}." else "")
        if (f.outsideAppNames.isNotEmpty()) out += Finding("outside_apps", false,
            plural(f.outsideAppNames.size, "app") + " from outside the Play Store",
            "Apps from websites or chats skip Google's checks. Remove any you don't recognise or no longer use.",
            "Review apps", Fix.APPS_SETTINGS, f.outsideAppNames)
        else out += Finding("outside_apps", true, "Apps come from the Play Store", "No apps from unknown places.")
        out += if (f.usbDebugging) Finding("usb_debugging", false, "USB debugging is on",
            "A computer plugged into this phone could read and install things. Turn it off unless you make apps.",
            "Open developer settings", Fix.DEVELOPER_SETTINGS)
        else Finding("usb_debugging", true, "Developer settings are off", "")
        if (!f.encrypted) out += Finding("encrypted", false, "Storage isn't encrypted",
            "Setting a screen lock usually turns this on. If it stays off, ask IT.", "Set a screen lock", Fix.SECURITY_SETTINGS)
        return out.sortedBy { it.ok }
    }

    /** What is sent to the panel: yes/no answers and counts only. */
    fun report(f: PhoneFacts): Map<String, Any> = mapOf(
        "screen_lock" to f.screenLock, "usb_debugging" to f.usbDebugging, "rooted" to f.rooted, "encrypted" to f.encrypted,
        "outside_apps" to f.outsideAppNames.size, "screen_reading_apps" to f.screenReadingAppNames.size,
        "android" to f.android, "patch" to f.patch, "app_version" to f.appVersion,
    )

    fun plural(n: Int, word: String) = if (n == 1) "1 $word" else "$n ${word}s"
}
