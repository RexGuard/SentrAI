package pro.sentrai.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.time.LocalDate

class CheckRulesTest {
    private val today = LocalDate.of(2026, 11, 9)
    private val good = PhoneFacts(screenLock = true, usbDebugging = false, rooted = false, encrypted = true,
        outsideAppNames = emptyList(), screenReadingAppNames = emptyList(), android = 35, patch = "2026-10-05",
        appVersion = "0.1.0")

    @Test fun aGoodPhoneHasNothingToFix() {
        assertEquals(emptyList<String>(), CheckRules.findings(good, today).filter { !it.ok }.map { it.key })
    }

    @Test fun problemsComeFirstWithAFix() {
        val bad = good.copy(screenLock = false, patch = "2025-12-01", outsideAppNames = listOf("Free VPN"),
            screenReadingAppNames = listOf("Free VPN"))
        val f = CheckRules.findings(bad, today)
        assertEquals(listOf("screen_lock", "screen_reading_apps", "patch", "outside_apps"), f.filter { !it.ok }.map { it.key })
        assertEquals(Fix.SECURITY_SETTINGS, f.first().fix)
        assertEquals(listOf("Free VPN"), f.first { it.key == "outside_apps" }.apps)
    }

    @Test fun theReportCarriesCountsNotNames() {
        val r = CheckRules.report(good.copy(outsideAppNames = listOf("A", "B")))
        assertEquals(2, r["outside_apps"])
        assertFalse(r.values.any { it == "A" || it == "B" })
        assertEquals(setOf("screen_lock", "usb_debugging", "rooted", "encrypted", "outside_apps", "screen_reading_apps",
            "android", "patch", "app_version"), r.keys)
    }

    @Test fun patchAge() {
        assertEquals(308, CheckRules.patchDays("2026-01-05", today))
        assertEquals(null, CheckRules.patchDays("soon", today))
    }
}
