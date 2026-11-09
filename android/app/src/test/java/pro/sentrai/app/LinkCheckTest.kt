package pro.sentrai.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import pro.sentrai.app.LinkCheck.Verdict

class LinkCheckTest {
    private fun verdict(link: String) = LinkCheck.check(link).verdict

    @Test fun realSitesLookOk() {
        for (link in listOf("https://www.google.com/search?q=x", "https://login.microsoftonline.com/common",
                "https://www.paypal.com/signin", "https://internet-banking.dbs.com.sg/", "https://google.com.sg",
                "https://example.org/about", "accounts.google.com")) {
            assertEquals(link, Verdict.LOOKS_OK, verdict(link))
        }
    }

    @Test fun lookAlikesLookFake() {
        for (link in listOf("https://rnicrosoft.com/login", "https://paypa1.com", "http://micros0ft-support.com",
                "https://paypal.com.secure-login.top/verify", "https://google.evil.example/x", "http://192.168.4.20/bank",
                "https://xn--pple-43d.com", "https://www.google.com@phish.example/", "https://amazon.xyz/refund")) {
            assertEquals(link, Verdict.LOOKS_FAKE, verdict(link))
        }
    }

    @Test fun shortAndOddLinksNeedCare() {
        assertEquals(Verdict.CAREFUL, verdict("https://bit.ly/3abcde"))
        assertEquals(Verdict.CAREFUL, verdict("http://example.com/"))
        assertEquals(Verdict.CAREFUL, verdict("https://free-gift-card-now.zip/claim"))
        assertEquals(Verdict.CAREFUL, verdict("https://my-paypal-help.com"))
    }

    @Test fun findsTheLinkInSharedText() {
        assertEquals("https://bit.ly/x", LinkCheck.findLink("Your parcel is waiting: https://bit.ly/x."))
        assertEquals(Verdict.NOT_A_LINK, verdict("hello there"))
        val r = LinkCheck.check("Check www.paypa1.com now")
        assertEquals("www.paypa1.com", r.host)
        assertTrue(r.reasons.first().contains("paypal.com"))
    }

    @Test fun sitesAndConfusables() {
        assertEquals("dbs.com.sg", LinkCheck.siteOf("internet-banking.dbs.com.sg"))
        assertEquals("example.com", LinkCheck.siteOf("a.b.example.com"))
        assertEquals("microsoft", LinkCheck.unconfuse("rnicr0soft"))
        assertEquals(1, LinkCheck.editDistance("paypai", "paypal"))
    }
}
