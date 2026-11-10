"""Website check: an outside look at the company's own websites, only once it proved it owns them."""
import io
import json
import sys
from pathlib import Path

import pytest

from app import websites as ws

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import sentrai_cli as cli  # noqa: E402

from .test_cli import through  # noqa: E402

NOW = 1_800_000_000.0
STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"


class FakeNet(ws.Net):
    """A pretend internet: pages by URL, DNS TXT by name, and a log of every request to a site."""

    def __init__(self, pages=None, txt=None, addresses=None, tls=None):
        self.pages, self.txts = dict(pages or {}), dict(txt or {})
        self.addrs = addresses or {}
        self.tls_info = tls or {"version": "TLSv1.3", "not_after": "Jan  1 00:00:00 2030 GMT"}
        self.log = []

    def pause(self):
        pass

    def addresses(self, host):
        return self.addrs.get(host, ["93.184.216.34"])

    def get(self, url, max_bytes):
        self.log.append(url)
        r = self.pages.get(url)
        if r is None:
            return ws.Resp(404, url, {"content-type": "text/html"}, [], "<html>not found</html>")
        if isinstance(r, ws.Resp):
            return r
        return ws.Resp(200, url, {"content-type": "text/html"}, [], r)

    def tls(self, host):
        self.log.append(f"tls:{host}")
        return self.tls_info

    def txt(self, name):
        return self.txts.get(name, [])


GOOD_HEADERS = {"content-type": "text/html", "strict-transport-security": "max-age=31536000; includeSubDomains",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin",
                "server": "nginx"}


def good_site(token=None):
    pages = {
        "http://shop.test/": ws.Resp(301, "http://shop.test/", {"location": "https://shop.test/"}),
        "https://shop.test/": ws.Resp(200, "https://shop.test/", GOOD_HEADERS,
                                      ["sid=abc; Secure; HttpOnly; SameSite=Lax"],
                                      '<html><title>Shop</title><script src="/app.js"></script>'
                                      '<form action="/login"><input type="password"></form></html>'),
        "https://shop.test/app.js": "console.log('hi')",
        "https://shop.test/.well-known/security.txt": "Contact: mailto:security@shop.test\n",
    }
    txt = {"shop.test": ["v=spf1 include:_spf.google.com -all"],
           "_dmarc.shop.test": ["v=DMARC1; p=reject; rua=mailto:d@shop.test"]}
    if token:
        txt["shop.test"].append(ws.VERIFY_TXT + token)
    return pages, txt


def bad_site():
    pages = {
        "http://shop.test/": "<html>plain</html>",
        "https://shop.test/": ws.Resp(
            200, "https://shop.test/", {"content-type": "text/html", "server": "Apache/2.4.41 (Ubuntu)",
                                        "x-powered-by": "PHP/7.4.3"},
            ["session=xyz; Path=/"],
            '<html><title>Shop</title><script src="/static/main.js"></script>'
            '<script src="https://cdn.other.test/lib.js"></script><img src="http://img.test/a.png">'
            '<form action="http://shop.test/login"><input type="password"></form></html>'),
        "https://shop.test/static/main.js": f'var k="{STRIPE}";\n//# sourceMappingURL=main.js.map',
        "https://shop.test/.env": ws.Resp(200, "https://shop.test/.env", {"content-type": "text/plain"}, [],
                                          "DB_PASSWORD=hunter2\nSTRIPE_SECRET=sk_live_x\n"),
        "https://shop.test/.git/HEAD": ws.Resp(200, "https://shop.test/.git/HEAD", {"content-type": "text/plain"},
                                               [], "ref: refs/heads/main\n"),
    }
    return pages, {"_dmarc.shop.test": ["v=DMARC1; p=none"]}


@pytest.fixture
def sites(tmp_path):
    records = []
    s = ws.Websites(tmp_path / "company" / "websites.json", FakeNet(), clock=lambda: NOW,
                    record=lambda t, d: records.append((t, d)))
    s.records = records
    return s


def prove(sites, pages, txt):
    token = sites.add("https://Shop.test/home", "team")["proof"]["file_text"]
    txt = {**txt, "shop.test": list(txt.get("shop.test", [])) + [ws.VERIFY_TXT + token]}
    sites.net = FakeNet(pages, txt)
    assert sites.verify("shop.test", "team")["found"] == "dns"
    return token


def test_domains_are_cleaned_and_numbers_refused():
    assert ws.clean_domain("https://WWW.Example.com/shop?x=1") == "www.example.com"
    for bad in ("10.0.0.1", "localhost", "not a site", "", "http://[::1]/"):
        with pytest.raises(ws.WebsiteError):
            ws.clean_domain(bad)
    assert not ws.public_address("10.0.0.5") and not ws.public_address("169.254.169.254")
    assert not ws.public_address("::ffff:127.0.0.1") and ws.public_address("93.184.216.34")
    assert ws.same_site("cdn.shop.test", "www.shop.test") and not ws.same_site("shop.test.evil", "shop.test")


def test_only_listed_and_proven_websites_are_checked(sites):
    with pytest.raises(ws.WebsiteError, match="only checks websites the company owns"):
        sites.check("someone-else.test", "erick")
    added = sites.add("shop.test", "team")
    assert not added["verified"] and added["proof"]["dns_value"].startswith(ws.VERIFY_TXT)
    with pytest.raises(ws.WebsiteError, match="not proven"):
        sites.check("shop.test", "erick")
    # Only the proof file was asked for: nothing else on the site was touched.
    assert sites.net.log == [f"https://shop.test{ws.VERIFY_FILE}"]


def test_proof_by_file_works_and_must_stay_published(sites):
    token = sites.add("shop.test", "team")["proof"]["file_text"]
    pages, txt = good_site()
    pages[f"https://shop.test{ws.VERIFY_FILE}"] = token + "\n"
    sites.net = FakeNet(pages, txt)
    assert sites.verify("shop.test", "team")["found"] == "file"
    assert sites.check("shop.test", "erick")["grade"] == "A"
    del sites.net.pages[f"https://shop.test{ws.VERIFY_FILE}"]
    with pytest.raises(ws.WebsiteError, match="taken down"):
        sites.check("shop.test", "erick")
    assert not sites.overview()["sites"][0]["verified"]


def test_private_addresses_are_refused(sites):
    sites.add("shop.test", "team")
    sites.net = FakeNet(addresses={"shop.test": ["10.1.2.3"]})
    with pytest.raises(ws.WebsiteError, match="public internet address"):
        sites.verify("shop.test", "team")
    assert sites.net.log == []


def test_a_well_set_up_site_gets_an_a_and_honest_not_checked(sites):
    prove(sites, *good_site())
    r = sites.check("shop.test", "erick")
    assert r["grade"] == "A" and r["score"] == 100 and not r["findings"], r["findings"]
    assert "Email signatures (DKIM)" in r["not_checked"]
    assert "nothing to fix" in r["headline"] and "does not mean" in r["note"]
    assert r["requests"] <= ws.MAX_REQUESTS
    assert all(u.startswith(("https://shop.test", "http://shop.test", "tls:shop.test")) for u in sites.net.log)


def test_a_leaky_site_is_graded_down_with_plain_findings(sites):
    prove(sites, *bad_site())
    r = sites.check("shop.test", "erick")
    keys = {f["key"] for f in r["findings"]}
    assert {"env_file", "git_folder", "secrets", "http_redirect", "hsts", "csp", "framing", "nosniff",
            "version_banner", "cookies", "mixed", "forms", "sri", "spf", "dmarc", "dmarc_reports",
            "source_map", "security_txt"} <= keys
    assert r["grade"] == "F" and r["findings"][0]["severity"] == "urgent"
    assert r["fix_first"] == r["findings"][0]["id"] and "serious" in r["headline"]
    saved = json.dumps(r)
    assert "hunter2" not in saved and STRIPE not in saved and "sk_live_4eC39H" not in saved
    assert "DB_PASSWORD" in saved  # names of settings are shown, values never
    form = next(f for f in r["findings"] if f["key"] == "forms")
    assert form["severity"] == "high" and "password" in form["title"]
    secret = next(f for f in r["findings"] if f["key"] == "secrets")
    assert "Stripe" in secret["saw"] and secret["fix_prompt"].startswith("My website shop.test")
    # The other company's script was never downloaded.
    assert not any("cdn.other.test" in u or "img.test" in u for u in sites.net.log)
    assert r["requests"] <= ws.MAX_REQUESTS
    assert sites.records[-1][0] == "website_check" and sites.records[-1][1]["grade"] == "F"


def test_checking_again_shows_what_was_fixed(sites):
    token = prove(sites, *bad_site())
    sites.check("shop.test", "erick")
    pages, txt = good_site(token)
    sites.net = FakeNet(pages, txt)
    r = sites.check("shop.test", "erick")
    assert r["grade"] == "A" and "The site's secret settings file can be downloaded" in r["fixed_since"]
    assert [g["grade"] for g in sites.overview()["sites"][0]["grades"]] == ["F", "A"]


def test_it_stops_when_the_site_says_slow_down(sites):
    pages, txt = good_site()
    pages["https://shop.test/"] = ws.Resp(429, "https://shop.test/", {})
    prove(sites, pages, txt)
    r = sites.check("shop.test", "erick")
    assert r["partial"] and "slow down" in r["stopped"] and r["grade"] == "?" and "Not graded" in r["headline"]
    assert "The website opens over https" in r["not_checked"]
    assert len([u for u in sites.net.log if not u.startswith("tls:")]) == 2  # http, then https: then it stopped


def test_redirects_off_the_domain_are_not_followed(sites):
    pages, txt = good_site()
    pages["https://shop.test/"] = ws.Resp(302, "https://shop.test/", {"location": "https://elsewhere.test/"})
    prove(sites, pages, txt)
    r = sites.check("shop.test", "erick")
    assert not any("elsewhere" in u for u in sites.net.log)
    assert any("elsewhere.test" in c["note"] for c in r["checks"] if c["key"] == "https")


def test_expiring_certificate_and_old_tls(sites):
    pages, txt = good_site()
    prove(sites, pages, txt)
    sites.net.tls_info = {"version": "TLSv1.1", "not_after": "Jan 18 00:00:00 2027 GMT"}  # NOW is Jan 15 2027
    r = sites.check("shop.test", "erick")
    keys = {f["key"]: f for f in r["findings"]}
    assert keys["cert_expiry"]["severity"] == "high" and keys["tls_version"]["severity"] == "medium"
    assert r["grade"] == "C"


def test_subdomains_of_a_proven_domain_count_as_proven(sites):
    pages, txt = good_site()
    prove(sites, pages, txt)
    assert sites.add("blog.shop.test", "team")["verified"]
    assert sites.checkable() == ["blog.shop.test", "shop.test"]


# ------------------------------------------------------------------ through the panel, Sentry and the CLI

def test_api_chat_and_cli(client):
    sites = client.app.state.websites
    r = client.post("/ui/websites", json={"domain": "shop.test", "operator": "team"})
    assert r.status_code == 200 and not r.json()["verified"]
    token = r.json()["proof"]["file_text"]
    pages, txt = bad_site()
    txt["shop.test"] = [ws.VERIFY_TXT + token]
    sites.net = FakeNet(pages, txt)
    assert client.post("/ui/websites/shop.test/verify", json={}).json()["found"] == "dns"
    assert client.get("/ui/websites/shop.test").status_code == 404  # not checked yet
    assert client.post("/ui/websites/nope.test/check", json={}).status_code == 400

    chat = client.app.state.chat
    refused = chat._dispatch("check_website", {"domain": "competitor.test"}, [], [], {"blocks": [], "followups": []})
    assert refused.startswith("Not checked") and "owns" in refused
    out = json.loads(chat._dispatch("check_website", {"domain": ""}, looked := [], [], {"blocks": [], "followups": []}))
    assert out["grade"] == "F" and out["findings"][0]["evidence_untrusted"]
    assert "fix_first_note_for_their_web_person" in out and looked == ["website check of shop.test"]
    saved = json.loads(chat._dispatch("get_website_check", {}, [], [], {"blocks": [], "followups": []}))
    assert saved["latest_untrusted_site_data"][0]["grade"] == "F"

    reply = client.post("/chat", json={"operator": "erick", "message": "is my website safe?"}).json()
    assert reply["source"] == "fallback" and "Fix first" in reply["text"] and "shop.test" in reply["text"]
    assert reply["blocks"][0]["columns"] == ["How serious", "What we saw", "What to do"]

    out = io.StringIO()
    assert cli.main(["websites", "list"], call=through(client), out=out) == 0
    assert "shop.test" in out.getvalue() and " F " in out.getvalue()
    out = io.StringIO()
    assert cli.main(["websites", "show", "shop.test"], call=through(client), out=out) == 0
    assert "grade F" in out.getvalue()
    assert cli.main(["websites", "remove", "shop.test"], call=through(client), out=io.StringIO()) == 0
    assert client.get("/ui/websites").json()["sites"] == []
    kinds = [r["type"] for r in client.get("/audit?limit=50").json().get("records", [])] if \
        client.get("/audit?limit=50").status_code == 200 else []
    assert not kinds or "website_check" in kinds
