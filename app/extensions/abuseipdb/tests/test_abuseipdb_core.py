"""AbuseIPDB extension: what the internet already knows about an attacking address, noted on the incident."""

import sentrai_extensions as se
from conftest import ATTACKER, brute_force

ab = se.load_part(se.installed()["abuseipdb"], "core")


class FakeAbuseIPDB:
    def __init__(self, status=200):
        self.status, self.calls = status, []

    def __call__(self, url, headers, params):
        assert headers["Key"] == "ab-key"
        self.calls.append(params["ipAddress"])
        if self.status != 200:
            return self.status, {"errors": [{"detail": "Daily rate limit of 1000 requests exceeded."}]}
        return 200, {"data": {"ipAddress": params["ipAddress"], "abuseConfidenceScore": 100, "totalReports": 312,
                              "countryCode": "US", "isp": "Linode", "isTor": False}}


def test_lookup_is_cached_and_never_sends_private_addresses():
    fake = FakeAbuseIPDB()
    client = ab.AbuseIPDB("ab-key", getter=fake)
    rep = client.check(ATTACKER)
    assert rep["score"] == 100 and rep["reports"] == 312
    assert client.check(ATTACKER)["cached"] is True and fake.calls == [ATTACKER]
    assert "reported 312 time(s), 100% abuse confidence, Linode, US" in ab.summary(rep)
    seen = []
    lookups = ab.Lookups(client, lambda ip, r: seen.append(ip), {"45.33.32.0/24"}, background=False)
    for ip in ("10.0.0.1", "127.0.0.1", "203.0.113.4", ATTACKER, None):
        assert lookups.request(ip) is False
    assert seen == [] and "ab-key" not in repr(client)
    bad = ab.AbuseIPDB("ab-key", getter=FakeAbuseIPDB(429))
    assert "rate limit" in bad.check("1.1.1.1")["error"] and bad.test()["ok"] is False


def test_closed_lookups_drop_what_is_queued():
    seen = []
    lookups = ab.Lookups(ab.AbuseIPDB("ab-key", getter=FakeAbuseIPDB()), lambda ip, r: seen.append(ip),
                         background=False)
    lookups.close()
    assert lookups.request(ATTACKER) is True and seen == []


def test_core_notes_reputation_on_the_incident(make_core):
    c = make_core(ABUSEIPDB_API_KEY="ab-key")
    fake = FakeAbuseIPDB()
    c.core.extensions.running["abuseipdb"].ext.client.get = fake
    brute_force(c)
    inc = c.get(f"/incidents/{c.get('/incidents').json()[0]['id']}").json()
    assert inc["reputation"]["score"] == 100
    assert any(t["kind"] == "reputation" and "312" in t["text"] for t in inc["timeline"])
    row = next(r for r in c.get("/extensions").json() if r["name"] == "abuseipdb")
    assert row["configured"] and "1 lookup since start" in row["detail"] and "ab-key" not in str(row)
    assert any(r["type"] == "reputation_lookup" for r in c.get("/audit").json()["records"])


def test_removed_abuseipdb_looks_nothing_up(make_core):
    c = make_core(ABUSEIPDB_API_KEY="ab-key")
    fake = FakeAbuseIPDB()
    c.core.extensions.running["abuseipdb"].ext.client.get = fake
    assert c.post("/extensions/abuseipdb/remove", json={"operator": "erick"}).status_code == 200
    brute_force(c)
    inc = c.get(f"/incidents/{c.get('/incidents').json()[0]['id']}").json()
    assert "reputation" not in inc and fake.calls == []


def test_added_without_a_key_says_what_is_missing(make_core):
    c = make_core()
    row = c.post("/extensions/abuseipdb/add", json={"operator": "erick"}).json()
    assert row["added"] is True and row["configured"] is False and "API key" in row["detail"]
    assert c.post("/extensions/abuseipdb/test").json() == {"ok": False, "error": row["detail"]}
