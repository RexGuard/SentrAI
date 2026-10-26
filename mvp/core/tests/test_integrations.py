"""Outside services: Cloudflare blocking, AbuseIPDB lookups, the Integrations endpoints."""

from fastapi.testclient import TestClient

from app import cloudflare, integrations, reputation
from app.cloudflare import CloudflareAPI, CloudflareResponder
from app.config import Settings
from app.main import create_app
from app.responders import BlocklistResponder

from .conftest import AUTH, brute_force

ATTACKER = "45.33.32.156"  # a public address (203.0.113.x is a documentation range, never sent out)


class FakeCloudflare:
    """Just enough of the Cloudflare API: IP Access rules on a zone, and one account IP list."""

    def __init__(self) -> None:
        self.rules: dict[str, dict] = {}
        self.items: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.down = False
        self.fail_delete = False
        self.n = 0

    def __call__(self, method, url, headers, params, body):
        assert headers["Authorization"] == "Bearer cf-token"
        path = url.removeprefix(cloudflare.API)
        self.calls.append((method, path))
        if self.down:
            raise OSError("connection refused")
        ok = lambda result: (200, {"success": True, "errors": [], "result": result})  # noqa: E731
        if "/firewall/access_rules/rules" in path:
            rid = path.rsplit("/rules", 1)[1].strip("/")
            if method == "GET":
                value = (params or {}).get("configuration.value")
                return ok([r for r in self.rules.values() if value in (None, r["configuration"]["value"])])
            if method == "POST":
                if any(r["configuration"]["value"] == body["configuration"]["value"] for r in self.rules.values()):
                    return 400, {"success": False, "errors": [{"code": 10009, "message": "duplicate"}]}
                self.n += 1
                rule = {"id": f"r{self.n}", **body}
                self.rules[rule["id"]] = rule
                return ok({"id": rule["id"]})
            if method == "DELETE":
                if self.fail_delete:
                    return 500, {"success": False, "errors": [{"code": 1000, "message": "internal error"}]}
                if rid not in self.rules:
                    return 404, {"success": False, "errors": [{"code": 10001, "message": "not found"}]}
                del self.rules[rid]
                return ok({"id": rid})
        if "/bulk_operations/" in path:
            return ok({"status": "completed"})
        if path.endswith("/items"):
            if method == "GET":
                return ok([i for i in self.items.values() if i["ip"].startswith(params.get("search", ""))])
            if method == "POST":
                for item in body:
                    self.n += 1
                    self.items[f"i{self.n}"] = {"id": f"i{self.n}", **item}
                return ok({"operation_id": "op1"})
            if method == "DELETE":
                for item in body["items"]:
                    self.items.pop(item["id"], None)
                return ok({"operation_id": "op2"})
        if "/rules/lists/" in path and method == "GET":
            return ok({"name": "sentrai_blocklist", "num_items": len(self.items)})
        return 404, {"success": False, "errors": [{"code": 7003, "message": "no route"}]}


def responder(fake, method="access_rule", **kw):
    api = CloudflareAPI("cf-token", zone_id="" if method == "list" else "z1", account_id="a1", list_id="l1",
                        requester=fake)
    return CloudflareResponder(api, method, protected_ips={"8.8.8.8"}, inner=BlocklistResponder(), **kw)


def act(ip=ATTACKER, n=1):
    return {"action_id": f"act-{n}", "incident": f"RSK-{n}", "type": "block_ip", "target": ip}


def test_block_and_undo_at_cloudflare():
    fake = FakeCloudflare()
    r = responder(fake)
    a = act()
    assert r.apply(a) is True
    rule = next(iter(fake.rules.values()))
    assert rule["mode"] == "block" and rule["configuration"] == {"target": "ip", "value": ATTACKER}
    assert rule["notes"].startswith("SentrAI RSK-1") and a["cloudflare"]["ok"] is True
    assert r.blocklist()["ips"] == [ATTACKER]  # the local block is in force too
    assert r.revert(a) is True and fake.rules == {} and a["cloudflare_revert"]["ok"] is True
    assert r.blocklist()["ips"] == []


def test_two_incidents_share_one_rule():
    fake = FakeCloudflare()
    r = responder(fake)
    a, b = act(n=1), act(n=2)
    r.apply(a), r.apply(b)
    assert len(fake.rules) == 1 and b["cloudflare"]["already_blocked"] is True
    r.revert(a)
    assert len(fake.rules) == 1  # the second incident still holds it
    r.revert(b)
    assert fake.rules == {}


def test_never_sends_protected_or_private_addresses():
    fake = FakeCloudflare()
    r = responder(fake)
    for ip in ("8.8.8.8", "10.0.0.5", "127.0.0.1", "203.0.113.45", "not-an-ip"):
        a = act(ip)
        r.apply(a)
        assert "skipped" in a["cloudflare"], ip
    assert fake.calls == []


def test_cloudflare_down_keeps_the_local_block():
    fake = FakeCloudflare()
    fake.down = True
    r = responder(fake)
    a = act()
    assert r.apply(a) is True  # still blocked locally
    assert a["cloudflare"]["ok"] is False and "connection refused" in a["cloudflare"]["error"]
    assert r.blocklist()["ips"] == [ATTACKER] and r.last_error
    assert r.revert(a) is True  # nothing was added at Cloudflare, so nothing to remove


def test_failed_removal_is_reported_and_retried():
    fake = FakeCloudflare()
    r = responder(fake)
    a = act()
    r.apply(a)
    fake.fail_delete = True
    assert r.revert(a) is False and a["cloudflare_revert"]["ok"] is False
    assert len(fake.rules) == 1
    fake.fail_delete = False
    assert r.revert(a) is True and fake.rules == {}  # the core's undo retry (Saguaro._check_actions)


def test_adopts_its_own_rule_after_a_restart_and_leaves_hand_made_ones():
    fake = FakeCloudflare()
    responder(fake).apply(act())  # a previous run made this rule
    r = responder(fake)  # restarted: knows nothing
    a = act()
    r.apply(a)
    assert len(fake.rules) == 1 and a["cloudflare"]["id"] == "r1"
    r.revert(a)
    assert fake.rules == {}
    fake.rules["mine"] = {"id": "mine", "mode": "block", "notes": "blocked by hand",
                          "configuration": {"target": "ip", "value": ATTACKER}}
    b = act()
    r.apply(b)
    r.revert(b)
    assert "mine" in fake.rules  # never removes a rule a person made


def test_ipv6_and_challenge_mode():
    fake = FakeCloudflare()
    r = responder(fake, mode="managed_challenge")
    r.apply(act("2600:1f18::1"))
    rule = next(iter(fake.rules.values()))
    assert rule["mode"] == "managed_challenge" and rule["configuration"]["target"] == "ip6"


def test_list_method():
    fake = FakeCloudflare()
    r = responder(fake, method="list")
    a = act()
    r.apply(a)
    assert [i["ip"] for i in fake.items.values()] == [ATTACKER] and a["cloudflare"]["id"] == "i1"
    assert r.test()["ok"] is True and "sentrai_blocklist" in r.test()["detail"]
    r.revert(a)
    assert fake.items == {}


def test_bad_settings_are_refused():
    for kw in ({"method": "nope"}, {"mode": "nope"}):
        try:
            responder(FakeCloudflare(), **{"method": "access_rule", **kw})
            raise AssertionError(f"accepted {kw}")
        except ValueError:
            pass
    try:
        CloudflareAPI("t")
        raise AssertionError("accepted no zone or account")
    except ValueError:
        pass
    assert "cf-token" not in repr(CloudflareAPI("cf-token", zone_id="z"))


def test_core_blocks_at_cloudflare_and_undoes_on_rollback(tmp_path):
    s = Settings(db_path=tmp_path / "c.db", background=False, cloudflare_api_token="cf-token", cloudflare_zone_id="z1")
    app = create_app(s)
    fake = FakeCloudflare()
    with TestClient(app, headers=AUTH) as c:
        core = app.state.core
        core.cloudflare.api.request = fake
        assert core.responders.for_type("block_ip") is core.cloudflare
        brute_force(c, ip=ATTACKER)
        iid = c.get("/incidents").json()[0]["id"]
        c.post(f"/incidents/{iid}/decision", json={"operator": "erick", "decision": "approve"})
        inc = c.get(f"/incidents/{iid}").json()
        assert inc["status"] == "contained" and len(fake.rules) == 1
        assert ATTACKER in c.get("/blocklist").json()["ips"]
        out = c.post(f"/incidents/{inc['id']}/rollback", json={"operator": "erick", "justification": "test"})
        assert out.status_code == 200 and fake.rules == {}
        rows = {r["name"]: r for r in c.get("/integrations").json()}
        assert rows["cloudflare"]["configured"] is True and rows["slack"]["configured"] is False
        assert "cf-token" not in str(rows)
        assert c.post("/integrations/cloudflare/test").json()["ok"] is True
        assert c.post("/integrations/nope/test").status_code == 404


def test_half_filled_cloudflare_settings_do_not_stop_the_core(tmp_path):
    s = Settings(db_path=tmp_path / "c.db", background=False, cloudflare_api_token="cf-token")  # no zone/account
    app = create_app(s)
    with TestClient(app, headers=AUTH) as c:
        rows = {r["name"]: r for r in c.get("/integrations").json()}
        assert rows["cloudflare"]["configured"] is False and "CLOUDFLARE_ZONE_ID" in rows["cloudflare"]["error"]
        assert c.post("/integrations/cloudflare/test").json()["ok"] is False


# ------------------------------------------------------------------ AbuseIPDB

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


def test_abuseipdb_lookup_is_cached_and_never_sends_private_addresses():
    fake = FakeAbuseIPDB()
    client = reputation.AbuseIPDB("ab-key", getter=fake)
    rep = client.check(ATTACKER)
    assert rep["score"] == 100 and rep["reports"] == 312
    assert client.check(ATTACKER)["cached"] is True and fake.calls == [ATTACKER]
    assert "reported 312 time(s), 100% abuse confidence, Linode, US" in reputation.summary(rep)
    seen = []
    lookups = reputation.Lookups(client, lambda ip, r: seen.append(ip), {"45.33.32.0/24"}, background=False)
    for ip in ("10.0.0.1", "127.0.0.1", "203.0.113.4", ATTACKER, None):
        assert lookups.request(ip) is False
    assert seen == [] and "ab-key" not in repr(client)
    bad = reputation.AbuseIPDB("ab-key", getter=FakeAbuseIPDB(429))
    assert "rate limit" in bad.check("1.1.1.1")["error"] and bad.test()["ok"] is False


def test_core_notes_reputation_on_the_incident(tmp_path):
    s = Settings(db_path=tmp_path / "c.db", background=False, abuseipdb_api_key="ab-key")
    app = create_app(s)
    with TestClient(app, headers=AUTH) as c:
        core = app.state.core
        core.reputation.get = FakeAbuseIPDB()
        brute_force(c, ip=ATTACKER)
        inc = c.get(f"/incidents/{c.get('/incidents').json()[0]['id']}").json()
        assert inc["reputation"]["score"] == 100
        assert any(t["kind"] == "reputation" and "312" in t["text"] for t in inc["timeline"])
        rows = {r["name"]: r for r in c.get("/integrations").json()}
        assert rows["abuseipdb"]["configured"] and "1 lookup" in rows["abuseipdb"]["detail"]


# ------------------------------------------------------------------ Slack test

def test_slack_test_message():
    sent = []
    assert integrations.slack_test("https://hooks.slack.com/services/x",
                                   lambda u, b, h: sent.append(b) or 200)["ok"] is True
    assert b"SentrAI test message" in sent[0]
    assert integrations.slack_test("http://insecure", lambda *a: 200)["ok"] is False
    assert integrations.slack_test("https://hooks.slack.com/x", lambda *a: 404)["ok"] is False
