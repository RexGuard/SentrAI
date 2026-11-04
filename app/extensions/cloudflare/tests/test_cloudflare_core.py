"""Cloudflare extension: blocking at Cloudflare's edge, and adding or removing it while blocks are in force."""

import json

import pytest

import sentrai_extensions as se
from app.responders import BlocklistResponder
from conftest import ATTACKER, brute_force

cf = se.load_part(se.installed()["cloudflare"], "core")
CloudflareAPI, CloudflareResponder = cf.CloudflareAPI, cf.CloudflareResponder
KEYS = {"CLOUDFLARE_API_TOKEN": "cf-token", "CLOUDFLARE_ZONE_ID": "z1"}


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
        path = url.removeprefix(cf.API)
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


@pytest.fixture
def edge(monkeypatch):
    """The fake Cloudflare every Cloudflare extension started in this test talks to."""
    fake = FakeCloudflare()
    monkeypatch.setattr(cf, "_httpx_requester", lambda timeout_s: fake)
    return fake


def responder(fake, method="access_rule", **kw):
    api = CloudflareAPI("cf-token", zone_id="" if method == "list" else "z1", account_id="a1", list_id="l1",
                        requester=fake)
    return CloudflareResponder(api, method, protected_ips={"8.8.8.8"}, inner=BlocklistResponder(), **kw)


def act(ip=ATTACKER, n=1):
    return {"action_id": f"act-{n}", "incident": f"RSK-{n}", "type": "block_ip", "target": ip}


def contain(c, ip=ATTACKER, start=0):
    brute_force(c, ip=ip, start=start)
    iid = next(i["id"] for i in c.get("/incidents").json() if i["src_ip"] == ip)
    c.post(f"/incidents/{iid}/decision", json={"operator": "erick", "decision": "approve"})
    inc = c.get(f"/incidents/{iid}").json()
    assert inc["status"] == "contained"
    return inc


def rows(c):
    return {r["name"]: r for r in c.get("/extensions").json()}


# ------------------------------------------------------------------ the responder on its own

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


def test_remove_all_takes_out_every_entry_it_made():
    fake = FakeCloudflare()
    r = responder(fake)
    r.apply(act(n=1)), r.apply(act("45.33.32.157", n=2))
    fake.rules["mine"] = {"id": "mine", "mode": "block", "notes": "blocked by hand",
                          "configuration": {"target": "ip", "value": "45.33.32.158"}}
    assert r.remove_all() == (2, []) and list(fake.rules) == ["mine"]
    assert r.blocklist()["ips"] == [ATTACKER, "45.33.32.157"]  # local blocks are not touched


# ------------------------------------------------------------------ inside the core

def test_core_blocks_at_cloudflare_and_undoes_on_rollback(make_core, edge):
    c = make_core(**KEYS)
    core = c.core
    ext = core.extensions.running["cloudflare"].ext
    assert core.responders.for_type("block_ip") is ext.responder
    inc = contain(c)
    assert len(edge.rules) == 1 and ATTACKER in c.get("/blocklist").json()["ips"]
    out = c.post(f"/incidents/{inc['id']}/rollback", json={"operator": "erick", "justification": "test"})
    assert out.status_code == 200 and edge.rules == {}
    r = rows(c)
    assert r["cloudflare"]["added"] is True and r["cloudflare"]["added_by"] == "settings"
    assert r["cloudflare"]["configured"] is True and r["slack"]["configured"] is False
    assert "zone z1" in r["cloudflare"]["detail"] and "cf-token" not in json.dumps(r)
    assert c.post("/extensions/cloudflare/test").json()["ok"] is True
    assert c.post("/integrations/cloudflare/test").json()["ok"] is True  # the old name still answers
    assert {x["name"] for x in c.get("/integrations").json()} == set(r)


def test_half_filled_cloudflare_settings_do_not_stop_the_core(make_core, edge):
    c = make_core(CLOUDFLARE_API_TOKEN="cf-token")  # no zone or account
    row = rows(c)["cloudflare"]
    assert row["added"] is True and row["running"] is False and row["configured"] is False
    assert "CLOUDFLARE_ZONE_ID" in row["error"]
    assert c.post("/extensions/cloudflare/test").json()["ok"] is False
    assert c.core.responders.for_type("block_ip") is c.core.blocklist_responder
    contain(c)  # the local block still works
    assert edge.calls == []


def test_adding_cloudflare_puts_the_blocks_in_force_at_the_edge(make_core, edge, tmp_path):
    (tmp_path / "extensions.json").write_text(json.dumps(
        {"extensions": {"cloudflare": {"added": False, "by": "erick", "at": "2026-10-27T09:00:00+08:00"}}}))
    c = make_core(**KEYS)  # the key is saved, but someone removed it on the Extensions page
    row = rows(c)["cloudflare"]
    assert row["added"] is False and row["added_by"] == "dashboard" and row["changed_by"] == "erick"
    contain(c)
    assert edge.rules == {}  # blocked locally only
    added = c.post("/extensions/cloudflare/add", json={"operator": "lee"})
    assert added.status_code == 200 and added.json()["added"] is True and added.json()["running"] is True
    assert [r["configuration"]["value"] for r in edge.rules.values()] == [ATTACKER]
    assert c.core.responders.for_type("block_ip").name == "cloudflare"
    rec = [r for r in c.get("/audit").json()["records"] if r["type"] == "extension_added"]
    assert rec and rec[-1]["data"]["operator"] == "lee" and rec[-1]["data"]["started"] is True


def test_removing_cloudflare_takes_its_entries_out_and_keeps_the_local_block(make_core, edge):
    c = make_core(**KEYS)
    inc = contain(c)
    assert len(edge.rules) == 1
    out = c.post("/extensions/cloudflare/remove", json={"operator": "erick"})
    assert out.status_code == 200
    body = out.json()
    assert body["added"] is False and body["running"] is False and body["added_by"] == "dashboard"
    assert body["cleanup"]["released"] == 1 and body["cleanup"]["left_in_place"] == []
    assert edge.rules == {} and ATTACKER in c.get("/blocklist").json()["ips"]
    assert c.core.responders.for_type("block_ip") is c.core.blocklist_responder
    assert rows(c)["cloudflare"]["detail"].startswith("Not added")
    calls = len(edge.calls)
    c.post(f"/incidents/{inc['id']}/rollback", json={"operator": "erick", "justification": "test"})
    assert c.get("/blocklist").json()["ips"] == [] and len(edge.calls) == calls  # Cloudflare is left alone now
    rec = [r for r in c.get("/audit").json()["records"] if r["type"] == "extension_removed"][-1]["data"]
    assert rec["extension"] == "cloudflare" and rec["released"] == 1
    c2 = make_core(**KEYS)  # a restart keeps the choice, although the key is still saved
    assert rows(c2)["cloudflare"]["added"] is False and "cloudflare" not in c2.core.extensions.running


def test_a_removal_cloudflare_refuses_is_reported_for_a_person(make_core, edge):
    c = make_core(**KEYS)
    inc = contain(c)
    edge.fail_delete = True
    cleanup = c.post("/extensions/cloudflare/remove", json={"operator": "erick"}).json()["cleanup"]
    assert cleanup["released"] == 0 and cleanup["left_in_place"][0]["target"] == ATTACKER
    assert cleanup["cloudflare_left"][0]["ip"] == ATTACKER and len(edge.rules) == 1
    timeline = c.get(f"/incidents/{inc['id']}").json()["timeline"]
    assert any(t["kind"] == "undo_failed" and "Remove it there by hand" in t["text"] for t in timeline)


def test_sentrai_extensions_on_the_server_wins(make_core, edge):
    c = make_core(SENTRAI_EXTENSIONS="none", **KEYS)
    row = rows(c)["cloudflare"]
    assert row["added"] is False and row["added_by"] == "SENTRAI_EXTENSIONS"
    refused = c.post("/extensions/cloudflare/add", json={"operator": "erick"})
    assert refused.status_code == 409 and "SENTRAI_EXTENSIONS" in refused.json()["detail"]
    contain(c)
    assert edge.calls == []
