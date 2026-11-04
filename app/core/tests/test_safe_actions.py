"""Protective actions stay within business limits, undo cleanly (and say so), and are checked afterwards."""

import pytest
from fastapi.testclient import TestClient

from app.agents import Needle, Proposal
from app.config import Settings
from app.firewall import FirewallResponder
from app.main import create_app
from app.responders import WebhookResponder

from .conftest import AUTH, brute_force, ev
from .test_firewall import FakeRunner, block

IP = "203.0.113.45"


@pytest.fixture
def make_client(tmp_path):
    def make(**kw):
        s = Settings(db_path=tmp_path / "sentrai.db", background=False, demo_speed=60.0, **kw)
        app = create_app(s)
        c = TestClient(app, headers=AUTH)
        c.core = app.state.core  # type: ignore[attr-defined]
        return c
    return make


def web(n, status, ip=IP, path="/"):
    e = ev(n, f"GET {path} {status}", ip=ip, user=None, source="nginx_access")
    e["parsed"] = {"format": "nginx_access", "kind": "http_request", "method": "GET", "path": path, "status": status}
    return e


def approve(c, iid="RSK-2026-081"):
    return c.post(f"/incidents/{iid}/decision", json={"operator": "erick", "decision": "approve"}).json()


def records(c, kind):
    return [x["data"] for x in c.get("/audit").json()["records"] if x["type"] == kind]


# ------------------------------------------------------------------ business limits

def test_ttl_per_type_is_capped_by_the_business_maximum():
    s = Settings(ttl_hours=2.0, action_ttl_hours={"lock_user": 1.0, "block_ip": 48.0}, max_ttl_hours=12.0)
    assert s.ttl_for("lock_user") == 1.0
    assert s.ttl_for("block_ip") == 12.0  # asked for 48, the limit is 12
    assert s.ttl_for("rate_limit") == 2.0


def test_env_limits_are_read(monkeypatch):
    monkeypatch.setenv("AUTO_ACTIONS", "block_ip, waf_rule")
    monkeypatch.setenv("ACTION_TTL_HOURS", "lock_user=0.5,bad,block_ip=x")
    monkeypatch.setenv("MAX_AUTO_ACTIONS_PER_HOUR", "3")
    s = Settings()
    assert s.auto_actions == {"block_ip", "waf_rule"}
    assert s.action_ttl_hours == {"lock_user": 0.5}
    assert s.max_auto_actions_per_hour == 3


def _incident():
    return {"id": "RSK-1", "ai_confidence": 1.0, "needs_review": False, "severity": "high", "points": 45.0,
            "classified_by": "rules"}


def test_major_actions_wait_for_a_person():
    needle = Needle(0.6, {"block_ip", "kill_process"}, set(), auto_actions={"block_ip"})
    props = [Proposal("block_ip", IP, "t"), Proposal("kill_process", "pid 4242", "t")]
    review = needle.review(_incident(), props, 90, 80)
    assert [p.type for p in review.approved_proposals] == ["block_ip"]
    assert {"type": "kill_process", "target": "pid 4242", "why": "major action: a person must approve it"} in review.denied
    ok, _ = needle.screen(props)  # an operator approving both is fine
    assert len(ok) == 2


def test_hourly_cap_on_automatic_actions():
    needle = Needle(0.6, {"block_ip"}, set(), max_auto_per_hour=2)
    props = [Proposal("block_ip", IP, "t"), Proposal("block_ip", "198.51.100.7", "t")]
    assert len(needle.review(_incident(), props, 90, 80, auto_last_hour=1).approved_proposals) == 1
    full = needle.review(_incident(), props, 90, 80, auto_last_hour=2)
    assert not full.approved and "business limit of 2" in full.reasoning


def test_cap_reached_hands_the_incident_to_a_person(make_client):
    with make_client(max_auto_actions_per_hour=0) as c:
        brute_force(c)
        c.post("/events", json=ev(10, "GET /search?q=' OR 1=1 -- 200", source="flask_access"))
        assert c.get("/blocklist").json()["ips"] == []
        assert any(n["kind"] == "needs_operator" for n in c.get("/notifications/pending").json())
        approve(c)  # a person can still act
        assert IP in c.get("/blocklist").json()["ips"]


def test_limits_endpoint(make_client):
    with make_client(auto_actions={"block_ip"}) as c:
        lim = c.get("/limits").json()
        assert lim["auto_actions"] == ["block_ip"] and "kill_process" in lim["needs_a_person"]
        assert lim["permanent_needs_a_person"] and lim["ttl_hours"]["block_ip"] == 2.0


# ------------------------------------------------------------------ reversal recorded

def test_rollback_records_a_successful_undo(make_client):
    with make_client() as c:
        brute_force(c)
        approve(c)
        inc = c.post("/incidents/RSK-2026-081/rollback", json={"operator": "erick", "justification": "test"}).json()
        assert all(a["undo"]["ok"] is True and a["undo"]["attempts"] == 1 for a in inc["actions"])
        assert {r["action_id"] for r in records(c, "action_undone")} == {a["action_id"] for a in inc["actions"]}


def test_firewall_undo_that_fails_is_reported_and_retried(make_client):
    runner = FakeRunner(fail_on="-D")
    with make_client(firewall="iptables", firewall_enforce=True, undo_retry_s=0.0) as c:
        c.core.blocklist_responder.runner = runner
        brute_force(c)
        approve(c)
        inc = c.post("/incidents/RSK-2026-081/rollback", json={"operator": "erick", "justification": "test"}).json()
        blk = next(a for a in inc["actions"] if a["type"] == "block_ip")
        assert blk["undo"]["ok"] is False and blk["firewall_revert"]["ok"] is False
        assert any(n["kind"] == "undo_failed" for n in c.get("/notifications/pending").json())
        assert records(c, "action_undo_failed")
        runner.fail_on = None  # the firewall works again: the next tick's retry takes the rule out
        c.core.advance(0.01)
        blk = next(a for a in c.get("/incidents/RSK-2026-081").json()["actions"] if a["type"] == "block_ip")
        assert blk["undo"]["ok"] is True and blk["undo"]["attempts"] >= 2
        assert runner.rules == set()


def test_failed_undo_gives_up_after_the_retries(make_client):
    runner = FakeRunner(fail_on="-D")
    with make_client(firewall="iptables", firewall_enforce=True, undo_retry_s=0.0, undo_retries=2) as c:
        c.core.blocklist_responder.runner = runner
        brute_force(c)
        approve(c)
        c.post("/incidents/RSK-2026-081/rollback", json={"operator": "erick", "justification": "test"})
        for _ in range(5):
            c.core.advance(0.01)
        blk = next(a for a in c.get("/incidents/RSK-2026-081").json()["actions"] if a["type"] == "block_ip")
        assert blk["undo"]["attempts"] == 3 and blk["undo"]["ok"] is False
        assert sum(n["kind"] == "undo_failed" for n in c.get("/notifications/pending").json()) == 2  # first + last


def test_firewall_revert_returns_whether_the_rule_is_gone():
    runner = FakeRunner()
    r = FirewallResponder("iptables", enforce=True, runner=runner)
    a = block()
    r.apply(a)
    assert r.revert(a) is True and a["firewall_revert"]["ok"]
    runner2 = FakeRunner(fail_on="-D")
    r2 = FirewallResponder("iptables", enforce=True, runner=runner2)
    b = block()
    r2.apply(b)
    assert r2.revert(b) is False and r2.status()["blocked"] == [IP]  # still tracked for a retry


def test_webhook_revert_reports_the_receiver_answer():
    hook = WebhookResponder("https://soar.example/hook", ("waf_rule",), poster=lambda url, body, h: 500)
    a = {"action_id": "act-1", "type": "waf_rule", "target": "/login"}
    assert hook.revert(a) is False and a["webhook_revert"]["error"] == "HTTP 500"
    hook.poster = lambda url, body, h: 204
    assert hook.revert(a) is True


# ------------------------------------------------------------------ after-action check

def test_check_finds_a_block_that_does_not_stop_the_attacker(make_client):
    with make_client() as c:  # blocklist only: nothing in front of the web server enforces it
        brute_force(c)
        approve(c)
        c.core.advance(0.02)
        for i in range(3):
            c.post("/events", json=web(100 + i, 200))
        c.core.advance(0.2)  # past CHECK_AFTER_MIN (10 timer minutes)
        blk = next(a for a in c.get("/incidents/RSK-2026-081").json()["actions"] if a["type"] == "block_ip")
        assert blk["check"]["worked"] is False and blk["check"]["got_through"] == 3
        assert any(n["kind"] == "action_check" for n in c.get("/notifications/pending").json())
        assert records(c, "action_checked")


def test_check_confirms_a_block_that_holds_and_hurts_no_one(make_client):
    with make_client() as c:
        for i in range(12):
            c.post("/events", json=web(200 + i, 200, ip="198.51.100.20"))  # normal visitors before
        brute_force(c)
        approve(c)
        c.core.advance(0.02)
        c.post("/events", json=web(300, 403))  # the attacker is refused
        for i in range(12):
            c.post("/events", json=web(400 + i, 200, ip="198.51.100.20"))  # visitors carry on
        c.core.advance(0.2)
        inc = c.get("/incidents/RSK-2026-081").json()
        blk = next(a for a in inc["actions"] if a["type"] == "block_ip")
        assert blk["check"]["worked"] is True and blk["check"]["disruption"] is False
        rate = next(a for a in inc["actions"] if a["type"] == "rate_limit")
        assert rate["check"]["worked"] is None  # SentrAI cannot see a rate limit itself
        assert not any(n["kind"] == "action_check" for n in c.get("/notifications/pending").json())


def test_check_flags_collateral_damage(make_client):
    with make_client(health_url="https://shop.example/") as c:
        probes = iter([{"ok": True, "status": 200}, {"ok": False, "status": 503}])
        c.core.health_probe = lambda url: next(probes)
        for i in range(12):
            c.post("/events", json=web(200 + i, 200, ip="198.51.100.20"))
        brute_force(c)
        approve(c)
        c.core.advance(0.02)
        for i in range(6):
            c.post("/events", json=web(400 + i, 502, ip="198.51.100.20"))
        c.core.advance(0.2)
        blk = next(a for a in c.get("/incidents/RSK-2026-081").json()["actions"] if a["type"] == "block_ip")
        chk = blk["check"]
        assert chk["disruption"] is True
        assert "health page stopped answering" in chk["disruption_note"] and "server errors rose" in chk["disruption_note"]
        assert blk["health_before"]["ok"] is True
