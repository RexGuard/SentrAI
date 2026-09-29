"""Monitor-only mode: the operator's "protection off" switch."""
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

from .conftest import AUTH, brute_force, ev

SQLI = "GET /search?q=' OR 1=1 -- 200"


def turn_off(client, reason="testing on the live server"):
    return client.post("/protection", json={"operator": "erick", "on": False, "reason": reason})


def test_protection_is_on_by_default(client):
    p = client.get("/protection").json()
    assert p["protection"] == "on" and p["monitor_only"] is False
    assert client.get("/risk").json()["monitor_only"] is False


def test_turning_off_needs_a_reason(client):
    assert turn_off(client, reason=" ").status_code == 400
    assert client.get("/protection").json()["monitor_only"] is False


def test_monitor_only_scores_but_never_contains(client):
    p = turn_off(client).json()
    assert p["protection"] == "off" and p["changed_by"] == "erick" and p["reason"] == "testing on the live server"
    brute_force(client)
    client.post("/events", json=ev(10, SQLI, source="flask_access"))
    risk = client.get("/risk").json()
    assert risk["risk_index"] >= 80 and risk["monitor_only"] is True  # still scored
    incs = client.get("/incidents").json()
    assert len(incs) == 2 and all(i["status"] == "open" and i["actions"] == [] for i in incs)
    assert client.get("/blocklist").json() == {"ips": [], "users": []}
    # Each skipped containment is recorded once, even as ticks keep running.
    client.post("/demo/advance", json={"demo_hours": 0.5})
    types = [r["type"] for r in client.get("/audit").json()["records"]]
    assert types.count("protection_changed") == 1
    assert types.count("containment_skipped") == 2
    assert "action_applied" not in types
    assert any(t["kind"] == "monitor_only" for t in incs[0]["timeline"])
    kinds = [n["kind"] for n in client.get("/notifications/pending").json()]
    assert "protection_off" in kinds and "autonomous_action" not in kinds


def test_monitor_only_refuses_approved_hotpatch(client):
    brute_force(client)
    turn_off(client)
    r = client.post("/incidents/RSK-2026-081/decision", json={"operator": "erick", "decision": "approve"})
    assert r.status_code == 409 and "monitor-only" in r.json()["detail"]
    inc = client.get("/incidents/RSK-2026-081").json()
    assert inc["actions"] == [] and inc["acked"] is False  # nothing changed
    # Reject, ack and rollback still work: they apply nothing.
    ok = client.post("/incidents/RSK-2026-081/decision",
                     json={"operator": "erick", "decision": "reject", "justification": "known tester"})
    assert ok.status_code == 200 and ok.json()["status"] == "rejected"


def test_turning_protection_back_on_contains_again(client):
    turn_off(client)
    brute_force(client)
    client.post("/events", json=ev(10, SQLI, source="flask_access"))
    assert client.get("/blocklist").json()["ips"] == []
    p = client.post("/protection", json={"operator": "erick", "on": True}).json()
    assert p["protection"] == "on"
    assert "203.0.113.45" in client.get("/blocklist").json()["ips"]
    records = client.get("/audit").json()["records"]
    changes = [r["data"] for r in records if r["type"] == "protection_changed"]
    assert [c["protection"] for c in changes] == ["off", "on"]
    assert client.get("/audit").json()["chain_valid"]


def test_actions_in_force_stay_and_can_be_rolled_back(client):
    brute_force(client)
    client.post("/incidents/RSK-2026-081/decision", json={"operator": "erick", "decision": "approve"})
    p = turn_off(client).json()
    assert p["active_actions"]  # left in force, and the operator is told
    assert "203.0.113.45" in client.get("/blocklist").json()["ips"]
    r = client.post("/incidents/RSK-2026-081/rollback", json={"operator": "erick", "justification": "undo"})
    assert r.status_code == 200
    assert client.get("/blocklist").json()["ips"] == []


def test_expired_hotpatch_cannot_be_made_permanent_while_off(client):
    brute_force(client)
    client.post("/incidents/RSK-2026-081/decision", json={"operator": "erick", "decision": "approve"})
    client.post("/demo/advance", json={"demo_hours": 2.1})
    turn_off(client)
    r = client.post("/incidents/RSK-2026-081/permanent", json={"operator": "erick", "justification": "keep"})
    assert r.status_code == 409
    assert client.get("/blocklist").json()["ips"] == []


def test_switch_survives_reset_and_restart(tmp_path):
    s = Settings(db_path=tmp_path / "p.db", background=False)
    with TestClient(create_app(s), headers=AUTH) as c:
        turn_off(c)
        c.post("/demo/reset")
        assert c.get("/protection").json()["monitor_only"] is True
    with TestClient(create_app(Settings(db_path=tmp_path / "p.db", background=False)), headers=AUTH) as c:
        p = c.get("/protection").json()
        assert p["monitor_only"] is True and p["changed_by"] == "erick"
    # An explicit CACTAI_MONITOR_ONLY wins at start.
    with TestClient(create_app(Settings(db_path=tmp_path / "p.db", background=False, monitor_only="0")), headers=AUTH) as c:
        assert c.get("/protection").json()["monitor_only"] is False
