import sqlite3

import pytest

from app.risk import band, risk_index

from .conftest import brute_force, ev


@pytest.mark.parametrize("raw,expected", [(0, 0), (35, 44), (70, 69), (97, 80), (140, 90)])
def test_risk_formula(raw, expected):
    assert risk_index(raw) == expected


def test_bands():
    assert [band(x) for x in (0, 29, 30, 59, 60, 79, 80, 100)] == [
        "green", "green", "amber", "amber", "red", "red", "critical", "critical"]


def test_health(client):
    assert client.get("/health").json() == {"ok": True}


def test_brute_force_creates_incident(client):
    results = brute_force(client, count=4)
    assert client.get("/incidents").json() == []  # below threshold: held, no incident
    assert results[-1]["accepted"] == 1
    r = client.post("/events", json=ev(4, "POST /login 401 user=admin")).json()
    incs = client.get("/incidents").json()
    assert len(incs) == 1
    inc = incs[0]
    assert inc["id"] == "RSK-2026-081"
    assert inc["category"] == "brute_force" and inc["severity"] == "high"
    assert inc["classified_by"] == "rules" and inc["ai_confidence"] == 1.0
    assert inc["points"] == 45.0  # 30 x 1.0 x 1.5
    assert len(inc["event_ids"]) == 5
    assert inc["status"] == "open" and inc["acked"] is False
    assert "203.0.113.45" in inc["recommended_action"]
    assert r["risk_index"] == risk_index(45)  # 53, amber
    risk = client.get("/risk").json()
    assert risk["band"] == "amber" and risk["open_incidents"] == ["RSK-2026-081"]
    pending = client.get("/notifications/pending").json()
    assert any(n["kind"] == "incident_opened" and n["incident"] == "RSK-2026-081" for n in pending)
    # A list payload is accepted too, and further failures aggregate into the same incident.
    out = client.post("/events", json=[ev(5, "POST /login 401 user=admin"), ev(6, "POST /login 401 user=admin")]).json()
    assert out["accepted"] == 2
    assert len(client.get("/incidents").json()) == 1
    assert len(client.get("/incidents/RSK-2026-081").json()["event_ids"]) == 7


def test_inaction_penalty_and_sla(client):
    brute_force(client)
    client.core.advance(3)
    inc = client.get("/incidents/RSK-2026-081").json()
    assert inc["inaction_penalty"] == 15
    assert inc["sla_breached"] is True
    kinds = [n["kind"] for n in client.get("/notifications/pending").json()]
    assert "sla_reminder" in kinds
    assert client.get("/risk").json()["raw_score"] == 60.0
    client.core.advance(20)
    assert client.get("/incidents/RSK-2026-081").json()["inaction_penalty"] == 30  # capped


def test_threshold_triggers_autonomous_block(client):
    brute_force(client)
    assert client.get("/blocklist").json() == {"ips": [], "users": []}
    r = client.post("/events", json=ev(10, "GET /search?q=' OR 1=1 -- 200", source="flask_access")).json()
    # 45 + 60 = 105 raw -> 83 >= 80: both incidents contained autonomously.
    incs = {i["id"]: i for i in client.get("/incidents").json()}
    assert incs["RSK-2026-082"]["category"] == "sql_injection"
    assert all(i["status"] == "contained" for i in incs.values())
    bl = client.get("/blocklist").json()
    # admin is an admin account: never auto-locked, so only the IP block and rate limit apply.
    assert "203.0.113.45" in bl["ips"] and bl["users"] == []
    acts = incs["RSK-2026-081"]["actions"]
    assert {a["type"] for a in acts} == {"block_ip", "rate_limit"}
    assert all(a["mode"] == "autonomous" and a["approved_by"] == "Countersign" and a["status"] == "active" for a in acts)
    assert all(len(a["snapshot_hash"]) == 64 and a["verified"] for a in acts)
    assert r["risk_index"] < 80  # contained incidents no longer count
    audit = client.get("/audit").json()
    types = [x["type"] for x in audit["records"]]
    for t in ("threshold_crossed", "snapshot", "needle_review", "action_applied", "verify"):
        assert t in types
    assert any(x["type"] == "needle_review" and x["data"]["agent"] == "Countersign" and x["data"]["approved"]
               for x in audit["records"])
    assert any({"type": "lock_user", "target": "admin", "why": "protected account"} in x["data"].get("denied", [])
               for x in audit["records"] if x["type"] == "needle_review")
    pending = client.get("/notifications/pending").json()
    auto = [n for n in pending if n["kind"] == "autonomous_action"]
    assert auto and "CXO" in auto[0]["recipients"]
    assert any(n["kind"] == "escalation" and "CXO" in n["recipients"] for n in pending)
    # TTL: 2 demo hours later the temporary block drops out of /blocklist.
    client.core.advance(2.1)
    assert client.get("/blocklist").json() == {"ips": [], "users": []}
    assert client.get("/incidents/RSK-2026-081").json()["actions"][0]["status"] == "expired"


def test_acked_incident_is_not_auto_contained(client):
    brute_force(client)
    client.post("/incidents/RSK-2026-081/ack", json={"operator": "erick", "channel": "telegram"})
    client.post("/events", json=ev(10, "GET /search?q=1 UNION SELECT password FROM members 200"))
    incs = {i["id"]: i for i in client.get("/incidents").json()}
    assert incs["RSK-2026-081"]["status"] == "acknowledged" and incs["RSK-2026-081"]["actions"] == []
    assert incs["RSK-2026-082"]["status"] == "contained"


def test_operator_verbs(client):
    brute_force(client)
    bad = client.post("/incidents/RSK-2026-081/decision", json={"operator": "erick", "decision": "reject"})
    assert bad.status_code == 400
    inc = client.post("/incidents/RSK-2026-081/decision", json={"operator": "erick", "decision": "approve"}).json()
    assert inc["status"] == "contained" and inc["acked_by"] == "erick"
    assert all(a["mode"] == "operator" and a["approved_by"] == "erick" for a in inc["actions"])
    assert "203.0.113.45" in client.get("/blocklist").json()["ips"]
    inc = client.post("/incidents/RSK-2026-081/rollback", json={"operator": "erick", "justification": "test"}).json()
    assert all(a["status"] == "rolled_back" for a in inc["actions"])
    assert client.get("/blocklist").json()["ips"] == []
    assert client.post("/incidents/RSK-2026-081/rollback", json={"operator": "erick"}).status_code == 409
    # new incident -> approve -> permanent survives TTL
    client.post("/events", json=ev(20, "GET /search?q=<script>alert(1)</script> 200", ip="198.51.100.7", user=None))
    iid = [i["id"] for i in client.get("/incidents").json() if i["category"] == "xss"][0]
    client.post(f"/incidents/{iid}/decision", json={"operator": "erick", "decision": "approve"})
    inc = client.post(f"/incidents/{iid}/permanent", json={"operator": "erick", "justification": "known bad"}).json()
    assert inc["status"] == "resolved" and all(a["status"] == "permanent" for a in inc["actions"])
    client.core.advance(5)
    assert "198.51.100.7" in client.get("/blocklist").json()["ips"]
    # reject closes with justification
    client.post("/events", json=ev(30, "shell spawned by www-data: /bin/sh", ip="192.0.2.9", layer="os", source="os_process"))
    iid = [i["id"] for i in client.get("/incidents").json() if i["category"] == "privilege_escalation"][0]
    inc = client.post(f"/incidents/{iid}/decision",
                      json={"operator": "erick", "decision": "reject", "justification": "pentest window"}).json()
    assert inc["status"] == "rejected"
    assert client.get("/incidents/NOPE").status_code == 404


def test_uncertain_classification_needs_review_never_auto_contained(client):
    # Fallback heuristic: 'dump' -> data_exfiltration with malicious p=0.55 (0.4-0.6 band)
    client.post("/events", json=ev(1, "db session requested full dump of table members", layer="db", crit=2.0,
                                   ip="10.0.0.8", user="svc"))
    inc = client.get("/incidents").json()[0]
    assert inc["classified_by"] == "fallback" and inc["needs_review"] is True
    assert 0.5 <= inc["ai_confidence"] <= 0.8
    # push risk over threshold with a confident incident from another source
    client.post("/events", json=ev(2, "shell spawned by www-data", ip="192.0.2.50", layer="os", source="os_process"))
    incs = {i["id"]: i for i in client.get("/incidents").json()}
    assert incs[inc["id"]]["status"] == "open" and incs[inc["id"]]["actions"] == []
    assert "10.0.0.8" not in client.get("/blocklist").json()["ips"]
    kinds = [n["kind"] for n in client.get("/notifications/pending").json()]
    assert "needs_review" in kinds


def test_audit_chain_valid_and_detects_tampering(client):
    brute_force(client)
    client.post("/events", json=ev(10, "GET /search?q=' OR 1=1 -- 200"))
    audit = client.get("/audit").json()
    assert audit["chain_valid"] is True and audit["count"] > 5
    recs = audit["records"]
    assert recs[0]["prev_hash"] == "0" * 64
    assert all(recs[i]["prev_hash"] == recs[i - 1]["hash"] for i in range(1, len(recs)))
    # The DB refuses edits through normal SQL (append-only triggers)...
    db = client.core.audit.path
    con = sqlite3.connect(db)
    with pytest.raises(sqlite3.DatabaseError):
        con.execute("UPDATE audit SET data = '{}' WHERE seq = 3")
    # ...and if an attacker drops the trigger and edits a row, verification catches it.
    con.execute("DROP TRIGGER audit_no_update")
    con.execute("UPDATE audit SET data = replace(data, 'Countersign', 'Nobody') WHERE type = 'needle_review'")
    con.commit()
    con.close()
    audit = client.get("/audit").json()
    assert audit["chain_valid"] is False and audit["first_invalid_seq"] is not None


def test_evidence_report(client):
    brute_force(client)
    client.core.advance(3)
    pending = client.get("/notifications/pending").json()
    first = [n for n in pending if n["incident"] == "RSK-2026-081"][0]
    d = client.post(f"/notifications/{first['id']}/delivered", json={"channel": "telegram", "message_id": 4242}).json()
    assert d["delivered"] is True
    assert first["id"] not in [n["id"] for n in client.get("/notifications/pending").json()]
    client.post("/events", json=ev(10, "GET /search?q=' OR 1=1 -- 200"))  # crosses 80 -> forced action
    rep = client.get("/reports/RSK-2026-081").json()
    assert rep["responsible_entity"] == "On-duty responder"
    assert rep["sla"]["breached"] is True and "Policy SLA: 2 hrs" in rep["sla"]["summary"]
    assert rep["forced_action"]["taken"] is True
    assert rep["non_repudiation"]["ack"] == "Ack: none"
    assert any(x["line"].startswith("Delivered") and "Ack: none" in x["line"] and "4242" in x["line"]
               for x in rep["non_repudiation"]["deliveries"])
    kinds = [t["kind"] for t in rep["timeline_of_inaction"]]
    assert kinds[0] == "detected" and kinds.count("inaction_penalty") == 3 and "action" in kinds
    assert rep["audit_proof"]["chain_valid"] is True and rep["audit_proof"]["records"]
    md = client.get("/reports/RSK-2026-081.md")
    assert md.status_code == 200
    assert "Responsible Entity" in md.text and "Ack: none" in md.text and "Incident timeline" in md.text
    assert rep["title"] == "Security Evidence Report" and rep["report_id"] == "ER-RSK-2026-081"
    assert any(a["by"] == "Countersign" and a["decision"] == "approved" for a in rep["approvals"])
    pdf = client.get("/reports/RSK-2026-081.pdf")
    assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF-1.4") and pdf.content.rstrip().endswith(b"%%EOF")
    assert "RSK-2026-081-evidence-report.pdf" in pdf.headers["content-disposition"]
    assert client.get("/reports/RSK-2026-999").status_code == 404
    assert client.get("/reports/RSK-2026-999.pdf").status_code == 404


def test_helpdesk_and_agents(client):
    brute_force(client)
    client.post("/events", json=ev(10, "GET /search?q=' OR 1=1 -- 200"))
    why = client.get("/incidents/RSK-2026-081/why").json()["answer"]
    assert "Countersign" in why and "failed logins" in why
    assert "RSK-2026-081" in client.get("/helpdesk/why", params={"target": "203.0.113.45"}).json()["incidents"]
    names = {a["name"] for a in client.get("/agents").json()}
    assert {"Cyanide", "Gatehouse", "Vault", "Garrison-Linux", "Garrison-Win", "Watchtower", "Countersign", "Watchdog",
            "Scribe", "HelpDesk"} <= names
    assert "Jev" not in names  # the AI classifier is an extension (mvp/extensions/typesafe), not added here


def test_watchdog_flags_silent_collector(client):
    client.post("/heartbeat", json={"collector": "web-01"})
    client.core.clock._offset += 31  # 31 real seconds of silence
    client.core.tick()
    kinds = [n["kind"] for n in client.get("/notifications/pending").json()]
    assert "watchdog" in kinds
    assert any(r["type"] == "collector_silent" for r in client.get("/audit").json()["records"])


def test_reset(client):
    brute_force(client)
    client.post("/events", json=ev(10, "GET /search?q=' OR 1=1 -- 200"))
    out = client.core.reset()
    assert out["ok"] is True
    assert client.get("/incidents").json() == []
    assert client.get("/blocklist").json() == {"ips": [], "users": []}
    assert client.get("/risk").json()["risk_index"] == 0
    audit = client.get("/audit").json()
    assert audit["chain_valid"] and audit["count"] == 1
    brute_force(client, start=100)
    assert client.get("/incidents").json()[0]["id"] == "RSK-2026-081"


def test_loopback_is_never_auto_blocked(client):
    # Presenter's own machine (no X-Demo-Src-IP header) must not lock itself out.
    brute_force(client, ip="127.0.0.1")
    client.post("/events", json=ev(20, "GET /search?q=' OR 1=1 -- 200", ip="127.0.0.1", source="flask_access"))
    bl = client.get("/blocklist").json()
    assert "127.0.0.1" not in bl["ips"]


def test_protected_user_not_locked(tmp_path):
    from fastapi.testclient import TestClient
    from app.config import Settings
    from app.main import create_app
    s = Settings(db_path=tmp_path / "p.db", background=False, protected_users={"admin"})
    with TestClient(create_app(s), headers={"Authorization": "Bearer test-token"}) as c:
        brute_force(c)
        c.post("/events", json=ev(20, "GET /search?q=' OR 1=1 -- 200", source="flask_access"))
        bl = c.get("/blocklist").json()
        assert "203.0.113.45" in bl["ips"] and "admin" not in bl["users"]


def test_routine_db_query_and_ordinary_words_are_benign(client):
    client.post("/events", json=[
        ev(30, "SELECT rows=2 q='alice'", layer="db", source="db_query"),
        ev(31, "GET /search?q=oracle scandal acl 200 extra", source="flask_access"),
        ev(32, "login fail user=admin", source="flask_auth"),
    ])
    assert client.get("/incidents").json() == []


def test_notification_report_url_is_absolute(client):
    brute_force(client)
    n = next(n for n in client.get("/notifications/pending").json() if n["incident"])
    assert n["report_url"].startswith("http://") and ".md?sig=" in n["report_url"]
