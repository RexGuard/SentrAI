"""Routing (who hears about an incident), owners, follow-up and escalation to the backup contact."""

import json

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

from .conftest import AUTH, brute_force, ev

ROUTING = {
    "contacts": {
        "amir": {"name": "Amir", "role": "on_duty", "email": "amir@example.test", "telegram": "@amir", "backup": "lee"},
        "lee": {"name": "Lee", "role": "team_lead", "email": "lee@example.test", "backup": "it"},
        "it": {"name": "Ika", "role": "it_manager", "backup": "boss"},
        "boss": {"name": "Boss", "role": "cxo", "email": "boss@example.test"},
        "dba": {"name": "Dana", "email": "dana@example.test", "backup": "lee"},
    },
    "rules": [
        {"name": "Database box", "match": {"host": "db-*"}, "owner": "dba", "notify": ["it"]},
        {"name": "Critical", "match": {"severity": "critical"}, "owner": "amir", "notify": ["lee", "it", "boss"]},
        {"name": "High", "match": {"severity": ["high"]}, "owner": "amir", "notify": ["lee"]},
    ],
    "follow_up": {"escalate_after_reminders": 2, "max_escalations": 2, "resolve_within_hours": 4},
}


def routed_client(tmp_path, routing=ROUTING):
    (tmp_path / "routing.json").write_text(json.dumps(routing), encoding="utf-8")
    settings = Settings(db_path=tmp_path / "cactai.db", background=False, demo_speed=60.0)
    app = create_app(settings)
    c = TestClient(app, headers=AUTH)
    c.__enter__()
    c.core = app.state.core  # type: ignore[attr-defined]
    return c


def pending(client, kind=None, iid="RSK-2026-081"):
    return [n for n in client.get("/notifications/pending").json()
            if n["incident"] == iid and (kind is None or n["kind"] == kind)]


def test_default_owner_is_on_duty_with_the_team_lead_as_backup(client):
    brute_force(client)
    inc = client.get("/incidents/RSK-2026-081").json()
    assert inc["owner"] == client.core.settings.on_duty and inc["backup"] == "Team lead"
    assert inc["route"] == "High" and inc["notify"] == ["Team lead"]
    first = pending(client, "incident_opened")[0]
    assert first["recipients"] == [inc["owner"], "Team lead"] and "Owner:" in first["text"]
    assert client.get("/routing").json()["source"] == "defaults"


def test_rules_route_by_severity_and_host(tmp_path):
    c = routed_client(tmp_path)
    brute_force(c)  # high, web-01
    inc = c.get("/incidents/RSK-2026-081").json()
    assert (inc["owner"], inc["backup"], inc["notify"]) == ("Amir", "Lee", ["Lee"])
    n = pending(c, "incident_opened")[0]
    assert [d["email"] for d in n["deliver_to"]] == ["amir@example.test", "lee@example.test"]
    assert n["deliver_to"][0]["telegram"] == "@amir"
    # Same attack against the database server: the DBA owns it and the IT manager is told.
    brute_force(c, ip="198.51.100.9", start=20)
    for i in range(5):
        c.post("/events", json=ev(40 + i, "POST /login 401 user=admin", ip="198.51.100.77", host="db-01"))
    db = next(i for i in c.get("/incidents").json() if i["host"] == "db-01")
    assert (db["owner"], db["route"], db["notify"]) == ("Dana", "Database box", ["Ika"])
    # Role names in the routing file replace the settings' names for the risk-band alerts too.
    assert c.core.settings.team_lead == "Lee" and c.core.settings.cxo == "Boss"


def test_unanswered_reminders_escalate_to_the_backup(tmp_path):
    c = routed_client(tmp_path)
    brute_force(c)
    c.core.advance(2.5)  # SLA 2 h: reminder 1 to Amir only
    c.core.advance(1)  # reminder 2
    reminders = pending(c, "sla_reminder")
    assert len(reminders) == 2 and all(n["recipients"] == ["Amir"] for n in reminders)
    c.core.advance(1)  # third: two unanswered, so Lee (the backup) takes over
    inc = c.get("/incidents/RSK-2026-081").json()
    assert (inc["owner"], inc["backup"], inc["escalation_level"]) == ("Lee", "Ika", 1)
    esc = pending(c, "escalated")
    assert len(esc) == 1 and esc[0]["recipients"] == ["Lee", "Amir"]
    assert inc["escalations"][0]["from"] == "Amir" and inc["escalations"][0]["to"] == "Lee"
    c.core.advance(2)  # two reminders to Lee
    assert pending(c, "sla_reminder")[-1]["recipients"] == ["Lee"]
    c.core.advance(1)
    assert c.get("/incidents/RSK-2026-081").json()["owner"] == "Ika"  # second escalation
    c.core.advance(10)  # max_escalations reached: Ika keeps it, reminders stop at the cap
    inc = c.get("/incidents/RSK-2026-081").json()
    assert inc["owner"] == "Ika" and inc["escalation_level"] == 2
    types = [r["type"] for r in c.get("/audit").json()["records"]]
    assert types.count("incident_escalated") == 2


def test_acknowledging_stops_escalation_and_unresolved_gets_a_nudge(tmp_path):
    c = routed_client(tmp_path)
    brute_force(c)
    c.core.advance(2.5)
    c.post("/incidents/RSK-2026-081/ack", json={"operator": "Amir"})
    c.core.advance(3)
    assert pending(c, "escalated") == [] and c.get("/incidents/RSK-2026-081").json()["owner"] == "Amir"
    c.core.advance(1.5)  # 4.5 h after the ack, resolve_within_hours 4
    nudges = pending(c, "resolve_reminder")
    assert len(nudges) == 1 and nudges[0]["recipients"] == ["Amir"]


def test_assign_take_and_resolve(client):
    brute_force(client)
    iid = "RSK-2026-081"
    r = client.post(f"/incidents/{iid}/assign", json={"operator": "erick", "assignee": "it manager", "note": "your box"})
    inc = r.json()
    assert inc["owner"] == "IT manager" and inc["backup"] == "CXO" and inc["assigned_by"] == "erick"
    told = pending(client, "assigned")
    assert told and told[0]["recipients"] == ["IT manager"]
    # Someone outside the contact book takes it (Telegram "Take it"): no message to themselves,
    # and the contact who had it becomes their backup.
    inc = client.post(f"/incidents/{iid}/assign", json={"operator": "rexguard", "assignee": "rexguard"}).json()
    assert inc["owner"] == "rexguard" and inc["backup"] == "IT manager"
    assert len(pending(client, "assigned")) == 1
    assert client.post(f"/incidents/{iid}/resolve", json={"operator": "rexguard", "note": " "}).status_code == 400
    inc = client.post(f"/incidents/{iid}/resolve", json={"operator": "rexguard", "note": "Reset the password"}).json()
    assert inc["status"] == "resolved" and inc["resolution"] == "Reset the password" and inc["acked"]
    assert client.get("/risk").json()["open_incidents"] == []
    assert client.post(f"/incidents/{iid}/resolve", json={"operator": "x", "note": "again"}).status_code == 409
    assert client.post(f"/incidents/{iid}/assign", json={"operator": "x", "assignee": "y"}).status_code == 409
    types = [x["type"] for x in client.get(f"/audit?incident={iid}").json()["records"]]
    assert types.count("incident_assigned") == 2 and "incident_resolved" in types


def test_owner_survives_a_restart(tmp_path):
    c = routed_client(tmp_path)
    brute_force(c)
    c.post("/incidents/RSK-2026-081/assign", json={"operator": "erick", "assignee": "Dana"})
    c.__exit__(None, None, None)
    c2 = routed_client(tmp_path)
    inc = c2.get("/incidents/RSK-2026-081").json()
    assert inc["owner"] == "Dana" and inc["backup"] == "Lee"


def test_a_broken_routing_file_falls_back_to_the_settings(tmp_path):
    (tmp_path / "routing.json").write_text("{not json", encoding="utf-8")
    settings = Settings(db_path=tmp_path / "cactai.db", background=False, demo_speed=60.0)
    with TestClient(create_app(settings), headers=AUTH) as c:
        brute_force(c)
        assert c.get("/incidents/RSK-2026-081").json()["owner"] == settings.on_duty


def test_the_sample_routing_file_loads():
    from pathlib import Path

    from app import routing
    path = Path(__file__).resolve().parents[1] / "profiles" / "routing.example.json"
    r = routing.load(path, "a", "b", "c", "d")
    assert r.source == str(path) and r.by_role("team_lead", "?") == "Lee (team lead)"
    assert r.route({"host": "db-01", "severity": "high"}).owner.name == "Dana (database)"
    assert r.route({"host": "web-01", "severity": "medium"}).rule == "Everything else"
