"""Per-machine risk (SENTRAI_RISK_SCOPE=host): one central core scoring many machines, each on its own."""

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

from .conftest import AUTH, ev

SQLI = "GET /search?q=' OR 1=1 -- 200"


@pytest.fixture
def panel(tmp_path):
    settings = Settings(db_path=tmp_path / "sentrai.db", background=False, demo_speed=60.0, risk_scope="host")
    app = create_app(settings)
    with TestClient(app, headers=AUTH) as c:
        c.core = app.state.core  # type: ignore[attr-defined]
        yield c


def attack(c, host, ip, start):
    """Brute force (45 points) then SQL injection (60): 105 raw, over the threshold on one machine."""
    for i in range(5):
        c.post("/events", json=ev(start + i, "POST /login 401 user=admin", ip=ip, host=host))
    c.post("/events", json=ev(start + 5, SQLI, ip=ip, host=host, source="flask_access"))


def test_scope_setting(monkeypatch):
    monkeypatch.setenv("SENTRAI_RISK_SCOPE", "host")
    assert Settings().risk_scope == "host"
    monkeypatch.setenv("SENTRAI_RISK_SCOPE", "anything else")
    assert Settings().risk_scope == "fleet"


def test_two_half_attacks_on_two_machines_never_add_up(panel):
    # 45 points on each machine: 90 raw would cross 80 in fleet scope, but each machine alone is amber.
    for i in range(5):
        panel.post("/events", json=ev(i, "POST /login 401 user=admin", ip="203.0.113.45", host="web-01"))
    for i in range(5):
        panel.post("/events", json=ev(10 + i, "POST /login 401 user=admin", ip="198.51.100.7", host="office-pc"))
    r = panel.get("/risk").json()
    assert r["risk_scope"] == "host" and r["band"] == "amber"  # the worst machine, not the sum
    assert all(i["status"] == "open" for i in panel.get("/incidents").json())
    assert panel.get("/blocklist").json() == {"ips": [], "users": []}


def test_attack_blocks_only_on_the_attacked_machine(panel):
    panel.post("/events", json={**ev(90, "heartbeat", host="office-pc", source="heartbeat", layer="os")})
    attack(panel, "web-01", "203.0.113.45", 0)
    web = panel.get("/risk", params={"host": "web-01"}).json()
    office = panel.get("/risk", params={"host": "office-pc"}).json()
    assert web["host"] == "web-01" and web["contained_incidents"] and web["open_incidents"] == []
    assert office["risk_index"] == 0 and office["contained_incidents"] == []
    assert "203.0.113.45" in panel.get("/blocklist", params={"host": "web-01"}).json()["ips"]
    assert panel.get("/blocklist", params={"host": "office-pc"}).json()["ips"] == []
    acts = [a for i in panel.get("/incidents").json() for a in i["actions"]]
    assert acts and all(a["host"] == "web-01" for a in acts)


def test_same_attacker_on_two_machines_is_two_incidents(panel):
    for host, start in (("web-01", 0), ("office-pc", 20)):
        for i in range(5):
            panel.post("/events", json=ev(start + i, "POST /login 401 user=admin", ip="203.0.113.45", host=host))
    incs = panel.get("/incidents").json()
    assert sorted(i["host"] for i in incs if i["category"] == "brute_force") == ["office-pc", "web-01"]
    assert [i["host"] for i in panel.get("/incidents", params={"host": "office-pc"}).json()] == ["office-pc"]


def test_machines_list(panel):
    panel.post("/events", json={**ev(90, "heartbeat", host="office-pc", source="heartbeat", layer="os")})
    attack(panel, "web-01", "203.0.113.45", 0)
    for i in range(5):
        panel.post("/events", json=ev(30 + i, "POST /login 401 user=admin", ip="198.51.100.7", host="db-01"))
    ms = panel.get("/machines").json()
    by = {m["host"]: m for m in ms}
    assert set(by) == {"web-01", "office-pc", "db-01"}
    assert ms[0]["host"] == "db-01" and by["db-01"]["open_incidents"] == 1  # worst first: still open
    assert by["web-01"]["contained_incidents"] == 2 and by["web-01"]["blocked"] == 1
    assert by["office-pc"]["risk_index"] == 0 and by["office-pc"]["last_seen"] and not by["office-pc"]["silent"]
    hist = panel.get("/risk", params={"host": "db-01"}).json()["history"]
    assert hist and hist[-1]["band"] == "amber"


def test_fleet_scope_unchanged(client):
    # The default keeps one score for everything, as on a single server; ?host= still reads one machine.
    for i in range(5):
        client.post("/events", json=ev(i, "POST /login 401 user=admin", ip="203.0.113.45", host="web-01"))
    client.post("/events", json=ev(9, SQLI, ip="198.51.100.7", host="office-pc", source="flask_access"))
    assert client.get("/risk").json()["risk_scope"] == "fleet"
    assert all(i["status"] == "contained" for i in client.get("/incidents").json())  # 45 + 60 added up
    assert client.get("/blocklist", params={"host": "office-pc"}).json() == client.get("/blocklist").json()
    assert client.get("/risk", params={"host": "web-01"}).json()["contained_incidents"] == ["RSK-2026-081"]


def test_old_actions_without_a_host_use_their_incident(panel):
    attack(panel, "web-01", "203.0.113.45", 0)
    for a in panel.core.actions:
        a.pop("host", None)
    assert "203.0.113.45" in panel.get("/blocklist", params={"host": "web-01"}).json()["ips"]
