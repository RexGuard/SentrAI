"""Machines joining a central panel: join codes, agent keys, what a key may do, revoking."""

import os

import pytest
from fastapi.testclient import TestClient

from app import fleet
from app.config import Settings
from app.main import create_app

from .conftest import AUTH, ev


@pytest.fixture
def panel(tmp_path):
    settings = Settings(db_path=tmp_path / "cactai.db", background=False, demo_speed=60.0, risk_scope="host")
    app = create_app(settings)
    with TestClient(app, headers=AUTH) as c:
        c.core = app.state.core  # type: ignore[attr-defined]
        c.fleet = app.state.fleet  # type: ignore[attr-defined]
        c.tmp = tmp_path
        yield c


def join(c, host="office-pc", name=None):
    code = c.post("/fleet/join-codes", json={"operator": "erick", "name": name}).json()["code"]
    r = c.post("/fleet/enrol", json={"code": code, "host": host}, headers={"Authorization": ""})
    assert r.status_code == 200, r.text
    return r.json()


def as_agent(key):
    return {"Authorization": f"Bearer {key}"}


def test_join_code_is_one_time(panel):
    code = panel.post("/fleet/join-codes", json={"operator": "erick"}).json()
    assert len(fleet.normalise_code(code["code"])) == 12 and code["expires_at"]
    first = panel.post("/fleet/enrol", json={"code": code["code"].lower(), "host": "office-pc"}, headers={"Authorization": ""})
    assert first.status_code == 200 and first.json()["key"].startswith("sa_")
    again = panel.post("/fleet/enrol", json={"code": code["code"], "host": "laptop"}, headers={"Authorization": ""})
    assert again.status_code == 403
    types = [r["type"] for r in panel.get("/audit").json()["records"]]
    assert "join_code_created" in types and "machine_joined" in types


def test_join_code_needs_the_owner_token(panel):
    assert panel.post("/fleet/join-codes", json={}, headers={"Authorization": ""}).status_code == 401
    key = join(panel)["key"]
    assert panel.post("/fleet/join-codes", json={}, headers=as_agent(key)).status_code == 403


def test_expired_code_and_name_rules(panel):
    panel.fleet.clock = lambda: 1_000.0
    code = panel.post("/fleet/join-codes", json={}).json()["code"]
    panel.fleet.clock = lambda: 1_000.0 + fleet.CODE_TTL_S + 1
    assert panel.post("/fleet/enrol", json={"code": code, "host": "a"}, headers={"Authorization": ""}).status_code == 403
    assert panel.post("/fleet/join-codes", json={"name": "bad name!"}).status_code == 400
    named = join(panel, host="ignored", name="web-01")
    assert named["host"] == "web-01"


def test_same_name_twice_is_refused(panel):
    join(panel, "office-pc")
    code = panel.post("/fleet/join-codes", json={}).json()["code"]
    assert panel.post("/fleet/enrol", json={"code": code, "host": "office-pc"},
                      headers={"Authorization": ""}).status_code == 409


def test_too_many_wrong_codes_locks_enrolment(panel):
    for _ in range(fleet.MAX_BAD_CODES):
        panel.post("/fleet/enrol", json={"code": "AAAA-BBBB-CCCC", "host": "x"}, headers={"Authorization": ""})
    code = panel.post("/fleet/join-codes", json={}).json()["code"]
    assert panel.post("/fleet/enrol", json={"code": code, "host": "x"}, headers={"Authorization": ""}).status_code == 429


def test_agent_key_only_reaches_its_own_routes(panel):
    key = join(panel)["key"]
    h = as_agent(key)
    assert panel.get("/fleet/me", headers=h).json()["host"] == "office-pc"
    assert panel.get("/incidents", headers=h).status_code == 403
    assert panel.get("/risk", headers=h).status_code == 403
    assert panel.post("/protection", json={"on": False, "operator": "x", "reason": "y"}, headers=h).status_code == 403
    assert panel.get("/blocklist", params={"host": "web-01"}, headers=h).status_code == 403
    assert panel.get("/blocklist", headers=h).status_code == 200
    assert panel.get("/fleet/me", headers=as_agent(key + "x")).status_code == 401


def test_agent_events_are_stamped_with_its_machine(panel):
    key = join(panel)["key"]
    for i in range(5):  # the log line claims another machine: the key decides
        panel.post("/events", json=ev(i, "POST /login 401 user=admin", host="web-01"), headers=as_agent(key))
    panel.post("/heartbeat", json={"collector": "web-01"}, headers=as_agent(key))
    assert {i["host"] for i in panel.get("/incidents").json()} == {"office-pc"}
    assert {m["host"] for m in panel.get("/machines").json()} == {"office-pc"}
    assert panel.fleet.agents()[0]["last_seen"]


def test_agent_reads_only_its_own_blocks(panel):
    office = as_agent(join(panel, "office-pc")["key"])
    web = as_agent(join(panel, "web-01")["key"])
    for i in range(5):
        panel.post("/events", json=ev(i, "POST /login 401 user=admin", ip="203.0.113.45"), headers=web)
    panel.post("/events", json=ev(5, "GET /search?q=' OR 1=1 -- 200", ip="203.0.113.45", source="flask_access"), headers=web)
    assert "203.0.113.45" in panel.get("/blocklist", headers=web).json()["ips"]
    assert panel.get("/blocklist", headers=office).json()["ips"] == []
    # Without a key, one machine's list is not open (the plain list stays open as before).
    assert panel.get("/blocklist", params={"host": "web-01"}, headers={"Authorization": ""}).status_code == 401
    assert panel.get("/blocklist", headers={"Authorization": ""}).status_code == 200


def test_revoke(panel):
    a = join(panel)
    out = panel.post(f"/fleet/agents/{a['agent_id']}/revoke", json={"operator": "erick"}).json()
    assert out["revoked_by"] == "erick" and "key_sha256" not in out
    assert panel.get("/fleet/me", headers=as_agent(a["key"])).status_code == 401
    assert panel.post("/fleet/agents/nope/revoke", json={}).status_code == 404
    join(panel)  # the name is free again once revoked
    listed = panel.get("/fleet/agents").json()
    assert len(listed) == 2 and all("key_sha256" not in x for x in listed)


def test_saved_without_plain_secrets(panel):
    a = join(panel)
    text = (panel.tmp / "fleet.json").read_text()
    assert a["key"] not in text and a["agent_id"] in text
    if os.name == "posix":
        assert (panel.tmp / "fleet.json").stat().st_mode & 0o777 == 0o600
    again = fleet.Fleet(panel.tmp / "fleet.json")
    assert again.check(a["key"])["host"] == "office-pc"
