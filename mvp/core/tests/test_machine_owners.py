"""Who answers for a machine: a person from Routing or the AI agent. The Machines list's bell pings them."""

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.saguaro import AGENT_OWNER

from .conftest import AUTH, ev


@pytest.fixture
def panel(tmp_path):
    settings = Settings(db_path=tmp_path / "sentrai.db", background=False, demo_speed=60.0, risk_scope="host")
    app = create_app(settings)
    with TestClient(app, headers=AUTH) as c:
        c.core = app.state.core  # type: ignore[attr-defined]
        yield c


def brute(c, host, start=0, ip="203.0.113.45"):
    for i in range(5):
        c.post("/events", json=ev(start + i, "POST /login 401 user=admin", ip=ip, host=host))


def row(c, host):
    return next(m for m in c.get("/ui/machines").json()["machines"] if m["host"] == host)


def test_person_owner_gets_new_and_open_alerts(panel):
    brute(panel, "web-01")
    first = panel.get("/incidents").json()[0]
    assert first["owner"] != "Team lead"
    out = panel.post("/ui/machines/web-01/owner", json={"kind": "person", "contact": "team_lead"}).json()
    assert out["moved"] == 1 and "is now responsible for web-01" in out["message"]
    assert panel.get(f"/incidents/{first['id']}").json()["owner"] == panel.core.router.contacts["team_lead"].name
    assert row(panel, "web-01")["owner"] == {"kind": "person", "name": panel.core.router.contacts["team_lead"].name,
                                             "contact": "team_lead", "backup": "", "backup_name": ""}
    brute(panel, "web-01", 100, ip="198.51.100.9")
    new = [i for i in panel.get("/incidents").json() if i["id"] != first["id"]]
    assert new and all(i["owner"] == panel.core.router.contacts["team_lead"].name for i in new)
    assert all(i["route"] == "Machine owner" for i in new)


def test_unknown_person_is_refused(panel):
    r = panel.post("/ui/machines/web-01/owner", json={"kind": "person", "contact": "nobody-here"})
    assert r.status_code == 400 and "Routing" in r.json()["detail"]


def test_ping_a_person_queues_a_message(panel):
    brute(panel, "web-01")
    assert panel.post("/ui/machines/web-01/ping", json={}).status_code == 409  # nobody set yet
    panel.post("/ui/machines/web-01/owner", json={"kind": "person", "contact": "it_manager"})
    out = panel.post("/ui/machines/web-01/ping", json={}).json()
    assert out["kind"] == "person" and out["open"] == 1
    n = next(n for n in panel.core.notifications if n["kind"] == "machine_ping")
    assert n["recipients"] == [panel.core.router.contacts["it_manager"].name] and "web-01" in n["title"]


def test_agent_owner_handles_alerts_and_hands_decisions_to_backup(panel):
    panel.post("/ui/machines/db-01/owner", json={"kind": "agent", "backup": "team_lead"})
    brute(panel, "db-01")
    inc = panel.get("/incidents").json()[0]
    assert inc["owner"] == AGENT_OWNER and inc["backup"] == panel.core.router.contacts["team_lead"].name
    # Nothing is sent to the AI agent itself (it would reach the fallback address, the business owner).
    assert not any(AGENT_OWNER in n["recipients"] for n in panel.core.notifications)
    out = panel.post("/ui/machines/db-01/ping", json={}).json()
    assert out["kind"] == "agent" and AGENT_OWNER in out["message"]
    # A critical one needs a person: the agent hands it to its backup.
    with panel.core.lock:
        i = panel.core.incidents[inc["id"]]
        i["severity"] = "critical"
    panel.post("/ui/machines/db-01/ping", json={})
    got = panel.get(f"/incidents/{inc['id']}").json()
    assert got["owner"] == panel.core.router.contacts["team_lead"].name
    assert not got["acked"]  # never acknowledged for them: automatic containment still applies


def test_agent_acknowledges_contained_ones(panel):
    panel.post("/ui/machines/web-01/owner", json={"kind": "agent"})
    brute(panel, "web-01")
    panel.post("/events", json=ev(5, "GET /search?q=' OR 1=1 -- 200", ip="203.0.113.45", host="web-01",
                                  source="flask_access"))
    contained = [i for i in panel.get("/incidents").json() if i["status"] in ("contained", "acknowledged")]
    assert contained
    panel.post("/ui/machines/web-01/ping", json={})
    for i in contained:
        got = panel.get(f"/incidents/{i['id']}").json()
        if i["status"] == "contained" and got["owner"] == AGENT_OWNER:
            assert got["acked"] and got["acked_by"] == AGENT_OWNER


def test_clear_owner_goes_back_to_rules_and_delete_still_hides(panel):
    brute(panel, "web-01")
    panel.post("/ui/machines/web-01/owner", json={"kind": "agent"})
    out = panel.post("/ui/machines/web-01/owner", json={"kind": ""}).json()
    assert out["owner"] is None and out["moved"] == 1
    assert panel.get("/incidents").json()[0]["owner"] != AGENT_OWNER
    panel.post("/ui/machines/web-01/owner", json={"kind": "person", "contact": "on_duty"})
    panel.post("/ui/machines/web-01/delete", json={})
    assert all(m["host"] != "web-01" for m in panel.get("/ui/machines").json()["machines"])
    assert panel.post("/ui/machines/web-01/ping", json={}).status_code == 409
    brute(panel, "web-01", 200, ip="198.51.100.20")  # logs naming it keep arriving: still hidden
    assert all(m["host"] != "web-01" for m in panel.get("/ui/machines").json()["machines"])
    panel.post("/ui/machines/web-01/restore", json={})
    assert row(panel, "web-01")["owner"]["contact"] == "on_duty"  # its owner comes back with it


def test_owner_survives_a_restart(tmp_path):
    settings = Settings(db_path=tmp_path / "sentrai.db", background=False, demo_speed=60.0, risk_scope="host")
    with TestClient(create_app(settings), headers=AUTH) as c:
        c.post("/ui/machines/web-01/owner", json={"kind": "person", "contact": "cxo"})
    with TestClient(create_app(settings), headers=AUTH) as c:
        brute(c, "web-01")
        assert row(c, "web-01")["owner"]["contact"] == "cxo"
        assert c.get("/incidents").json()[0]["route"] == "Machine owner"
