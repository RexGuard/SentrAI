"""Threat scans and backups the panel asks a joined machine to run (jobs.py)."""

import pytest
from fastapi.testclient import TestClient

from app import jobs
from app.config import Settings
from app.main import create_app

from .conftest import AUTH
from .test_fleet import as_agent, join


@pytest.fixture
def panel(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRAI_THREAT_STATE", str(tmp_path / "state" / "seen.json"))
    settings = Settings(db_path=tmp_path / "sentrai.db", background=False, demo_speed=60.0, risk_scope="host")
    app = create_app(settings)
    with TestClient(app, headers=AUTH) as c:
        c.core = app.state.core  # type: ignore[attr-defined]
        c.jobs = app.state.jobs  # type: ignore[attr-defined]
        yield c


SCAN = {"roots": ["~/site"], "files_checked": 12, "counts": {"critical": 1, "high": 0, "medium": 1},
        "took_s": 0.4, "findings": [
            {"path": "~/site/up/x.php", "real_path": "/home/erick/site/up/x.php", "line": 3, "kind": "web_shell",
             "severity": "critical", "label": "PHP web shell", "key": "php_eval", "sha256": "ab" * 32,
             "snippet": "eval($_POST['c'])"},
            {"path": "~/site/a.js", "kind": "miner", "severity": "medium", "label": "miner pool", "key": "pool",
             "sha256": "cd" * 32}]}


def test_queue_pick_up_and_report_a_scan(panel):
    key = join(panel, "web-01")["key"]
    job = panel.post("/fleet/jobs", json={"host": "web-01", "kind": "threat_scan", "operator": "erick"})
    assert job.status_code == 200 and job.json()["status"] == "queued"
    got = panel.get("/fleet/jobs/next", headers=as_agent(key)).json()["job"]
    assert got == {"id": job.json()["id"], "kind": "threat_scan"}
    assert panel.get("/fleet/jobs/next", headers=as_agent(key)).json()["job"] is None  # handed out once
    r = panel.post("/fleet/jobs/result", json={"id": got["id"], "ok": True, "result": SCAN}, headers=as_agent(key))
    assert r.status_code == 200 and r.json()["new_alerts"] == 1
    listed = panel.get("/fleet/jobs", params={"host": "web-01"}).json()[0]
    assert listed["status"] == "done" and "2 findings (1 critical or high)" in listed["summary"]
    assert all("real_path" not in f for f in listed["result"]["findings"])
    incs = [i for i in panel.get("/incidents").json() if i.get("category") == "malware"]
    assert incs and incs[0]["host"] == "web-01"
    # the same file reported again opens nothing new
    panel.post("/fleet/jobs", json={"host": "web-01", "kind": "threat_scan"})
    again = panel.get("/fleet/jobs/next", headers=as_agent(key)).json()["job"]
    assert panel.post("/fleet/jobs/result", json={"id": again["id"], "ok": True, "result": SCAN},
                      headers=as_agent(key)).json()["new_alerts"] == 0
    types = [r["type"] for r in panel.get("/audit").json()["records"]]
    assert "machine_job_queued" in types and "machine_job_done" in types


def test_failed_backup_alerts(panel):
    key = join(panel, "db-01")["key"]
    panel.post("/fleet/jobs", json={"host": "db-01", "kind": "backup", "operator": "erick"})
    got = panel.get("/fleet/jobs/next", headers=as_agent(key)).json()["job"]
    r = panel.post("/fleet/jobs/result", json={"id": got["id"], "ok": False, "error": "disk full"}, headers=as_agent(key))
    assert r.json()["status"] == "failed"
    assert any(n["kind"] == "backup_failed" and "db-01" in n["title"] for n in panel.get("/notifications").json())


def test_backup_result_keeps_only_the_summary(panel):
    key = join(panel, "db-01")["key"]
    panel.post("/fleet/jobs", json={"host": "db-01", "kind": "backup"})
    got = panel.get("/fleet/jobs/next", headers=as_agent(key)).json()["job"]
    panel.post("/fleet/jobs/result", json={"id": got["id"], "ok": True, "result": {
        "id": "b-1", "files": 3, "bytes": 2 * 1048576, "sha256": "ef" * 32, "real_roots": ["/srv/db"]}},
               headers=as_agent(key))
    j = panel.get("/fleet/jobs").json()[0]
    assert j["result"] == {"id": "b-1", "files": 3, "bytes": 2 * 1048576, "sha256": "ef" * 32}
    assert j["summary"] == "b-1: 3 files, 2.0 MB"


def test_rules(panel):
    a = join(panel, "web-01")["key"]
    b = join(panel, "web-02")["key"]
    assert panel.post("/fleet/jobs", json={"host": "nope", "kind": "backup"}).status_code == 404
    assert panel.post("/fleet/jobs", json={"host": "web-01", "kind": "rm -rf"}).status_code == 400
    assert panel.post("/fleet/jobs", json={"host": "web-01", "kind": "backup"}).status_code == 200
    assert panel.post("/fleet/jobs", json={"host": "web-01", "kind": "backup"}).status_code == 409
    # an agent never queues, lists or sees another machine's jobs
    assert panel.post("/fleet/jobs", json={"host": "web-01", "kind": "backup"}, headers=as_agent(a)).status_code == 403
    assert panel.get("/fleet/jobs", headers=as_agent(a)).status_code == 403
    assert panel.get("/fleet/jobs/next", headers=as_agent(b)).json()["job"] is None
    got = panel.get("/fleet/jobs/next", headers=as_agent(a)).json()["job"]
    assert panel.post("/fleet/jobs/result", json={"id": got["id"], "ok": True}, headers=as_agent(b)).status_code == 404
    assert panel.get("/fleet/jobs/next").status_code == 400  # the operator token is not a machine


def test_cancel_expire_and_revoke(panel):
    join(panel, "web-01")
    clock = [1_000.0]
    panel.jobs.clock = lambda: clock[0]
    j = panel.post("/fleet/jobs", json={"host": "web-01", "kind": "backup"}).json()
    assert panel.post(f"/fleet/jobs/{j['id']}/cancel", json={"operator": "erick"}).json()["status"] == "cancelled"
    k = panel.post("/fleet/jobs", json={"host": "web-01", "kind": "backup"}).json()
    clock[0] += jobs.QUEUED_TTL_S + 1
    status = {x["id"]: x["status"] for x in panel.get("/fleet/jobs").json()}
    assert status[k["id"]] == "expired"
    s = panel.post("/fleet/jobs", json={"host": "web-01", "kind": "threat_scan"}).json()
    aid = panel.get("/fleet/agents").json()[0]["agent_id"]
    panel.post(f"/fleet/agents/{aid}/revoke", json={"operator": "erick"})
    status = {x["id"]: x["status"] for x in panel.get("/fleet/jobs").json()}
    assert status[s["id"]] == "cancelled"
    assert panel.post("/fleet/jobs", json={"host": "web-01", "kind": "backup"}).status_code == 404
