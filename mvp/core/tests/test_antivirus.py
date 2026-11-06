"""The panel's side of the agents' antivirus: the shared fingerprint list (signatures.py), the file
watch's finds (POST /fleet/threats), quarantine jobs, and shared reputation."""

import pytest
from fastapi.testclient import TestClient

from app import jobs, signatures
from app.config import Settings
from app.main import create_app

from .conftest import AUTH
from .test_fleet import as_agent, join

A = "ab" * 32
B = "cd" * 32
M = "ef" * 16


@pytest.fixture
def panel(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRAI_THREAT_STATE", str(tmp_path / "state" / "seen.json"))
    settings = Settings(db_path=tmp_path / "sentrai.db", background=False, demo_speed=60.0, risk_scope="host")
    app = create_app(settings)
    with TestClient(app, headers=AUTH) as c:
        yield c


def test_parse_formats():
    plain = f"# my list\n{A}  webshell.php\n{M}\nnot a hash\n"
    assert signatures.parse(plain) == [(A, "webshell.php"), (M, "")]
    clam = f"{B}:1234:Unix.Trojan.Example-1\n{M}:99:Win.Test.Thing:73\n"
    assert signatures.parse(clam) == [(B, "Unix.Trojan.Example-1"), (M, "Win.Test.Thing")]
    csv_text = ('"first_seen_utc","sha256_hash","md5_hash","signature"\n'
                f'"2026-11-06 10:00:00","{A}","{M}","Mirai"\n')
    assert signatures.parse(csv_text) == [(A, "Mirai")]


def test_add_remove_and_versions(tmp_path):
    s = signatures.Signatures(tmp_path / "s.json")
    assert s.add([(A, "x"), (A, "again"), ("nope", "")], "operator", "erick") == {"added": 1, "known": 1, "refused": 1}
    v = s.version
    assert s.add([(B, "")], "import:feed", "erick")["added"] == 1 and s.version == v + 1
    again = signatures.Signatures(tmp_path / "s.json")  # kept on disk
    assert again.hashes() == {"sha256": sorted([A, B]), "md5": []} and again.version == s.version
    assert again.remove(source="import:feed") == 1 and again.lookup(B) is None and again.lookup(A)["name"] == "x"


def test_cli_import_and_agent_fetch(panel):
    text = f"{A}:10:Unix.Test-1\n{B}:20:Unix.Test-2\n"
    r = panel.post("/signatures", json={"text": text, "source": "main.hsb", "operator": "erick"})
    assert r.status_code == 200 and r.json()["added"] == 2
    summary = panel.get("/signatures").json()
    assert summary["count"] == 2 and summary["by_source"] == {"import:main.hsb": 2}
    key = join(panel, "web-01")["key"]
    got = panel.get("/fleet/signatures", headers=as_agent(key)).json()
    assert got["sha256"] == sorted([A, B]) and "Unix.Test-1" not in str(got)  # names stay on the panel
    assert panel.get("/fleet/signatures", params={"have": got["version"]}, headers=as_agent(key)).json()["unchanged"]
    assert panel.post("/signatures/remove", json={"source": "import:main.hsb"}).json()["removed"] == 2
    assert panel.post("/signatures", json={}).status_code == 400
    types = [x["type"] for x in panel.get("/audit").json()["records"]]
    assert "signatures_added" in types and "signatures_removed" in types


def test_file_watch_finds_open_one_incident(panel):
    key = join(panel, "web-01")["key"]
    finds = [{"id": "3f9c0a7d1e2b4c5a", "path": "~/site/uploads/cat.jpg", "kind": "disguised", "severity": "critical",
              "label": "a Linux program pretending to be a .jpg file", "key": "program-in-disguise", "sha256": A,
              "source": "watch", "real_path": "/home/erick/site/uploads/cat.jpg"},
             {"path": "/etc/hosts", "kind": "persistence", "severity": "medium", "label": "the hosts file changed",
              "key": "watched-file-changed", "sha256": B, "source": "watch", "old": "1234", "new": "5678"}]
    r = panel.post("/fleet/threats", json={"findings": finds}, headers=as_agent(key))
    assert r.json() == {"ok": True, "findings": 2, "new_alerts": 1}
    assert panel.post("/fleet/threats", json={"findings": finds}, headers=as_agent(key)).json()["new_alerts"] == 0
    rows = panel.get("/fleet/threats", params={"host": "web-01"}).json()["findings"]
    assert rows[0]["id"] == "3f9c0a7d1e2b4c5a" and all("real_path" not in x for x in rows)
    incs = [i for i in panel.get("/incidents").json() if i.get("category") == "malware"]
    assert len(incs) == 1 and incs[0]["host"] == "web-01"
    assert panel.post("/fleet/threats", json={"findings": finds}).status_code == 400  # operator token: not an agent


def test_quarantine_job_shares_the_fingerprint(panel):
    key = join(panel, "web-01")["key"]
    assert panel.post("/fleet/jobs", json={"host": "web-01", "kind": "quarantine"}).status_code == 400
    assert panel.post("/fleet/jobs", json={"host": "web-01", "kind": "quarantine",
                                           "params": {"finding": "../../etc/passwd"}}).status_code == 400
    job = panel.post("/fleet/jobs", json={"host": "web-01", "kind": "quarantine", "operator": "erick",
                                          "params": {"finding": "3f9c0a7d1e2b4c5a"}}).json()
    got = panel.get("/fleet/jobs/next", headers=as_agent(key)).json()["job"]
    assert got["params"] == {"finding": "3f9c0a7d1e2b4c5a"}
    result = {"id": "q-1a2b3c4d", "path": "~/site/uploads/cat.jpg", "sha256": A, "label": "disguised program",
              "original": "/home/erick/site/uploads/cat.jpg", "size": 10}
    panel.post("/fleet/jobs/result", json={"id": job["id"], "ok": True, "result": result}, headers=as_agent(key))
    done = panel.get("/fleet/jobs", params={"host": "web-01"}).json()[0]
    assert "original" not in done["result"] and "q-1a2b3c4d" in done["summary"]
    shared = panel.get("/signatures").json()
    assert shared["count"] == 1 and shared["recent"][0]["source"] == "quarantine on web-01"
    # every other machine now gets it
    other = join(panel, "web-02")["key"]
    assert A in panel.get("/fleet/signatures", headers=as_agent(other)).json()["sha256"]
    types = [x["type"] for x in panel.get("/audit").json()["records"]]
    assert "file_quarantined" in types
    undo = panel.post("/fleet/jobs", json={"host": "web-01", "kind": "restore", "params": {"item": "q-1a2b3c4d"}})
    assert undo.status_code == 200


def test_clean_findings_cuts_long_text():
    rows = jobs.clean_findings([{"path": "x" * 1000, "label": "y", "severity": "high", "examples": ["e"] * 9,
                                 "real_path": "/secret"}, "not a dict"])
    assert len(rows) == 1 and len(rows[0]["path"]) == 300 and len(rows[0]["examples"]) == 5
    assert "real_path" not in rows[0]
