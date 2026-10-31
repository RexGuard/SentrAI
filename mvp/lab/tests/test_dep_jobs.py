"""The agent's side of dependency scans and package updates (agent/tasks.py): an update names only a
finding id, and the package, place and version come from this machine's own last scan."""
from __future__ import annotations

import subprocess

from agent import agent, tasks  # noqa: F401  (agent puts core/ on the path)
from app import depscan


def finding(tmp_path, **over):
    venv = tmp_path / ".venv"
    (venv / "bin").mkdir(parents=True, exist_ok=True)
    (venv / "bin" / "python").write_text("")
    return {"id": "3f1c9a0b7d2e4f61", "kind": "python", "ecosystem": "PyPI", "name": "requests",
            "version": "2.32.3", "fixed": "2.33.0", "severity": "high", "update": "safe", "how": "",
            "real_path": str(venv), "python": str(venv / "bin" / "python"), "path": "~/.venv", **over}


def test_scan_update_undo(tmp_path, monkeypatch):
    data = tmp_path / "agent"
    f = finding(tmp_path)
    monkeypatch.setattr(depscan, "scan", lambda roots: {"findings": [f], "note": None, "counts": {}})
    ran = []
    monkeypatch.setattr(depscan.subprocess, "run",
                        lambda cmd, **kw: ran.append(cmd) or subprocess.CompletedProcess(cmd, 0, "ok", ""))

    ok, result, _ = tasks.run_job({"id": "j-1", "kind": "dep_scan"}, data)
    assert ok and "real_path" not in result["findings"][0] and "python" not in result["findings"][0]

    ok, rec, err = tasks.run_job({"id": "j-2", "kind": "dep_update", "params": {"finding": f["id"]}}, data)
    assert ok, err
    assert ran[-1][-1] == "requests==2.33.0" and rec["id"].startswith("u-") and "real_path" not in rec

    ok, back, err = tasks.run_job({"id": "j-3", "kind": "dep_rollback", "params": {"update": rec["id"]}}, data)
    assert ok, err
    assert ran[-1][-1] == "requests==2.32.3" and back["status"] == "rolled_back"
    ok, _, err = tasks.run_job({"id": "j-4", "kind": "dep_rollback", "params": {"update": rec["id"]}}, data)
    assert not ok and "not applied" in err


def test_update_only_from_its_own_list(tmp_path, monkeypatch):
    data = tmp_path / "agent"
    monkeypatch.setattr(depscan, "scan", lambda roots: {"findings": [finding(tmp_path, update="manual")], "note": None})
    monkeypatch.setattr(depscan.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("ran")))
    tasks.run_job({"id": "j-1", "kind": "dep_scan"}, data)
    ok, _, err = tasks.run_job({"id": "j-2", "kind": "dep_update", "params": {"finding": "0" * 16}}, data)
    assert not ok and "not in this machine's last dependency scan" in err
    ok, _, err = tasks.run_job({"id": "j-3", "kind": "dep_update", "params": {"finding": "3f1c9a0b7d2e4f61"}}, data)
    assert not ok and "not a one-press update" in err


def test_offline_scan_keeps_the_last_list(tmp_path, monkeypatch):
    data = tmp_path / "agent"
    monkeypatch.setattr(depscan, "scan", lambda roots: {"findings": [finding(tmp_path)], "note": None})
    tasks.run_job({"id": "j-1", "kind": "dep_scan"}, data)
    monkeypatch.setattr(depscan, "scan", lambda roots: {"findings": [], "note": "Could not reach OSV"})
    ok, result, _ = tasks.run_job({"id": "j-2", "kind": "dep_scan"}, data)
    assert ok and result["note"]
    assert (tasks._deps_dir(data) / "last_scan.json").read_text().count("3f1c9a0b7d2e4f61") == 1
