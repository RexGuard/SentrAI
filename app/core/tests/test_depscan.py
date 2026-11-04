"""Dependency scan (depscan.py) and the package updates a person asks a joined machine to make.

OSV is never called: every test hands the scan a fake fetch.
"""

import json
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import depscan
from app.config import Settings
from app.main import create_app

from .conftest import AUTH
from .test_fleet import as_agent, join


def vuln(vid, eco, name, fixed, severity="HIGH", aliases=()):
    return {"id": vid, "aliases": list(aliases), "summary": f"{name} flaw",
            "database_specific": {"severity": severity},
            "affected": [{"package": {"ecosystem": eco, "name": name},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}


def fake_osv(records: dict[tuple[str, str, str], list[dict]]):
    """records: (ecosystem, name, version) -> the vulnerabilities OSV would return for it."""
    by_id = {v["id"]: v for vs in records.values() for v in vs}
    calls = []

    def fetch(method, path, body):
        calls.append((method, path))
        if path == "/v1/querybatch":
            return {"results": [{"vulns": [{"id": v["id"]} for v in records.get(
                (q["package"]["ecosystem"], q["package"]["name"], q["version"]), [])]} for q in body["queries"]]}
        return by_id[path.rsplit("/", 1)[1]]
    fetch.calls = calls
    return fetch


def make_venv(root: Path, pkgs: dict[str, str]) -> Path:
    (root / "pyvenv.cfg").parent.mkdir(parents=True, exist_ok=True)
    (root / "pyvenv.cfg").write_text("home = /usr/bin\n")
    site = root / "lib" / "python3.11" / "site-packages"
    for name, version in pkgs.items():
        d = site / f"{name}-{version}.dist-info"
        d.mkdir(parents=True)
        (d / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nbody\n")
    (root / "bin").mkdir(exist_ok=True)
    (root / "bin" / "python").write_text("")
    return root


def make_npm(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4.17.0"}}))
    (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"lodash": "^4.17.0"}},
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/lodash/node_modules/minimist": {"version": "1.2.0"}}}))
    return root


def test_versions():
    assert depscan.vkey("2.33.0") > depscan.vkey("2.32.3")
    assert depscan.vkey("1.0") == depscan.vkey("1.0.0")
    assert depscan.vkey("1.0rc1") < depscan.vkey("1.0") < depscan.vkey("1.0.post1")
    assert depscan.same_major("2.32.3", "2.33.0") and not depscan.same_major("12.3.0", "13.0.0")
    assert not depscan.same_major("0.4.1", "0.5.0")  # 0.x breaks on a minor


def test_finds_and_plans(tmp_path):
    make_venv(tmp_path / "app" / ".venv", {"requests": "2.32.3", "Pillow": "12.3.0", "idna": "3.10"})
    make_npm(tmp_path / "web")
    (tmp_path / "requirements.txt").write_text("flask==3.0.3\nrequests>=2\n")
    fetch = fake_osv({
        ("PyPI", "requests", "2.32.3"): [vuln("GHSA-r1", "PyPI", "requests", "2.33.0", aliases=["CVE-1"]),
                                         vuln("PYSEC-r1", "PyPI", "requests", "2.33.0", aliases=["CVE-1"])],
        ("PyPI", "Pillow", "12.3.0"): [vuln("GHSA-p1", "PyPI", "pillow", "13.0.0", "CRITICAL")],
        ("npm", "lodash", "4.17.20"): [vuln("GHSA-l1", "npm", "lodash", "4.17.21")],
        ("npm", "minimist", "1.2.0"): [vuln("GHSA-m1", "npm", "minimist", "1.2.6", "MODERATE")],
        ("PyPI", "flask", "3.0.3"): [vuln("GHSA-f1", "PyPI", "flask", "3.1.3", "LOW")],
    })
    r = depscan.scan([str(tmp_path)], fetch=fetch, own_env=False, os_packages=False)
    got = {f["name"]: f for f in r["findings"]}
    assert set(got) == {"requests", "Pillow", "lodash", "minimist", "flask"}
    assert got["requests"]["update"] == "safe" and got["requests"]["fixed"] == "2.33.0"
    assert got["requests"]["vuln_count"] == 1  # GHSA and PYSEC for one CVE count once
    assert got["Pillow"]["update"] == "manual" and "major" in got["Pillow"]["how"]
    assert got["lodash"]["update"] == "safe"
    assert got["minimist"]["update"] == "manual"  # pulled in by lodash, not a direct dependency
    assert got["flask"]["kind"] == "pinned" and got["flask"]["update"] == "manual"
    assert r["findings"][0]["name"] == "Pillow"  # worst first
    assert r["packages_checked"] == 6 and r["note"] is None
    assert "real_path" not in json.dumps(depscan.shown(r))


def test_own_environment_is_never_one_press(tmp_path):
    src = {"kind": "python", "own": True, "ecosystem": "PyPI", "python": "x", "real_path": "x"}
    assert depscan.plan(src, "certifi", "2026.7.22", "2026.10.18")[0] == "manual"


def test_offline_says_so():
    def down(*_):
        raise OSError("no route to host")
    r = depscan.scan([], fetch=down, own_env=True, os_packages=False)
    assert r["findings"] == [] and "OSV" in r["note"]


def test_debian_packages(tmp_path):
    status = tmp_path / "status"
    status.write_text("Package: libssl3\nStatus: install ok installed\nSource: openssl (3.0.11-1)\n"
                      "Version: 3.0.11-1\n\nPackage: openssl\nStatus: install ok installed\nVersion: 3.0.11-1\n\n"
                      "Package: gone\nStatus: deinstall ok config-files\nVersion: 1\n")
    rel = tmp_path / "os-release"
    rel.write_text('ID=debian\nVERSION_ID="12"\n')
    fetch = fake_osv({("Debian:12", "openssl", "3.0.11-1"): [vuln("DSA-1", "Debian:12", "openssl", "3.0.13-1")]})
    r = depscan.scan([], fetch=fetch, own_env=False, os_packages=True, dpkg_status=status, os_release=rel)
    (f,) = r["findings"]
    assert f["kind"] == "os" and f["update"] == "manual"
    assert "--only-upgrade libssl3 openssl" in f["how"]


def test_update_and_undo_python(tmp_path):
    venv = make_venv(tmp_path / ".venv", {"requests": "2.32.3"})
    fetch = fake_osv({("PyPI", "requests", "2.32.3"): [vuln("GHSA-r1", "PyPI", "requests", "2.33.0")]})
    (f,) = depscan.scan([str(tmp_path)], fetch=fetch, own_env=False, os_packages=False)["findings"]
    ran = []

    def run(cmd, **kw):
        ran.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "ok", "")
    rec = depscan.apply_update(f, tmp_path / "undo", run=run)
    assert ran[-1] == [str(venv / "bin" / "python"), "-m", "pip", "install", "--disable-pip-version-check",
                       "--no-input", "requests==2.33.0"]
    back = depscan.rollback(rec, run=run)
    assert ran[-1][-1] == "requests==2.32.3" and back["status"] == "rolled_back"
    with pytest.raises(depscan.UpdateError):
        depscan.rollback(back, run=run)


def test_update_refuses_what_is_not_safe(tmp_path):
    f = {"id": "x", "kind": "python", "ecosystem": "PyPI", "name": "pillow", "version": "12.3.0", "fixed": "13.0.0",
         "update": "manual", "how": "new major", "real_path": str(tmp_path), "python": "p"}
    with pytest.raises(depscan.UpdateError):
        depscan.apply_update(f, tmp_path, run=lambda *a, **k: pytest.fail("ran"))
    with pytest.raises(depscan.UpdateError):  # a name that is really an option
        depscan.apply_update({**f, "update": "safe", "name": "--index-url=http://evil"}, tmp_path,
                             run=lambda *a, **k: pytest.fail("ran"))


def test_failed_npm_update_puts_the_project_back(tmp_path, monkeypatch):
    proj = make_npm(tmp_path / "web")
    before = (proj / "package-lock.json").read_text()
    fetch = fake_osv({("npm", "lodash", "4.17.20"): [vuln("GHSA-l1", "npm", "lodash", "4.17.21")]})
    f = next(f for f in depscan.scan([str(tmp_path)], fetch=fetch, own_env=False, os_packages=False)["findings"]
             if f["name"] == "lodash")
    monkeypatch.setattr(depscan.shutil, "which", lambda _: "npm")

    def broken(cmd, **kw):
        (proj / "package-lock.json").write_text("half written")
        return subprocess.CompletedProcess(cmd, 1, "", "ERESOLVE")
    with pytest.raises(depscan.UpdateError, match="ERESOLVE"):
        depscan.apply_update(f, tmp_path / "undo", run=broken)
    assert (proj / "package-lock.json").read_text() == before


# ------------------------------------------------------------------ on the panel

@pytest.fixture
def panel(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRAI_THREAT_STATE", str(tmp_path / "state" / "seen.json"))
    settings = Settings(db_path=tmp_path / "sentrai.db", background=False, demo_speed=60.0, risk_scope="host")
    app = create_app(settings)
    with TestClient(app, headers=AUTH) as c:
        yield c


def scan_result(update="safe"):
    return {"packages_checked": 2, "counts": {"high": 1}, "sources": [], "findings": [
        {"id": "3f1c9a0b7d2e4f61", "kind": "python", "ecosystem": "PyPI", "name": "requests", "version": "2.32.3",
         "fixed": "2.33.0", "severity": "high", "update": update, "how": "…", "path": "/srv/app/.venv",
         "real_path": "/srv/app/.venv", "vulns": [{"id": "GHSA-r1", "aliases": ["CVE-1"], "summary": "s"}]}]}


def run_job(panel, key, result, ok=True, error=None):
    got = panel.get("/fleet/jobs/next", headers=as_agent(key)).json()["job"]
    panel.post("/fleet/jobs/result", json={"id": got["id"], "ok": ok, "result": result, "error": error},
               headers=as_agent(key))
    return got


def test_update_needs_a_safe_finding_from_the_latest_scan(panel):
    key = join(panel, "web-01")["key"]
    assert panel.post("/fleet/jobs", json={"host": "web-01", "kind": "dep_update",
                                           "params": {"finding": "3f1c9a0b7d2e4f61"}}).status_code == 404
    panel.post("/fleet/jobs", json={"host": "web-01", "kind": "dep_scan"})
    run_job(panel, key, scan_result())
    scan = panel.get("/fleet/jobs?host=web-01").json()[0]
    assert "real_path" not in scan["result"]["findings"][0]
    assert scan["summary"] == "2 packages checked, 1 vulnerable (1 critical or high), 1 can be updated here"
    assert panel.post("/fleet/jobs", json={"host": "web-01", "kind": "dep_update",
                                           "params": {"finding": "../../etc"}}).status_code == 404
    assert panel.post("/fleet/jobs", json={"host": "web-01", "kind": "dep_update",
                                           "params": {"finding": "3f1c9a0b7d2e4f61", "to": "9.9"}}).status_code == 400
    r = panel.post("/fleet/jobs", json={"host": "web-01", "kind": "dep_update", "operator": "erick",
                                        "params": {"finding": "3f1c9a0b7d2e4f61"}})
    assert r.status_code == 200
    got = panel.get("/fleet/jobs/next", headers=as_agent(key)).json()["job"]
    assert got == {"id": r.json()["id"], "kind": "dep_update", "params": {"finding": "3f1c9a0b7d2e4f61"}}
    audit = panel.get("/audit").json()
    rows = audit if isinstance(audit, list) else audit.get("records", [])
    assert any("requests 2.32.3 → 2.33.0" in json.dumps(x, ensure_ascii=False) for x in rows)


def test_manual_finding_is_refused(panel):
    key = join(panel, "web-01")["key"]
    panel.post("/fleet/jobs", json={"host": "web-01", "kind": "dep_scan"})
    run_job(panel, key, scan_result("manual"))
    r = panel.post("/fleet/jobs", json={"host": "web-01", "kind": "dep_update", "params": {"finding": "3f1c9a0b7d2e4f61"}})
    assert r.status_code == 409


def test_undo_once(panel):
    key = join(panel, "web-01")["key"]
    panel.post("/fleet/jobs", json={"host": "web-01", "kind": "dep_scan"})
    run_job(panel, key, scan_result())
    panel.post("/fleet/jobs", json={"host": "web-01", "kind": "dep_update", "params": {"finding": "3f1c9a0b7d2e4f61"}})
    change = {"id": "u-1a2b3c4d", "finding": "3f1c9a0b7d2e4f61", "kind": "python", "name": "requests",
              "from": "2.32.3", "to": "2.33.0", "path": "/srv/app/.venv", "status": "applied"}
    run_job(panel, key, {**change, "real_path": "/secret"})
    j = panel.get("/fleet/jobs?host=web-01").json()[0]
    assert j["result"] == change and "u-1a2b3c4d" in j["summary"]
    undo = {"host": "web-01", "kind": "dep_rollback", "params": {"update": "u-1a2b3c4d"}}
    assert panel.post("/fleet/jobs", json=undo).status_code == 200
    run_job(panel, key, {**change, "status": "rolled_back"})
    assert panel.post("/fleet/jobs", json=undo).status_code == 409
    assert panel.post("/fleet/jobs", json={**undo, "params": {"update": "u-00000000"}}).status_code == 404


def test_panel_scan(panel, monkeypatch, tmp_path):
    make_venv(tmp_path / "svc" / ".venv", {"requests": "2.32.3"})
    monkeypatch.setenv("SENTRAI_DEP_PATHS", str(tmp_path))
    monkeypatch.setattr(depscan, "osv_fetch", fake_osv({
        ("PyPI", "requests", "2.32.3"): [vuln("GHSA-r1", "PyPI", "requests", "2.33.0")]}))
    monkeypatch.setenv("SENTRAI_DEP_OS", "off")
    assert panel.get("/deps").json() == {"findings": [], "scanned_at": None}
    out = panel.post("/deps/scan", json={"operator": "erick"}).json()
    assert any(f["name"] == "requests" and f["update"] == "safe" for f in out["findings"])
    assert panel.get("/deps").json()["scanned_at"] == out["scanned_at"]
