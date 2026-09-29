"""End-to-end test of the SentrAI demo story against the REAL components.

Starts core (:8000), the target app (:5000) and the collector as subprocesses using each
component's own venv, then runs the lab attack scripts and checks the whole chain:

  benign traffic -> no incident
  brute force    -> brute_force incident, risk rises, operator notified
  inaction       -> penalty grows (fast demo clock)
  SQL injection  -> risk crosses 80 -> Needle approves -> attacker blocked (HTTP 403)
  loopback       -> never blocked
  report         -> evidence report with "Ack: none", audit chain valid
  rollback       -> block removed

Run from mvp\\lab's venv (it has requests + pytest):
    ..\\lab\\.venv\\Scripts\\python.exe -m pytest -q test_e2e.py
Ports 8000 and 5000 must be free (stop the demo first with ..\\stop_demo.ps1).
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

MVP = Path(__file__).resolve().parents[1]
CORE = "http://127.0.0.1:8000"
TARGET = "http://127.0.0.1:5000"
AUTH = {"Authorization": "Bearer e2e-token"}  # the core API token every component gets below
ATTACKER_BF = "203.0.113.45"
ATTACKER_SQLI = "198.51.100.23"


def venv_python(component: str) -> Path:
    exe = "python.exe" if os.name == "nt" else "python"
    sub = "Scripts" if os.name == "nt" else "bin"
    return MVP / component / ".venv" / sub / exe


def port_busy(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def wait_http(url: str, seconds: float = 30) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        try:
            if requests.get(url, timeout=1).status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.3)
    return False


def wait_for(pred, seconds: float = 20, step: float = 0.5):
    end = time.time() + seconds
    last = None
    while time.time() < end:
        last = pred()
        if last:
            return last
        time.sleep(step)
    return last


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    for comp in ("core", "lab"):
        if not venv_python(comp).exists():
            pytest.skip(f"{comp} venv missing: create mvp\\{comp}\\.venv first")
    for port in (8000, 5000):
        if port_busy(port):
            pytest.skip(f"port {port} is in use: stop the running demo (stop_demo.ps1) first")

    tmp = tmp_path_factory.mktemp("e2e")
    (tmp / "config.json").write_text("{}")  # empty settings: defaults only, and no setup wizard
    env = dict(os.environ)
    env.update(
        PYTHONUTF8="1",
        CACTAI_CONFIG=str(tmp / "config.json"),
        DEMO_SPEED="3600",          # 1 real second = 1 demo hour
        CACTAI_DB=str(tmp / "audit.db"),
        CACTAI_CORE_URL=CORE,
        CACTAI_API_TOKEN="e2e-token",
        HOTPATCH_TTL_HOURS="200",   # keep blocks active long enough to assert on them
    )
    env.pop("TYPESAFE_API_KEY", None)  # deterministic: rules + fallback only
    logs = MVP / "lab" / "logs"
    logs.mkdir(exist_ok=True)
    for f in logs.glob("*.jsonl"):
        f.unlink()

    procs: list[subprocess.Popen] = []
    out = open(tmp / "processes.log", "w", encoding="utf-8")

    def start(args, cwd):
        p = subprocess.Popen(args, cwd=str(cwd), env=env, stdout=out, stderr=subprocess.STDOUT)
        procs.append(p)
        return p

    try:
        start([str(venv_python("core")), "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"], MVP / "core")
        assert wait_http(f"{CORE}/health"), "core did not start"
        start([str(venv_python("lab")), "-m", "target_app"], MVP / "lab")
        assert wait_http(f"{TARGET}/healthz"), "target app did not start"
        start([str(venv_python("lab")), "-m", "collector.collector", "--flush-interval", "0.5"], MVP / "lab")
        yield env
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        out.close()


def attack(module: str, *args: str) -> None:
    env = dict(os.environ, PYTHONUTF8="1")
    subprocess.run([str(venv_python("lab")), "-m", module, *args], cwd=str(MVP / "lab"), env=env,
                   check=True, capture_output=True, timeout=120)


def incidents() -> list[dict]:
    return requests.get(f"{CORE}/incidents", headers=AUTH, timeout=3).json()


def risk() -> dict:
    return requests.get(f"{CORE}/risk?history=0", headers=AUTH, timeout=3).json()


def test_demo_story(stack):
    # 1. Benign traffic creates no incident.
    attack("attacks.benign", "--count", "6", "--delay", "0.1")
    time.sleep(2)
    assert incidents() == [], "benign traffic must not open incidents"

    # 2. Brute force opens a brute_force incident and notifies the operator.
    attack("attacks.brute_force", "--count", "8", "--delay", "0.1")
    bf = wait_for(lambda: next((i for i in incidents() if i["category"] == "brute_force"), None))
    assert bf, "brute force incident not created"
    assert bf["src_ip"] == ATTACKER_BF and bf["classified_by"] == "rules"
    start_risk = risk()["risk_index"]
    assert start_risk >= 30
    pending_kinds = {n["kind"] for n in requests.get(f"{CORE}/notifications", headers=AUTH, timeout=3).json()}
    assert "incident_opened" in pending_kinds

    # 3. Inaction: with the fast demo clock the penalty grows within seconds.
    assert wait_for(lambda: risk()["risk_index"] > start_risk, 15), "inaction penalty did not raise risk"

    # 4. SQL injection pushes risk over the threshold -> autonomous containment.
    attack("attacks.sqli", "--count", "3", "--delay", "0.2")
    bl = wait_for(lambda: (lambda b: b if ATTACKER_SQLI in b["ips"] else None)(
        requests.get(f"{CORE}/blocklist", headers=AUTH, timeout=3).json()), 20)
    assert bl, "attacker IP was not blocked"
    assert ATTACKER_BF in bl["ips"] and "admin" in bl["users"]
    by_cat = {i["category"]: i for i in incidents()}
    assert by_cat["sql_injection"]["status"] == "contained"
    acts = [a for i in by_cat.values() for a in i["actions"]]
    assert acts and all(a["approved_by"] == "Needle" and a["mode"] == "autonomous" for a in acts)
    history = requests.get(f"{CORE}/risk?history=600", headers=AUTH, timeout=3).json()["history"]
    assert max(h["risk_index"] for h in history) >= 80, "threshold peak missing from chart history"

    # 5. The target app enforces the block (poll interval 2 s); loopback is never blocked.
    def attacker_status():
        r = requests.get(f"{TARGET}/", headers={"X-Demo-Src-IP": ATTACKER_SQLI}, timeout=3)
        return r.status_code == 403
    assert wait_for(attacker_status, 10), "target app did not return 403 for the blocked attacker"
    assert requests.get(f"{TARGET}/", timeout=3).status_code == 200, "loopback must never be blocked"

    # 6. Negligence report and audit chain.
    md = requests.get(f"{CORE}/reports/{bf['id']}.md", headers=AUTH, timeout=3).text
    assert "Ack: none" in md and "Needle" in md
    audit = requests.get(f"{CORE}/audit", headers=AUTH, timeout=3).json()
    assert audit["chain_valid"] is True and audit["count"] > 10

    # 7. Rollback removes the block for that incident.
    sq = by_cat["sql_injection"]
    r = requests.post(f"{CORE}/incidents/{sq['id']}/rollback",
                      json={"operator": "erick", "justification": "e2e test rollback"}, headers=AUTH, timeout=3)
    assert r.status_code == 200
    assert ATTACKER_SQLI not in requests.get(f"{CORE}/blocklist", headers=AUTH, timeout=3).json()["ips"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
