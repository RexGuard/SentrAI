"""Build the labelled event set used by evaluate.py (writes eval/events.jsonl).

Three origins, all in the contract Event shape the collector sends to core:

- "lab":        the real lab target app (Flask test client, no network) driven with the
                payloads from lab/attacks/*.py plus normal staff traffic. Its log lines are
                read back and turned into Events by the real collector (collector.normalize).
- "replay":     lab/replay/simulate.py's scripted incident, unchanged.
- "handcrafted": lines the lab cannot produce (firewall, cloud, Windows, Linux auth) and
                benign look-alikes that should NOT raise an incident.

Labelling rule: a line gets an attack label only if an analyst reading that line alone (plus
the earlier lines from the same source, for brute force) could see the attack. Companion
lines that show nothing ("GET /search 200" from the SQLi attacker) are left out rather than
labelled either way. Every failed login in a brute-force burst is labelled brute_force,
including the first few before any threshold is reached.

Needs Flask (lab/requirements.txt). The generated events.jsonl is committed, so
evaluate.py does not need Flask:

    python eval/build_dataset.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent
MVP = EVAL_DIR.parent
LAB = MVP / "lab"
OUT = EVAL_DIR / "events.jsonl"

_TMP = Path(tempfile.mkdtemp(prefix="cactai-eval-"))
os.environ["CACTAI_LAB_LOGS"] = str(_TMP / "logs")
os.environ["CACTAI_LAB_DB"] = str(_TMP / "portal.sqlite3")
os.environ["CACTAI_CONFIG"] = str(_TMP / "no-config.json")  # ignore this machine's saved settings
sys.path.insert(0, str(LAB))

from attacks.benign import SEARCH_TERMS  # noqa: E402
from attacks.brute_force import WRONG_PASSWORDS  # noqa: E402
from attacks.shell import COMMANDS  # noqa: E402
from attacks.sqli import PAYLOADS as SQLI_PAYLOADS  # noqa: E402
from collector import collector  # noqa: E402
from replay import simulate  # noqa: E402
from target_app import paths  # noqa: E402
from target_app.app import create_app  # noqa: E402

SGT = timezone(timedelta(hours=8))
T0 = datetime(2026, 9, 28, 9, 0, 0, tzinfo=SGT)
STAFF_IP, STAFF2_IP = "192.0.2.10", "192.0.2.11"

# Extra payloads sent through the lab app's /search (the lab has no XSS script).
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg/onload=alert('xss')>",
    "javascript:alert(1)",
    "\"><iframe src=javascript:alert(1)>",
]
# SQLi written differently from the lab script (URL-encoded, no quotes, comment styles).
SQLI_VARIANTS = [
    "1 AND 1=1",
    "admin' #",
    "1' AND SLEEP(5)-- -",
    "' uNiOn/**/SeLeCt null,version()--",
    "x' AND extractvalue(1,concat(0x7e,database()))--",
]
# Normal searches that contain SQL/HTML-looking words.
BENIGN_SEARCHES = SEARCH_TERMS + [
    "O'Brien", "select course", "Diploma in Business", "oracle training",
    "union street campus", "drop-in session", "script writing club", "C++ & Java",
]


class LabRun:
    """Drives the lab app in-process and turns each new log line into a labelled Event."""

    def __init__(self) -> None:
        self.app = create_app(start_polling=False)
        self.client = self.app.test_client()
        self.pos: dict[str, int] = {}
        self.events: list[dict] = []

    def _new_lines(self) -> list[tuple[str, dict]]:
        out = []
        for name in paths.ALL_LOGS:
            p = paths.logs_dir() / name
            if not p.exists():
                continue
            lines = p.read_text(encoding="utf-8").splitlines()
            start = self.pos.get(name, 0)
            self.pos[name] = len(lines)
            out += [(name, json.loads(line)) for line in lines[start:] if line.strip()]
        return out

    def step(self, scenario: str, label: str, keep: set[str], send, ip: str, hour: str | None = None) -> None:
        """Send one request; keep lines from the `keep` log files, labelled `label`."""
        headers = {"X-Demo-Src-IP": ip}
        if hour:
            headers["X-Demo-Hour"] = hour
        send(self.client, headers)
        for name, rec in self._new_lines():
            if name not in keep:
                continue
            ev = collector.normalize(name, rec)
            if ev is not None:
                self.events.append({**ev, "label": label, "origin": "lab", "scenario": scenario})


def lab_events() -> list[dict]:
    run = LabRun()
    pw = (paths.seed_dir() / "admin_password.txt").read_text(encoding="utf-8").strip()
    web = {paths.ACCESS_LOG, paths.AUTH_LOG, paths.DB_LOG, paths.OS_LOG}
    login = lambda user, password: lambda c, h: c.post("/login", data={"user": user, "password": password}, headers=h)  # noqa: E731
    search = lambda q: lambda c, h: c.get("/search", query_string={"q": q}, headers=h)  # noqa: E731

    # Normal staff traffic (attacks/benign.py pattern), including one mistyped password.
    for i, q in enumerate(BENIGN_SEARCHES):
        run.step("benign_staff", "benign", web, lambda c, h: c.get("/", headers=h), STAFF_IP)
        run.step("benign_staff", "benign", web, login("admin", pw), STAFF_IP)
        run.step("benign_staff", "benign", web, search(q), STAFF_IP)
    run.step("benign_typo", "benign", web, login("admin", pw + "x"), STAFF2_IP)
    run.step("benign_typo", "benign", web, login("admin", pw), STAFF2_IP)

    # attacks/brute_force.py: 12 wrong passwords from one IP.
    for p in WRONG_PASSWORDS:
        run.step("lab_brute_force", "brute_force", {paths.ACCESS_LOG, paths.AUTH_LOG}, login("admin", p), "203.0.113.45")
    # attacks/sqli.py payloads, then variants. Only the DB line shows the payload.
    for q in SQLI_PAYLOADS:
        run.step("lab_sqli", "sql_injection", {paths.DB_LOG}, search(q), "198.51.100.23")
    for q in SQLI_VARIANTS:
        run.step("lab_sqli_variants", "sql_injection", {paths.DB_LOG}, search(q), "198.51.100.24")
    for q in XSS_PAYLOADS:
        run.step("lab_xss", "xss", {paths.DB_LOG}, search(q), "198.51.100.40")
    # attacks/exfil.py: 4 off-hours full exports (the lab portal has 40 members).
    for _ in range(4):
        run.step("lab_exfil", "data_exfiltration", {paths.ACCESS_LOG, paths.DB_LOG},
                 lambda c, h: c.get("/export", headers=h), "203.0.113.77", hour="03")
    # attacks/shell.py: simulated web shell. Only the OS line shows it.
    for cmd in COMMANDS:
        run.step("lab_shell", "privilege_escalation", {paths.OS_LOG},
                 lambda c, h, cmd=cmd: c.get("/admin/run", query_string={"cmd": cmd}, headers=h), "198.51.100.77")
    return run.events


def replay_events() -> list[dict]:
    out = []
    for ev in simulate.build_sequence():
        raw = ev["raw"]
        if ev["source"] == "flask_auth":
            label = "brute_force"
        elif ev["source"] == "db_query":
            label = "sql_injection"
        elif ev["source"] == "os_process":
            label = "privilege_escalation"
        else:
            label = "benign"
        assert label != "benign" or "200" in raw, raw
        out.append({**ev, "label": label, "origin": "replay", "scenario": "replay"})
    return out


def _hand(scenario, label, layer, source, raw, ip=None, user=None, host="web-01", crit=1.0) -> dict:
    return {"event_id": "", "timestamp": "", "host": host, "layer": layer, "source": source, "src_ip": ip,
            "user": user, "raw": raw, "asset_criticality": crit, "label": label, "origin": "handcrafted",
            "scenario": scenario}


def handcrafted_events() -> list[dict]:
    fw, cloud, win, auth, osp = ("network", "firewall"), ("cloud", "cloud_audit"), ("os", "windows_security"), ("os", "linux_auth"), ("os", "os_process")
    h = []
    # Port scans as firewall / IDS lines.
    for i, raw in enumerate([
        "IDS alert: nmap SYN scan detected from 198.51.100.90 against 10.0.0.5 (ports 1-1024)",
        "UFW BLOCK SRC=198.51.100.90 DST=10.0.0.5 PROTO=TCP DPT=23 flags=SYN; port scan suspected",
        "suricata: ET SCAN masscan TCP scan 203.0.113.9 -> 10.0.0.0/24",
        "firewall: 214 connection attempts to 97 distinct ports from 203.0.113.9 in 10s",
        "kernel: TCP SYN to closed ports 21,22,23,25,80,110,139,443,445,3389 from 203.0.113.9",
    ]):
        h.append(_hand("hand_port_scan", "port_scan", *fw, raw, ip="198.51.100.90" if i < 2 else "203.0.113.9", host="fw-01"))
    # Misconfigurations as cloud / config audit lines.
    for raw in [
        "PutBucketAcl bucket=aegis-student-docs acl=public-read by user=it-admin",
        "Security group sg-0a1 rule added: ingress 0.0.0.0/0 tcp 3389",
        "Security group sg-0a1 rule added: ingress 0.0.0.0/0 tcp 22",
        "config audit: router admin still uses default password",
        "blob container 'reports' access level changed to public (anonymous read)",
    ]:
        h.append(_hand("hand_misconfig", "misconfiguration", *cloud, raw, user="it-admin", host="cloud"))
    # Privilege escalation on a host.
    for raw in [
        "auditd: new SUID binary /tmp/.x/bash owner=www-data",
        "nginx worker spawned /bin/sh -c 'id; uname -a'",
        "sudo: www-data : user NOT in sudoers ; TTY=pts/0 ; COMMAND=/bin/bash",
        "w3wp.exe started cmd.exe /c whoami",
        "process powershell -enc SQBFAFgA... started by apache",
    ]:
        h.append(_hand("hand_priv_esc", "privilege_escalation", *osp, raw, host="web-01"))
    # Brute force outside the web app: Windows 4625 and sshd.
    for i in range(6):
        h.append(_hand("hand_brute_windows", "brute_force", *win,
                       f"EventID=4625 An account failed to log on. Account=administrator Source={'203.0.113.60'}",
                       ip="203.0.113.60", user="administrator", host="dc-01"))
    for i in range(6):
        h.append(_hand("hand_brute_ssh", "brute_force", *auth,
                       f"sshd[812]: Failed password for root from 203.0.113.61 port {40100 + i} ssh2",
                       ip="203.0.113.61", user="root", host="web-01"))
    # Data exfiltration outside the web app.
    for raw in [
        "COPY members TO '/tmp/m.csv' rows=5200",
        "SELECT * FROM members rows=5200 client=203.0.113.77",
        "s3 GetObject x 1840 objects (2.1 GB) bucket=aegis-student-docs by key AKIA...XYZ from 203.0.113.77",
    ]:
        h.append(_hand("hand_exfil", "data_exfiltration", "db", "db_query", raw, ip="203.0.113.77", host="db-01", crit=1.5))
    # Benign look-alikes: should NOT open an incident.
    for layer, source, raw in [
        ("db", "db_query", "SELECT rows=12 q='SELECT * FROM members WHERE program = ?'"),
        ("db", "db_query", "pg_dump nightly backup completed rows=40 dest=/backup/2026-09-28.sql"),
        ("os", "os_process", "cron: daily logrotate finished"),
        ("os", "os_process", "sshd[900]: Accepted publickey for deploy from 192.0.2.20 port 51022 ssh2"),
        ("os", "os_process", "systemd: Started Session 41 of user deploy."),
        ("web", "flask_access", "GET /static/app.js 304"),
        ("web", "flask_access", "GET /favicon.ico 404"),
        ("web", "flask_access", "GET /reports/term3.pdf 500 error while rendering"),
        ("network", "firewall", "UFW ALLOW SRC=192.0.2.10 DST=10.0.0.5 PROTO=TCP DPT=443"),
        ("network", "firewall", "vulnerability scan by approved vendor window 02:00-03:00 finished, 0 findings"),
        ("cloud", "cloud_audit", "PutBucketAcl bucket=aegis-student-docs acl=private by user=it-admin"),
        ("cloud", "cloud_audit", "Security group sg-0a1 rule removed: ingress 0.0.0.0/0 tcp 3389"),
        ("os", "windows_security", "EventID=4624 An account was successfully logged on. Account=teacher01"),
        ("web", "flask_access", "GET /export 200 rows=8 user=admin"),
        ("web", "flask_access", "GET /help/download all course notes 200"),
    ]:
        h.append(_hand("hand_benign_lookalike", "benign", layer, source, raw, ip="192.0.2.10"))
    return h


def main() -> None:
    events = lab_events() + replay_events() + handcrafted_events()
    # Fixed ids and timestamps so the file is stable across runs. Scenarios are 10 minutes
    # apart, events 5 s apart, so a brute-force window never spans two scenarios.
    scen_start: dict[str, datetime] = {}
    for n, ev in enumerate(events, 1):
        base = scen_start.setdefault(ev["scenario"], T0 + timedelta(minutes=10 * len(scen_start)))
        idx = sum(1 for e in events[:n - 1] if e["scenario"] == ev["scenario"])
        ev["event_id"] = f"eval-{n:04d}"
        ev["timestamp"] = (base + timedelta(seconds=5 * idx)).isoformat(timespec="seconds")
    with OUT.open("w", encoding="utf-8", newline="\n") as fh:
        for ev in events:
            fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
    counts: dict[str, int] = {}
    for ev in events:
        counts[ev["label"]] = counts.get(ev["label"], 0) + 1
    print(f"wrote {len(events)} events to {OUT.relative_to(MVP)}")
    for k in sorted(counts):
        print(f"  {k:<22}{counts[k]}")


if __name__ == "__main__":
    main()
