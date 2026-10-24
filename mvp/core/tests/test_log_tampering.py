"""Log tampering: wiping commands, collector integrity notices, a broken audit chain, clock jumps."""

import sqlite3
import time
from datetime import datetime, timedelta, timezone

import pytest

from app import integrity
from app.integrity import IntegrityGuard
from app.risk import SEVERITY, risk_index
from app.rules import RulesEngine, log_wipe

T0 = 1_790_000_000.0


def host_line(n, raw, source="linux_auth"):
    return {"event_id": f"t{n}", "source": source, "layer": "os", "host": "web-01", "raw": raw}


SUDO = "sudo:  deploy : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND="


@pytest.mark.parametrize("raw", [
    SUDO + "/usr/bin/rm -f /var/log/auth.log",
    SUDO + "/usr/bin/journalctl --vacuum-time=1s",
    SUDO + "/usr/bin/systemctl stop rsyslog",
    SUDO + "/usr/bin/systemctl mask auditd.service",
    SUDO + "/usr/bin/chattr -a /var/log/secure",
    SUDO + "/usr/bin/sed -i /203.0.113.70/d /var/log/auth.log",
    SUDO + "/usr/bin/truncate -s 0 /var/log/nginx/access.log",
    SUDO + "/usr/bin/rm -rf /var/lib/cactai/cactai.db",
    "bash history: history -c && unset HISTFILE",
    "shred -u /root/.bash_history",
    ": > /var/log/wtmp",
    "cat /dev/null > /var/log/auth.log",
    "auditctl -D",
    "process wevtutil.exe cl Security started by administrator",
    "EventID=1102 The audit log was cleared. Account=administrator",
])
def test_wiping_commands_are_log_tampering(raw):
    hit = RulesEngine().check(host_line(1, raw), T0)
    assert hit.category == "log_tampering", raw
    assert hit.reason.startswith("Log tampering:")


@pytest.mark.parametrize("raw", [
    SUDO + "/usr/bin/tail -n 50 /var/log/auth.log",
    SUDO + "/usr/bin/systemctl restart rsyslog",
    SUDO + "/usr/bin/rm /var/log/syslog.4.gz",       # old rotated archive: disk housekeeping
    SUDO + "/usr/bin/rm -f /var/log/nginx/access.log-20261001",
    SUDO + "/usr/bin/rm /tmp/build.log",
    "grep sshd /var/log/auth.log",
    "sed -n 1,20p /var/log/auth.log",
    "backup.sh >> /var/log/backup.log",
    "backup.sh > /var/log/backup.log",                  # a cron job writing its own log
    "kill -9 4242",
    "logrotate: rotating /var/log/nginx/access.log -> access.log.1",
])
def test_admin_lookalikes_are_not(raw):
    assert log_wipe(raw) is None, raw
    hit = RulesEngine().check(host_line(1, raw), T0)
    assert hit is None or hit.category != "log_tampering", raw


def test_the_same_words_in_a_web_request_are_not_a_wiped_log():
    line = {"event_id": "w1", "source": "nginx_access", "layer": "web",
            "raw": '198.51.100.7 - - [28/Sep/2026:14:00:01 +0000] "GET /?c=history%20-c HTTP/1.1" 404 9 "-" "curl/8"'}
    hit = RulesEngine().check(line, T0)
    assert hit is None or hit.category != "log_tampering"


def test_integrity_notices_are_log_tampering():
    r = RulesEngine()
    for source, raw in [("log_integrity", "log-integrity truncated: /var/log/auth.log shrank from 9000 to 0 bytes"),
                        ("audit_integrity", "audit-integrity chain broken at record 12")]:
        hit = r.check(host_line(1, raw, source), T0)
        assert hit.category == "log_tampering" and hit.reason.startswith("Log integrity:")


def test_log_tampering_alone_asks_a_person():
    severity, points = SEVERITY["log_tampering"]
    assert severity == "critical"
    assert risk_index(points) < 80  # never auto-contained on its own: the command may be an admin's


def _tamper_event(n, raw):
    return {"event_id": f"evt-tamper-{n}", "timestamp": "2026-10-02T10:00:00+08:00", "host": "web-01",
            "layer": "os", "source": "linux_auth", "src_ip": "203.0.113.70", "user": "deploy", "raw": raw,
            "asset_criticality": 1.0}


def test_incident_explains_what_was_wiped(client):
    from app.saguaro import TITLES
    assert TITLES["log_tampering"] == "Log tampering"
    client.post("/events", json=_tamper_event(1, SUDO + "/usr/bin/journalctl --vacuum-time=1s"))
    inc = [i for i in client.get("/incidents").json() if i["category"] == "log_tampering"][0]
    assert "journal vacuumed" in inc["explanation"]
    assert "cover their tracks" in inc["explanation"]
    assert "203.0.113.70" in inc["recommended_action"]
    assert inc["status"] == "open"  # waits for a person; nothing applied on its own


def test_broken_audit_chain_opens_an_incident(client):
    core = client.core
    assert core.integrity.check(force=True) == []
    # Someone with access to the database file drops the guard triggers and edits a record.
    db = sqlite3.connect(str(core.audit.path))
    db.execute("DROP TRIGGER audit_no_update")
    db.execute("UPDATE audit SET data = '{}' WHERE seq = 1")
    db.commit()
    db.close()
    found = core.integrity.check(force=True)
    assert len(found) == 1 and "chain broken at record 1" in found[0]["raw"]
    assert core.integrity.check(force=True) == []  # reported once, not every tick
    core.ingest(found)
    inc = [i for i in client.get("/incidents").json() if i["category"] == "log_tampering"][0]
    assert "chain broken" in inc["explanation"]


def test_tick_runs_the_integrity_check(client, monkeypatch):
    core = client.core
    calls = []
    monkeypatch.setattr(core.integrity, "check", lambda: calls.append(1) or [])
    core.tick()
    assert calls == [1]


def test_core_clock_jump_back(client, monkeypatch):
    guard = client.core.integrity
    guard.check(force=True)
    real = time.time
    monkeypatch.setattr(integrity.time, "time", lambda: real() - 3600)
    found = guard.check(force=True)
    assert any("clock jumped back by 3600 s on the core host" in e["raw"] for e in found)


def _iso(dt):
    return dt.isoformat(timespec="seconds")


def test_collector_clock_jump_from_heartbeats(monkeypatch):
    guard = IntegrityGuard.__new__(IntegrityGuard)
    guard.clock_jump_s, guard._beats = 120.0, {}
    steady = [1000.0]
    monkeypatch.setattr(integrity, "_steady", lambda: (steady[0], True))
    t = datetime(2026, 10, 2, 10, 0, tzinfo=timezone.utc)
    assert guard.heartbeat("web-01", _iso(t)) is None
    steady[0] += 10
    assert guard.heartbeat("web-01", _iso(t + timedelta(seconds=10))) is None
    # Held back while the core was unreachable, then delivered together: not a jump.
    steady[0] += 300
    for k in range(2, 6):
        assert guard.heartbeat("web-01", _iso(t + timedelta(seconds=10 * k))) is None
    # Wall clock set an hour ahead.
    steady[0] += 10
    jump = guard.heartbeat("web-01", _iso(t + timedelta(seconds=60 + 3600)))
    assert jump and "jumped forward by 3600 s on web-01" in jump["raw"] and jump["source"] == "audit_integrity"
    # ...and back again.
    steady[0] += 10
    jump = guard.heartbeat("web-01", _iso(t + timedelta(seconds=70)))
    assert jump and "jumped back" in jump["raw"]


def test_forward_jumps_are_ignored_when_sleep_cannot_be_told_apart(monkeypatch):
    guard = IntegrityGuard.__new__(IntegrityGuard)
    guard.clock_jump_s, guard._beats = 120.0, {}
    monkeypatch.setattr(integrity, "_steady", lambda: (1000.0, False))  # e.g. Windows: no CLOCK_BOOTTIME
    t = datetime(2026, 10, 2, 10, 0, tzinfo=timezone.utc)
    guard.heartbeat("laptop", _iso(t))
    assert guard.heartbeat("laptop", _iso(t + timedelta(hours=8))) is None  # woke from sleep
