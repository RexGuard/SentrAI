"""Real server logs: nginx and sshd parsing, journald, and read positions that survive restarts.

The sample files in ``tests/samples`` are synthetic lines in the real formats (documentation IP
ranges, made-up hosts and users); no real server data.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from collector import collector, parsers
from collector.collector import Collector, DiscoveredLogSource, JournaldSource, OffsetStore, Tailer
from target_app import paths

SAMPLES = Path(__file__).resolve().parent / "samples"
SGT = parsers.log_tz("+08:00")


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("CACTAI_LOG_TZ", "+08:00")
    monkeypatch.setenv("CACTAI_HOST", "vps-real")
    monkeypatch.setenv("CACTAI_COLLECTOR_STATE", str(tmp_path / "state.json"))


def lines(name: str) -> list[str]:
    return (SAMPLES / name).read_text(encoding="utf-8").splitlines()


# ------------------------------------------------------------------ nginx

def test_nginx_access_lines_become_http_fields():
    parsed = [parsers.parse_line(ln, "nginx") for ln in lines("nginx_access.log")]
    assert all(parsed), "every sample access line parses"
    env = parsed[2]
    assert (env.src_ip, env.ts) == ("203.0.113.9", "2026-09-28T14:02:11+08:00")
    assert env.fields.items() >= {"format": "nginx_access", "kind": "http_request", "method": "GET", "path": "/.env",
                               "status": 404, "bytes": 153, "user_agent": "Mozilla/5.0 zgrab/0.x"}.items()
    assert [p.fields["path"] for p in parsed[3:6]] == ["/.git/config", "/wp-login.php", "/phpmyadmin/index.php"]


def test_nginx_scanner_junk_is_marked_malformed():
    tls, empty = (parsers.parse_line(ln, "nginx") for ln in lines("nginx_access.log")[7:9])
    assert tls.fields["malformed_request"] and tls.fields["method"] is None and tls.fields["status"] == 400
    assert empty.fields["malformed_request"] and empty.fields["request"] is None


def test_nginx_query_user_extras_and_escaped_quotes():
    sqli, auth, quoted = (parsers.parse_line(ln, "nginx") for ln in lines("nginx_access.log")[9:12])
    assert sqli.fields["path"] == "/search" and sqli.fields["query"] == "q=1%27%20OR%20%271%27=%271"
    assert sqli.fields["user_agent"].startswith("sqlmap/")
    assert auth.user == "admin" and auth.fields["status"] == 401 and auth.fields["protocol"] == "HTTP/2.0"
    assert quoted.fields["user_agent"] == 'Agent with "quotes" inside'


def test_nginx_error_log_has_client_and_request():
    first, ssl = (parsers.parse_line(ln, "nginx") for ln in lines("nginx_error.log"))
    assert first.src_ip == "203.0.113.9" and first.ts == "2026-09-28T14:02:11+08:00"
    assert first.fields.items() >= {"format": "nginx_error", "level": "error", "method": "GET", "path": "/.env"}.items()
    assert ssl.src_ip == "198.51.100.4" and ssl.fields["level"] == "crit"


# ------------------------------------------------------------------ sshd

SSHD_EXPECTED = [  # (ssh_event, src_ip, user, invalid_user, outcome) per auth.log sample line
    ("accepted", "192.0.2.10", "deploy", False, "success"),
    ("session_opened", None, "deploy", False, "success"),
    ("invalid_user", "203.0.113.50", "oracle", True, "failure"),
    ("pam_check_pass", None, None, False, "failure"),
    ("auth_failure_pam", "203.0.113.50", None, False, "failure"),
    ("failed_auth", "203.0.113.50", "oracle", True, "failure"),
    ("connection_closed", "203.0.113.50", "oracle", True, "info"),
    ("auth_failure_pam", "203.0.113.50", "root", False, "failure"),
    ("failed_auth", "203.0.113.50", "root", False, "failure"),
    ("failed_auth", "203.0.113.50", "root", False, "failure"),
    ("max_auth_exceeded", "203.0.113.50", "root", False, "failure"),
    ("disconnecting", "203.0.113.50", "root", False, "info"),
    ("auth_failures_more", "203.0.113.50", "root", False, "failure"),
    ("invalid_user", "203.0.113.51", None, True, "failure"),
    ("disconnected", "203.0.113.51", None, True, "info"),
    ("received_disconnect", "203.0.113.52", None, False, "info"),
    ("connection_reset", "203.0.113.53", "admin", False, "info"),
    ("banner_error", "203.0.113.54", None, False, "info"),
    ("negotiation_failed", "203.0.113.55", None, False, "info"),
    ("no_identification", "203.0.113.56", None, False, "info"),
    ("banner_error", None, None, False, "info"),
    ("connection_closed", "2001:db8::77", "ubuntu", False, "info"),
    ("disconnected", "192.0.2.10", "deploy", False, "info"),
    ("session_closed", None, "deploy", False, "info"),
]


def test_every_sshd_sample_line_is_recognised():
    got = [parsers.parse_line(ln, "syslog") for ln in lines("auth.log")]
    sshd = [p for p in got if p.fields["program"] == "sshd"]
    assert [(p.fields["ssh_event"], p.src_ip, p.user, p.fields["invalid_user"], p.fields["outcome"])
            for p in sshd] == SSHD_EXPECTED
    assert all(p.host == "vps-test" and p.ts.endswith("+08:00") for p in got)
    failed = sshd[8]
    assert failed.fields["auth_method"] == "password" and failed.fields["port"] == 51240
    assert sshd[6].fields["preauth"] is True
    cron = got[-1]
    assert cron.fields["program"] == "CRON" and cron.fields["kind"] == "log" and "ssh_event" not in cron.fields


def test_rsyslog_iso_timestamps_and_sshd_session():
    p = parsers.parse_line("2026-09-28T06:02:17.123456+00:00 vps-test sshd-session[99]: "
                           "Failed password for root from 203.0.113.63 port 40003 ssh2")
    assert p.ts == "2026-09-28T06:02:17+00:00" and p.fields["ssh_event"] == "failed_auth"
    assert p.fields["program"] == "sshd-session" and p.src_ip == "203.0.113.63"


def test_syslog_year_rolls_back_for_december_lines_read_in_january():
    now = datetime(2027, 1, 1, 0, 5, tzinfo=SGT)
    p = parsers.parse_line("Dec 31 23:59:58 vps-test sshd[1]: Invalid user a from 203.0.113.1 port 1", now=now)
    assert p.ts == "2026-12-31T23:59:58+08:00"


@pytest.mark.parametrize("name,expected", [("UTC", "+00:00"), ("-05:30", "-05:30"), ("Asia/Singapore", "+08:00")])
def test_log_timezone_setting(name, expected):
    try:
        tz = parsers.log_tz(name)
    except Exception:  # pragma: no cover
        pytest.skip("no tz database")
    if name == "Asia/Singapore" and tz.utcoffset(datetime(2026, 9, 28)) is None:
        pytest.skip("no tz database")
    p = parsers.parse_line("Sep 28 14:02:11 h sshd[1]: Invalid user a from 203.0.113.1 port 1", tz=tz,
                           now=datetime(2026, 9, 28, tzinfo=timezone.utc))
    assert p.ts == f"2026-09-28T14:02:11{expected}"


def test_journald_json_lines():
    got = [parsers.parse_journald(ln) for ln in lines("journal.jsonl")]
    assert [(p.fields["ssh_event"], p.src_ip, p.user) for p in got] == [
        ("invalid_user", "203.0.113.60", "test"), ("failed_auth", "203.0.113.60", "test"),
        ("accepted", "192.0.2.20", "alice")]
    assert got[0].ts == "2026-09-28T14:02:01+08:00" and got[0].host == "vps-journal"
    assert got[0].fields["unit"] == "ssh.service" and got[2].extra["cursor"] == "s=abc;i=3"
    raw_bytes = json.dumps({"MESSAGE": list(b"Invalid user x from 203.0.113.9 port 1"), "SYSLOG_IDENTIFIER": "sshd"})
    assert parsers.parse_journald(raw_bytes).src_ip == "203.0.113.9"


def test_unknown_lines_are_not_parsed():
    for ln in ("hello world", '{"ts": "x"}', "GET /a 200", ""):
        assert parsers.parse_line(ln) is None


# ------------------------------------------------------------------ events

def test_server_log_events_carry_real_time_host_and_fields(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("\n".join(lines("nginx_access.log")) + "\n")
    events = DiscoveredLogSource(log, "web", "text").poll()
    assert len(events) == 12
    ev = events[2]
    assert ev["timestamp"] == "2026-09-28T14:02:11+08:00" and ev["host"] == "vps-real"
    assert ev["src_ip"] == "203.0.113.9" and ev["raw"] == lines("nginx_access.log")[2]
    assert ev["parsed"]["path"] == "/.env" and ev["parsed"]["status"] == 404
    auth = tmp_path / "auth.log"
    auth.write_text("\n".join(lines("auth.log")) + "\n")
    ev = DiscoveredLogSource(auth, "os", "syslog").poll()[2]
    assert ev["host"] == "vps-test" and ev["user"] == "oracle" and ev["parsed"]["ssh_event"] == "invalid_user"


def test_unparsed_text_lines_still_guess_ip_and_user(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("login failed user=amy from 198.51.100.8\n")
    ev = DiscoveredLogSource(log, "web").poll()[0]
    assert ev["src_ip"] == "198.51.100.8" and ev["user"] == "amy" and ev["parsed"] == {"format": "text", "kind": "log"}


def test_demo_portal_events_keep_their_shape():
    ev = collector.normalize(paths.ACCESS_LOG, {"ts": "2026-09-29T14:00:03+08:00", "src_ip": "203.0.113.45",
                                                "method": "POST", "path": "/login", "status": 401,
                                                "raw": "POST /login 401 user=admin"})
    assert ev["host"] == "web-01" and ev["raw"] == "POST /login 401 user=admin"
    assert ev["parsed"] == {"format": "cactai_demo", "kind": "http_request", "method": "POST", "path": "/login",
                            "status": 401}


# ------------------------------------------------------------------ read positions

def test_partial_last_line_waits_for_its_newline(tmp_path):
    log = tmp_path / "a.log"
    log.write_bytes(b"one\ntw")
    t = Tailer(log)
    assert t.read_new_lines() == ["one"]
    with open(log, "ab") as fh:
        fh.write(b"o\n")
    assert t.read_new_lines() == ["two"]
    assert t.checkpoint()["pos"] == log.stat().st_size


def test_restart_resumes_from_saved_position(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("one\ntwo\n")
    t = Tailer(log)
    assert t.read_new_lines() == ["one", "two"]
    saved = t.checkpoint()
    with open(log, "a") as fh:
        fh.write("three\n")
    assert Tailer(log, saved).read_new_lines() == ["three"]


def test_rotation_while_running_reads_the_rest_of_the_old_file(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("one\n")
    t = Tailer(log)
    assert t.read_new_lines() == ["one"]
    with open(log, "a") as fh:
        fh.write("two\n")
    os.replace(log, tmp_path / "access.log.1")  # logrotate: rename, then nginx reopens a new file
    log.write_text("three\n")
    assert t.read_new_lines() == ["two", "three"]


def test_rotation_while_stopped_reads_old_rest_then_new_file(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("one\n")
    t = Tailer(log)
    t.read_new_lines()
    saved = t.checkpoint()
    with open(log, "a") as fh:
        fh.write("two\n")
    os.replace(log, tmp_path / "access.log.1")
    log.write_text("three\n")
    assert Tailer(log, saved).read_new_lines() == ["two", "three"]


def test_truncation_starts_again(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("one line that is long\n")
    t = Tailer(log)
    t.read_new_lines()
    saved = t.checkpoint()
    log.write_text("new\n")  # copytruncate
    assert Tailer(log, saved).read_new_lines() == ["new"]
    assert t.read_new_lines() == ["new"]


def test_first_look_reads_only_recent_history(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "BACKFILL", 20)
    log = tmp_path / "auth.log"
    log.write_text("".join(f"line {i:03d}\n" for i in range(100)))  # 9 bytes a line
    assert DiscoveredLogSource(log, "os").tailer.read_new_lines() == ["line 098", "line 099"]
    assert DiscoveredLogSource(log, "os", from_end=True).tailer.read_new_lines() == []


def test_unreadable_file_is_skipped_not_fatal(tmp_path, capsys):
    if os.name == "nt" or os.geteuid() == 0:
        pytest.skip("needs a non-root POSIX user")
    log = tmp_path / "auth.log"
    log.write_text("x\n")
    log.chmod(0)
    assert Tailer(log).read_new_lines() == []
    assert "cannot read" in capsys.readouterr().out


class _Resp:
    def raise_for_status(self):
        pass

    def json(self):
        return {"risk_index": 0}


def _collector_for(auth: Path, monkeypatch) -> Collector:
    from scout import sources

    sources.add({"path": str(auth), "layer": "os", "format": "syslog"}, "test")
    return Collector("http://127.0.0.1:9", auth.parent / "demo-logs")


def test_collector_restart_sends_nothing_twice(tmp_path, monkeypatch):
    auth = tmp_path / "auth.log"
    auth.write_text("\n".join(lines("auth.log")[:5]) + "\n")
    sent: list[dict] = []
    monkeypatch.setattr(collector.requests, "post", lambda url, json, timeout: (sent.extend(json), _Resp())[1])
    try:
        c = _collector_for(auth, monkeypatch)
        c.collect()
        assert c.flush()
        first = [e["raw"] for e in sent if e["source"] == "scout:auth.log"]
        assert len(first) == 5
        with open(auth, "a") as fh:
            fh.write(lines("auth.log")[5] + "\n")
        c2 = Collector("http://127.0.0.1:9", tmp_path / "demo-logs")  # restart
        sent.clear()
        c2.collect()
        c2.flush()
        assert [e["raw"] for e in sent if e["source"] == "scout:auth.log"] == [lines("auth.log")[5]]
    finally:
        from scout import sources
        Path(sources.sources_file()).unlink(missing_ok=True)


def test_positions_are_saved_only_after_core_accepts(tmp_path, monkeypatch):
    auth = tmp_path / "auth.log"
    auth.write_text(lines("auth.log")[2] + "\n")

    def down(*a, **k):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(collector.requests, "post", down)
    try:
        c = _collector_for(auth, monkeypatch)
        c.collect()
        assert not c.flush()
        c2 = Collector("http://127.0.0.1:9", tmp_path / "demo-logs")  # crash + restart before delivery
        c2.collect()
        assert [e["parsed"].get("ssh_event") for e in c2.pending if e["source"] == "scout:auth.log"] == ["invalid_user"]
    finally:
        from scout import sources
        Path(sources.sources_file()).unlink(missing_ok=True)


def test_offset_store_round_trip(tmp_path):
    store = OffsetStore(tmp_path / "s" / "state.json")
    store.save({"/var/log/auth.log": {"pos": 10}})
    assert OffsetStore(tmp_path / "s" / "state.json").get("/var/log/auth.log") == {"pos": 10}


# ------------------------------------------------------------------ journald + setup

def _fake_journalctl(tmp_path: Path) -> list[str]:
    script = tmp_path / "fake_journalctl.py"
    script.write_text(f"import sys\nsys.stdout.write(open({str(SAMPLES / 'journal.jsonl')!r}).read())\n")
    return [sys.executable, str(script)]


def test_journald_source_reads_and_remembers_cursor(tmp_path):
    src = JournaldSource(command=_fake_journalctl(tmp_path))
    events: list[dict] = []
    import time
    for _ in range(100):
        events += src.poll()
        if len(events) >= 3:
            break
        time.sleep(0.02)
    assert [e["parsed"]["ssh_event"] for e in events] == ["invalid_user", "failed_auth", "accepted"]
    assert events[0]["host"] == "vps-journal" and events[0]["source"] == "journald:sshd"
    assert events[0]["raw"] == "Invalid user test from 203.0.113.60 port 52000"
    assert src.checkpoint() == {"cursor": "s=abc;i=3"}
    resumed = JournaldSource(saved=src.checkpoint())
    assert resumed.command()[-5:-3] == ["--after-cursor", "s=abc;i=3"]
    assert "--lines" in JournaldSource(from_end=True).command()


def test_journald_entry_in_sources_json():
    src = collector.source_for({"path": "journald:sshd", "layer": "os", "format": "journald"})
    assert isinstance(src, JournaldSource) and src.key == "journald:sshd"


def test_system_log_entries(tmp_path):
    (tmp_path / "var/log/nginx").mkdir(parents=True)
    (tmp_path / "var/log/nginx/access.log").write_text("")
    (tmp_path / "var/log/secure").write_text("")
    got = collector.system_log_entries(tmp_path, has_journalctl=True)
    assert [(Path(e["path"]).name, e["format"]) for e in got] == [("access.log", "nginx"), ("secure", "syslog")]
    (tmp_path / "var/log/secure").unlink()
    assert collector.system_log_entries(tmp_path, has_journalctl=True)[-1]["path"] == "journald:sshd"
    assert [e["format"] for e in collector.system_log_entries(tmp_path, has_journalctl=False)] == ["nginx"]
