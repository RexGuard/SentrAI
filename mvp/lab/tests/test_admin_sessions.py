"""Administrators' sessions: sudo, su and systemd-logind lines, the key an SSH sign-in used, and the
sign-in poll (``who`` on Linux and macOS, ``quser`` on Windows) that tells the core who is signed in.

All lines are synthetic (documentation address ranges, made-up hosts, the contract's example key).
"""
from __future__ import annotations

import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import pytest

from collector import collector, parsers
from collector.collector import DiscoveredLogSource, HeartbeatSource, JournaldSource, SessionSource

SAMPLES = Path(__file__).resolve().parent / "samples"
SGT = parsers.log_tz("+08:00")
NOON = datetime(2026, 10, 28, 12, 0, tzinfo=SGT)
KEY = "SHA256:Q7w3cZk2u5Yd9bJm1LxkfA0Hn6Rr8PtEoSvNqGiCz4U"
KEY2 = "SHA256:Zz9x8c7v6b5n4m3L2k1j0h9g8f7d6s5a4p3o2i1u0y9T"
WIPE = "/usr/bin/systemctl stop sentrai-core"

WHO = """\
erick    pts/0        2026-10-28 10:21 (203.0.113.5)
erick    tty1         2026-10-28 09:00
root     pts/1        2026-10-28 10:30 (web-02)
erick    :0           2026-10-28 08:00 (:0)
"""
QUSER = """\
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>erick                 console             1  Active      none   10/28/2026 10:21 AM
 helpdesk              rdp-tcp#3           2  Active         .   10/28/2026 10:30 AM
 guest                                     3  Disc        1:05   10/28/2026 9:00 AM
"""


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTRAI_LOG_TZ", "+08:00")
    monkeypatch.setenv("SENTRAI_HOST", "web-01")
    monkeypatch.setenv("SENTRAI_COLLECTOR_STATE", str(tmp_path / "state.json"))


def syslog(msg: str) -> parsers.Parsed:
    p = parsers.parse_line(f"Oct 28 10:21:00 web-01 {msg}", "syslog", tz=SGT, now=NOON)
    assert p is not None, msg
    return p


def sudo_fields(p: parsers.Parsed) -> tuple:
    f = p.fields
    return (f["sudo_event"], f["by"], f["target_user"], f["tty"], f["command"], f["outcome"], f["count"])


class Clock:
    """A clock the tests move by hand."""

    def __init__(self, t: float = 1_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def fake_who(outputs: list[str]):
    """A command runner that answers with the next `who` output each time it is called."""
    calls: list[list[str]] = []

    def run(cmd: list[str]) -> tuple[int, str, str]:
        calls.append(cmd)
        return 0, outputs[min(len(calls), len(outputs)) - 1], ""

    run.calls = calls  # type: ignore[attr-defined]
    return run


# ------------------------------------------------------------------ sudo

@pytest.mark.parametrize("msg,expected", [
    (f"sudo:    erick : TTY=pts/0 ; PWD=/home/erick ; USER=root ; COMMAND={WIPE}",
     ("command", "erick", "root", "pts/0", WIPE, "success", None)),
    ("sudo:  erick : TTY=pts/0 ; PWD=/home/erick ; USER=root ; COMMAND=/usr/bin/apt update",  # the core's own form
     ("command", "erick", "root", "pts/0", "/usr/bin/apt update", "success", None)),
    ("sudo[3100]: deploy : TTY=unknown ; PWD=/srv ; USER=postgres ; GROUP=postgres ; ENV=PGUSER=x ; COMMAND=/usr/bin/psql",
     ("command", "deploy", "postgres", None, "/usr/bin/psql", "success", None)),
    ("sudo:    guest : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/guest ; USER=root ; COMMAND=/bin/bash",
     ("not_in_sudoers", "guest", "root", "pts/1", "/bin/bash", "failure", None)),
    ("sudo:   deploy : command not allowed ; TTY=pts/2 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/bash",
     ("not_allowed", "deploy", "root", "pts/2", "/usr/bin/bash", "failure", None)),
    ("sudo:    erick : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/erick ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
     ("wrong_password", "erick", "root", "pts/0", "/usr/bin/cat /etc/shadow", "failure", 3)),
    ("sudo:    erick : a password is required ; TTY=pts/0 ; PWD=/home/erick ; USER=root ; COMMAND=/usr/bin/id",
     ("refused", "erick", "root", "pts/0", "/usr/bin/id", "failure", None)),
    ("sudo: pam_unix(sudo:session): session opened for user root(uid=0) by erick(uid=1000)",
     ("session_opened", "erick", "root", None, None, "info", None)),
    ("sudo: pam_unix(sudo:session): session closed for user root",
     ("session_closed", None, "root", None, None, "info", None)),
    ("sudo: pam_unix(sudo:auth): authentication failure; logname=erick uid=1000 euid=0 tty=/dev/pts/0 ruser=erick rhost=  user=erick",
     ("auth_failure", "erick", "erick", "pts/0", None, "failure", None)),
    ("sudo: unable to resolve host web-01: Name or service not known",
     ("other", None, None, None, None, "info", None)),
])
def test_sudo_lines(msg, expected):
    p = syslog(msg)
    assert p.fields["kind"] == "sudo" and p.fields["program"] == "sudo" and p.fields["format"] == "syslog"
    assert sudo_fields(p) == expected
    assert p.user == expected[1]  # the account that ran sudo, never "root" from USER=root
    assert p.src_ip is None and p.host == "web-01" and p.ts == "2026-10-28T10:21:00+08:00"


def test_sudo_parsed_object_has_exactly_the_contract_fields():
    p = syslog(f"sudo:    erick : TTY=pts/0 ; PWD=/home/erick ; USER=root ; COMMAND={WIPE}")
    assert set(p.fields) == {"format", "program", "pid", "message", "kind", "sudo_event", "by", "target_user", "tty",
                             "command", "outcome", "count"}


# ------------------------------------------------------------------ su

@pytest.mark.parametrize("msg,expected", [
    ("su: (to root) erick on pts/0", ("switched", "erick", "root", "pts/0", "success")),
    ("su[2200]: (to postgres) deploy on pts/3", ("switched", "deploy", "postgres", "pts/3", "success")),
    ("su: (to root) erick on none", ("switched", "erick", "root", None, "success")),
    ("su: FAILED SU (to root) guest on pts/1", ("failed", "guest", "root", "pts/1", "failure")),
    ("su[2200]: pam_unix(su:session): session opened for user root(uid=0) by erick(uid=1000)",
     ("session_opened", "erick", "root", None, "info")),
    ("su[2200]: pam_unix(su-l:session): session opened for user root by (uid=1000)",  # older PAM: no name
     ("session_opened", None, "root", None, "info")),
    ("su[2200]: pam_unix(su-l:session): session closed for user root", ("session_closed", None, "root", None, "info")),
    ("su: pam_unix(su:auth): authentication failure; logname=guest uid=1001 euid=0 tty=/dev/pts/1 ruser=guest rhost=  user=root",
     ("auth_failure", "guest", "root", "pts/1", "failure")),
    ("su-l[2300]: pam_unix(su-l:session): session opened for user root(uid=0) by erick(uid=1000)",
     ("session_opened", "erick", "root", None, "info")),
    ("su: pam_unix(su:auth): conversation failed", ("other", None, None, None, "info")),
])
def test_su_lines(msg, expected):
    p = syslog(msg)
    f = p.fields
    assert f["kind"] == "su" and f["program"] in ("su", "su-l")
    assert (f["su_event"], f["by"], f["target_user"], f["tty"], f["outcome"]) == expected
    assert p.user == expected[1]
    assert set(f) == {"format", "program", "pid", "message", "kind", "su_event", "by", "target_user", "tty", "outcome"}


# ------------------------------------------------------------------ systemd-logind

@pytest.mark.parametrize("msg,expected", [
    ("systemd-logind[812]: New session 5 of user erick.", ("started", "erick", "5")),
    ("systemd-logind[812]: New session c2 of user gdm.", ("started", "gdm", "c2")),
    ("systemd-logind[812]: Removed session 5.", ("ended", None, "5")),
    ("systemd-logind[812]: Session 5 logged out. Waiting for processes to exit.", ("ended", None, "5")),
])
def test_logind_session_lines(msg, expected):
    p = syslog(msg)
    f = p.fields
    assert f["kind"] == "login_session" and f["program"] == "systemd-logind"
    assert (f["session_event"], f["user"], f["session_id"]) == expected
    assert f["tty"] is None and f["origin"] is None and f["since"] is None
    assert p.user == expected[1]
    assert set(f) == {"format", "program", "pid", "message", "kind", "session_event", "user", "tty", "origin",
                      "session_id", "since"}


def test_other_logind_lines_are_plain_log_lines():
    p = syslog("systemd-logind[812]: Watching system buttons on /dev/input/event0 (Power Button)")
    assert p.fields["kind"] == "log" and "session_event" not in p.fields and p.user is None


# ------------------------------------------------------------------ sshd keys

def test_ssh_sign_in_with_a_key_names_it():
    p = syslog(f"sshd[4100]: Accepted publickey for erick from 203.0.113.5 port 51234 ssh2: ED25519 {KEY}")
    f = p.fields
    assert (f["ssh_event"], f["auth_method"], f["key_type"], f["key_fingerprint"]) == ("accepted", "publickey", "ED25519", KEY)
    assert (p.user, p.src_ip, f["port"]) == ("erick", "203.0.113.5", 51234)
    rejected = syslog(f"sshd[4101]: Failed publickey for erick from 203.0.113.5 port 51235 ssh2: RSA {KEY2}").fields
    assert (rejected["ssh_event"], rejected["auth_method"], rejected["key_type"], rejected["key_fingerprint"]) == \
        ("failed_auth", "publickey", "RSA", KEY2)
    cert = syslog(f"sshd[4102]: Accepted publickey for erick from 203.0.113.5 port 51236 ssh2: ED25519-CERT {KEY} "
                  f"ID erick (serial 42) CA ED25519 {KEY2}").fields
    assert (cert["key_type"], cert["key_fingerprint"]) == ("ED25519-CERT", KEY)


def test_ssh_sign_ins_without_a_key_leave_the_key_fields_empty():
    password = syslog("sshd[4103]: Accepted password for erick from 203.0.113.6 port 51237 ssh2").fields
    assert (password["auth_method"], password["key_type"], password["key_fingerprint"]) == ("password", None, None)
    kbd = syslog("sshd[4104]: Accepted keyboard-interactive/pam for erick from 203.0.113.7 port 51238 ssh2").fields
    assert (kbd["ssh_event"], kbd["auth_method"], kbd["key_fingerprint"]) == ("accepted", "keyboard-interactive/pam", None)
    old = syslog("sshd[4105]: Failed password for root from 203.0.113.8 port 51239 ssh2").fields
    assert (old["ssh_event"], old["key_type"], old["key_fingerprint"]) == ("failed_auth", None, None)


# ------------------------------------------------------------------ whole files: auth.log and journald

def test_auth_log_with_sudo_su_and_logind_becomes_events(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text((SAMPLES / "admin_auth.log").read_text(encoding="utf-8"), encoding="utf-8")
    events = DiscoveredLogSource(log, "os", "syslog").poll()
    assert len(events) == 19 and all(e["layer"] == "os" and e["host"] == "web-01" for e in events)
    kinds = [e["parsed"]["kind"] for e in events]
    assert kinds == ["ssh", "ssh", "login_session", "sudo", "sudo", "sudo", "sudo", "sudo", "sudo", "sudo", "sudo",
                     "su", "su", "su", "su", "su", "login_session", "login_session", "log"]
    wipe, firewall = events[3], events[6]
    assert wipe["user"] == "erick" and wipe["parsed"]["command"] == WIPE and wipe["parsed"]["tty"] == "pts/0"
    assert wipe["timestamp"] == "2026-10-28T10:21:00+08:00"
    # A command that names an address is not a line "from" that address: nothing is guessed for sudo lines.
    assert firewall["src_ip"] is None and firewall["user"] == "erick"
    assert [e["user"] for e in events[7:11]] == ["guest", "deploy", "guest", "guest"]
    assert events[12]["parsed"]["su_event"] == "session_opened" and events[12]["user"] == "erick"
    assert events[0]["parsed"]["key_fingerprint"] == KEY and events[0]["src_ip"] == "203.0.113.5"
    assert [e["parsed"]["session_event"] for e in (events[2], events[16], events[17])] == ["started", "ended", "ended"]


def test_journald_records_for_sudo_su_and_logind():
    got = [parsers.parse_journald(ln) for ln in (SAMPLES / "journal_admin.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [(p.fields["kind"], p.user) for p in got] == [
        ("sudo", "erick"), ("sudo", "erick"), ("su", "erick"), ("su", "erick"), ("login_session", "guest"),
        ("login_session", None), ("ssh", "erick")]
    sudo, logind, ssh = got[0], got[4], got[6]
    assert sudo.fields["sudo_event"] == "command" and sudo.fields["command"] == WIPE and sudo.fields["tty"] == "pts/0"
    assert sudo.fields["unit"] == "session-5.scope" and sudo.host == "vps-journal" and sudo.ts == "2026-10-28T10:21:01+08:00"
    assert logind.fields["session_event"] == "started" and logind.fields["session_id"] == "6"
    assert got[5].fields["session_event"] == "ended" and got[5].fields["session_id"] == "6"
    assert ssh.fields["key_fingerprint"] == KEY and ssh.src_ip == "203.0.113.5"


def _fake_journalctl(tmp_path: Path, sample: str) -> list[str]:
    script = tmp_path / "fake_journalctl.py"
    script.write_text(f"import sys\nsys.stdout.write(open({str(SAMPLES / sample)!r}).read())\n")
    return [sys.executable, str(script)]


def test_journald_source_reads_sudo_su_and_logind_lines(tmp_path):
    src = JournaldSource(command=_fake_journalctl(tmp_path, "journal_admin.jsonl"))
    events: list[dict] = []
    for _ in range(100):
        events += src.poll()
        if len(events) >= 7:
            break
        time.sleep(0.02)
    assert [e["parsed"]["kind"] for e in events] == ["sudo", "sudo", "su", "su", "login_session", "login_session", "ssh"]
    assert events[0]["raw"].strip() == f"erick : TTY=pts/0 ; PWD=/home/erick ; USER=root ; COMMAND={WIPE}"
    assert events[0]["user"] == "erick" and events[0]["src_ip"] is None and events[0]["source"] == "journald:sshd"
    assert events[4]["user"] == "guest" and events[6]["parsed"]["key_type"] == "ED25519"
    assert src.checkpoint() == {"cursor": "s=adm;i=7"}


def test_journald_source_matches_sshd_sudo_su_and_logind():
    src = JournaldSource()
    assert src.match == ["SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "SYSLOG_IDENTIFIER=sshd-auth",
                         "SYSLOG_IDENTIFIER=sudo", "SYSLOG_IDENTIFIER=su", "SYSLOG_IDENTIFIER=su-l",
                         "SYSLOG_IDENTIFIER=systemd-logind"]
    cmd = src.command()
    assert cmd[:5] == ["journalctl", "-o", "json", "--no-pager", "--follow"] and cmd[-7:] == src.match
    assert src.name == src.source == "journald:sshd"  # the sources.json entry and the event source are unchanged
    # An entry with its own match list keeps it.
    own = collector.source_for({"path": "journald:sshd", "format": "journald", "layer": "os",
                                "match": ["SYSLOG_IDENTIFIER=sshd"]})
    assert own.match == ["SYSLOG_IDENTIFIER=sshd"]
    why = collector.system_log_entries(Path("/nonexistent-root"), has_journalctl=True, windows=False)[-1]["why"]
    assert "sudo" in why and "sign-in sessions" in why


# ------------------------------------------------------------------ the sign-in poll: who

def test_who_output_is_parsed_with_this_computers_offset():
    sessions = parsers.parse_who(WHO, SGT)
    assert sessions == [
        {"user": "erick", "tty": "pts/0", "origin": "203.0.113.5", "session_id": None, "since": "2026-10-28T10:21:00+08:00"},
        {"user": "erick", "tty": "tty1", "origin": None, "session_id": None, "since": "2026-10-28T09:00:00+08:00"},
        {"user": "root", "tty": "pts/1", "origin": "web-02", "session_id": None, "since": "2026-10-28T10:30:00+08:00"},
        {"user": "erick", "tty": ":0", "origin": ":0", "session_id": None, "since": "2026-10-28T08:00:00+08:00"}]
    # Without a zone given, the time carries the local offset of that moment.
    local = parsers.parse_who("erick    pts/0        2026-10-28 10:21 (203.0.113.5)")[0]["since"]
    assert local == datetime(2026, 10, 28, 10, 21).astimezone().isoformat(timespec="seconds")
    assert len(local) == 25 and local[19] in "+-"
    # macOS and BSD write no year: this year, or last year for a December line read in January.
    bsd = parsers.parse_who("erick    ttys000  Oct 28 10:21 (203.0.113.5)\nbob      console  Dec 31 23:50\n", SGT,
                            now=datetime(2027, 1, 1, 0, 5, tzinfo=SGT))
    assert [s["since"] for s in bsd] == ["2026-10-28T10:21:00+08:00", "2026-12-31T23:50:00+08:00"]
    assert bsd[0]["origin"] == "203.0.113.5" and bsd[1]["origin"] is None
    assert parsers.parse_who("", SGT) == [] and parsers.parse_who("who: cannot open /var/run/utmp\n", SGT) == []


def test_session_poll_reports_existing_then_started_and_ended():
    clock = Clock()
    run = fake_who([WHO, WHO.replace("root     pts/1        2026-10-28 10:30 (web-02)\n", "")
                    + "alice    pts/2        2026-10-28 10:40 (198.51.100.20)\n"])
    src = SessionSource(windows=False, run=run, tz=SGT, clock=clock)
    assert src.key is None and src.source == "sessions"
    first = src.poll()
    assert run.calls == [["who"]]
    assert [e["raw"] for e in first] == [
        "session existing: erick on pts/0 from 203.0.113.5 since 2026-10-28T10:21:00+08:00",
        "session existing: erick on tty1 since 2026-10-28T09:00:00+08:00",
        "session existing: root on pts/1 from web-02 since 2026-10-28T10:30:00+08:00",
        "session existing: erick on :0 from :0 since 2026-10-28T08:00:00+08:00"]
    ev = first[0]
    assert ev["source"] == "sessions" and ev["layer"] == "os" and ev["host"] == "web-01"
    assert ev["user"] == "erick" and ev["src_ip"] == "203.0.113.5" and ev["asset_criticality"] == 1.0
    assert ev["parsed"] == {"format": "who", "kind": "login_session", "session_event": "existing", "user": "erick",
                            "tty": "pts/0", "origin": "203.0.113.5", "session_id": None,
                            "since": "2026-10-28T10:21:00+08:00"}
    # A host name or a display is kept as the origin, but is not an address to block.
    assert first[1]["src_ip"] is None and first[1]["parsed"]["origin"] is None
    assert first[2]["src_ip"] is None and first[2]["parsed"]["origin"] == "web-02"
    assert first[3]["src_ip"] is None and first[3]["parsed"]["origin"] == ":0"
    # Within the 15 s interval nothing runs; after it, only the changes are sent.
    clock.t += 5
    assert src.poll() == [] and run.calls == [["who"]]
    clock.t += 10
    changes = src.poll()
    assert len(run.calls) == 2
    assert [e["raw"] for e in changes] == [
        "session ended: root on pts/1 from web-02 since 2026-10-28T10:30:00+08:00",
        "session started: alice on pts/2 from 198.51.100.20 since 2026-10-28T10:40:00+08:00"]
    assert changes[0]["parsed"]["session_event"] == "ended" and changes[0]["user"] == "root"
    assert changes[1]["parsed"]["session_event"] == "started" and changes[1]["src_ip"] == "198.51.100.20"
    clock.t += 15
    assert src.poll() == []  # nothing changed


def test_same_terminal_used_again_is_a_new_session():
    clock = Clock()
    again = "erick    pts/0        2026-10-28 11:05 (203.0.113.5)\n"
    src = SessionSource(windows=False, run=fake_who([WHO.splitlines()[0] + "\n", again]), tz=SGT, clock=clock)
    src.poll()
    clock.t += 15
    assert [e["raw"] for e in src.poll()] == [
        "session ended: erick on pts/0 from 203.0.113.5 since 2026-10-28T10:21:00+08:00",
        "session started: erick on pts/0 from 203.0.113.5 since 2026-10-28T11:05:00+08:00"]


def test_open_sessions_are_reported_again_about_once_an_hour():
    clock = Clock()
    two = "".join(WHO.splitlines(keepends=True)[:2])
    # Four polls see the same two sign-ins (start, +30 min, +1 h, +1 h 15 s); alice signs in before the fifth.
    src = SessionSource(windows=False,
                        run=fake_who([two] * 4 + [two + "alice    pts/2        2026-10-28 11:40 (198.51.100.20)\n"]),
                        tz=SGT, clock=clock)
    assert [e["parsed"]["session_event"] for e in src.poll()] == ["existing", "existing"]
    clock.t += 1800
    assert src.poll() == []  # half an hour on: nothing changed, nothing said
    clock.t += 1800
    again = src.poll()  # an hour on: both sign-ins are still open, so the core hears of them again
    assert [e["raw"] for e in again] == [
        "session existing: erick on pts/0 from 203.0.113.5 since 2026-10-28T10:21:00+08:00",
        "session existing: erick on tty1 since 2026-10-28T09:00:00+08:00"]
    clock.t += 15
    assert src.poll() == []
    clock.t += 3600
    mixed = src.poll()  # the next hour: a new sign-in is "started", the old ones "existing" (not both)
    assert [(e["parsed"]["session_event"], e["user"]) for e in mixed] == [("started", "alice"), ("existing", "erick"),
                                                                           ("existing", "erick")]


def test_missing_who_says_so_once_and_sends_nothing(capsys):
    def missing(cmd):
        raise FileNotFoundError(2, "No such file or directory", cmd[0])

    clock = Clock()
    src = SessionSource(windows=False, run=missing, tz=SGT, clock=clock)
    assert src.poll() == []
    clock.t += 15
    assert src.poll() == []
    out = capsys.readouterr().out
    assert out.count("cannot run who") == 1 and "not collected" in out


def test_failed_who_keeps_the_sessions_it_last_saw(capsys):
    answers = [(0, WHO, ""), (1, "", "who: cannot open /var/run/utmp"), (0, WHO, "")]
    clock = Clock()
    src = SessionSource(windows=False, run=lambda cmd: answers.pop(0), tz=SGT, clock=clock)
    assert len(src.poll()) == 4
    clock.t += 15
    assert src.poll() == []  # a failed run is not "everyone signed out"
    assert "who failed (exit 1)" in capsys.readouterr().out
    clock.t += 15
    assert src.poll() == []  # the same sessions as before: no change


def test_a_hung_command_is_skipped_this_time(capsys):
    answers = [(0, WHO, ""), subprocess.TimeoutExpired(["who"], 10), (0, "", "")]

    def run(cmd):
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a

    clock = Clock()
    src = SessionSource(windows=False, run=run, tz=SGT, clock=clock)
    assert len(src.poll()) == 4
    clock.t += 15
    assert src.poll() == [] and "did not answer" in capsys.readouterr().out
    clock.t += 15
    assert [e["parsed"]["session_event"] for e in src.poll()] == ["ended"] * 4  # it answered: everyone is gone


def test_run_command_returns_exit_code_and_output():
    code, out, err = collector.run_command([sys.executable, "-c", "import sys; print('hi'); sys.stderr.write('x'); sys.exit(3)"])
    assert (code, out.strip(), err.strip()) == (3, "hi", "x")
    with pytest.raises(OSError):
        collector.run_command(["sentrai-no-such-command-xyz"])


def test_default_sources_include_the_session_poll_unless_switched_off(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTRAI_SESSIONS", "on")
    names = [type(s).__name__ for s in collector.default_sources(tmp_path)]
    assert names[-2:] == ["SessionSource", "HeartbeatSource"]
    monkeypatch.setenv("SENTRAI_SESSIONS", "off")
    assert "SessionSource" not in [type(s).__name__ for s in collector.default_sources(tmp_path)]
    assert isinstance(collector.default_sources(tmp_path)[-1], HeartbeatSource)


# ------------------------------------------------------------------ the sign-in poll: quser (Windows)

def test_quser_output_uses_the_session_name_as_the_terminal():
    sessions = parsers.parse_quser(QUSER, SGT)
    assert sessions == [
        {"user": "erick", "tty": "console", "origin": None, "session_id": "1", "since": "2026-10-28T10:21:00+08:00"},
        {"user": "helpdesk", "tty": "rdp-tcp#3", "origin": None, "session_id": "2", "since": "2026-10-28T10:30:00+08:00"},
        {"user": "guest", "tty": "session-3", "origin": None, "session_id": "3", "since": "2026-10-28T09:00:00+08:00"}]
    # Other date orders (a British or German Windows) still give a time; an unknown one gives none.
    assert parsers.parse_quser(" guest  rdp-tcp#4  5  Active  1+02:03  28/10/2026 09:00\n", SGT)[0]["since"] == "2026-10-28T09:00:00+08:00"
    assert parsers.parse_quser(" guest  rdp-tcp#4  5  Active  1+02:03  28.10.2026 09:00\n", SGT)[0]["since"] == "2026-10-28T09:00:00+08:00"
    assert parsers.parse_quser(" guest  rdp-tcp#4  5  Active  1+02:03  Tuesday\n", SGT)[0]["since"] is None
    assert parsers.parse_quser("No User exists for *\n", SGT) == []


def test_windows_session_poll_runs_quser_and_reads_nobody_signed_in_as_ended():
    answers = [(0, QUSER, ""), (1, "", "No User exists for *\r\n")]
    calls: list[list[str]] = []

    def run(cmd):
        calls.append(cmd)
        return answers.pop(0)

    clock = Clock()
    src = SessionSource(windows=True, run=run, tz=SGT, clock=clock)
    events = src.poll()
    assert calls == [["quser"]] and src.format == "quser"
    assert [e["raw"] for e in events] == [
        "session existing: erick on console since 2026-10-28T10:21:00+08:00",
        "session existing: helpdesk on rdp-tcp#3 since 2026-10-28T10:30:00+08:00",
        "session existing: guest on session-3 since 2026-10-28T09:00:00+08:00"]
    assert events[1]["parsed"] == {"format": "quser", "kind": "login_session", "session_event": "existing",
                                   "user": "helpdesk", "tty": "rdp-tcp#3", "origin": None, "session_id": "2",
                                   "since": "2026-10-28T10:30:00+08:00"}
    assert all(e["src_ip"] is None and e["source"] == "sessions" and e["layer"] == "os" for e in events)
    clock.t += 15
    assert [e["parsed"]["session_event"] for e in src.poll()] == ["ended"] * 3  # "No User exists" is an empty list
