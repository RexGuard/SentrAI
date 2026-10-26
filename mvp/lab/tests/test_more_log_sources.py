"""More log sources: Windows Event Log, Suricata eve.json, MySQL/MariaDB, PostgreSQL and MongoDB.

The samples in ``tests/samples`` are synthetic lines in the real formats (documentation IP ranges,
made-up hosts and users); no real machine's data.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from collector import collector, parsers
from collector.collector import DiscoveredLogSource, WindowsEventSource

SAMPLES = Path(__file__).resolve().parent / "samples"


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTRAI_LOG_TZ", "+08:00")
    monkeypatch.setenv("SENTRAI_HOST", "vps-real")
    monkeypatch.setenv("SENTRAI_COLLECTOR_STATE", str(tmp_path / "state.json"))


def lines(name: str) -> list[str]:
    return (SAMPLES / name).read_text(encoding="utf-8").splitlines()


def tail(tmp_path, sample: str, fmt: str, layer: str) -> list[dict]:
    path = tmp_path / sample
    path.write_text((SAMPLES / sample).read_text(encoding="utf-8"), encoding="utf-8")
    return DiscoveredLogSource(path, layer, fmt).poll()


# ------------------------------------------------------------------ Windows Event Log

def test_wevtutil_xml_becomes_records_and_events():
    recs = parsers.winevent_from_xml((SAMPLES / "winevent_security.xml").read_text(encoding="utf-8"))
    assert [r["record_id"] for r in recs] == [1001, 1002, 1003, 1004]
    failed, service_logon, group, cleared = (parsers.winevent_parsed(r) for r in recs)
    assert (failed.src_ip, failed.user, failed.ts) == ("203.0.113.60", "WIN-SRV01\\Administrator", "2026-10-26T10:00:01+08:00")
    assert failed.fields.items() >= {"kind": "auth", "outcome": "failure", "service": "rdp", "program": "rdp",
                                     "logon_type": "remote_desktop", "status": "0xc000006a"}.items()
    assert service_logon is None  # a service signing in: never an attack signal, not sent at all
    assert group.fields["group"] == "Administrators" and group.user == "S-1-5-21-1-2-3-1009"
    assert cleared.fields["win_event"] == "log_cleared" and cleared.user == "Administrator"  # from UserData
    assert parsers.winevent_raw(failed).startswith("Windows Security 4625 logon_failed: user=WIN-SRV01\\Administrator ip=203.0.113.60")


def test_forwarded_windows_events_in_json():
    defender, service, sql, other = (parsers.parse_line(ln, "winevent") for ln in lines("winevent.jsonl"))
    assert defender.fields["threat"] == "Trojan:Win32/Meterpreter.A" and defender.host == "WIN-SRV01"
    assert "powershell" in service.fields["image_path"] and service.fields["service_name"] == "WinUpdSvc"
    assert (sql.src_ip, sql.user, sql.fields["service"]) == ("203.0.113.70", "sa", "mssql")
    assert sql.fields["reason"] == "Password did not match that for the login provided"
    assert other.extra["drop"]  # event 104 from another program is not "log cleared"


def test_windows_source_reads_new_records_and_resumes():
    xml = (SAMPLES / "winevent_security.xml").read_text(encoding="utf-8")
    calls = []

    def read(channel, xpath, reverse, limit):
        calls.append((channel, xpath, reverse, limit))
        return xml if len(calls) == 1 else "<Events></Events>"

    src = WindowsEventSource("Security", read=read)
    events = src.poll()
    assert [e["parsed"]["event_id"] for e in events] == [4625, 4732, 1102]
    assert events[0]["host"] == "vps-real" and events[0]["source"] == "winevent:Security"
    assert events[0]["src_ip"] == "203.0.113.60" and events[0]["layer"] == "os"
    assert src.checkpoint() == {"record_id": 1004}
    assert calls[0][0] == "Security" and calls[0][2:] == (True, 200)  # first look: the newest 200
    src._next = 0
    assert src.poll() == []
    assert "EventRecordID>1004" in calls[1][1] and "EventID=4625" in calls[1][1] and calls[1][2:] == (False, 500)
    again = WindowsEventSource("Security", saved=src.checkpoint(), read=read)
    assert "EventRecordID>1004" in again.query()[0]


def test_windows_source_approved_while_running_starts_at_the_end():
    xml = (SAMPLES / "winevent_security.xml").read_text(encoding="utf-8")
    src = WindowsEventSource("Security", from_end=True, read=lambda *a: xml)
    assert src.poll() == [] and src.record_id == 1004


def test_windows_source_without_rights_warns_once(capsys):
    def denied(*a):
        raise OSError(5, "Access is denied.")

    src = WindowsEventSource("Security", read=denied)
    assert src.poll() == []
    src._next = 0
    assert src.poll() == []
    assert capsys.readouterr().out.count("Event Log Readers") == 1


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows Event Log API is only on Windows")
def test_real_windows_event_log_api():
    from collector import wevtapi

    recs = parsers.winevent_from_xml(wevtapi.query("System", "*", reverse=True, limit=5))
    assert 0 < len(recs) <= 5 and all(r.get("record_id") and r.get("event_id") for r in recs)
    assert recs[0]["record_id"] > recs[-1]["record_id"]  # newest first
    with pytest.raises(OSError):
        wevtapi.query("No-Such-Channel/Operational", "*")
    src = WindowsEventSource("System", event_ids=[7036, 7040, 7045])  # service state changes: always some
    src.poll()
    assert src.record_id is not None


def test_winevent_entry_in_sources_json():
    src = collector.source_for({"path": "winevent:Microsoft-Windows-Windows Defender/Operational",
                                "format": "winevent", "layer": "os"})
    assert isinstance(src, WindowsEventSource) and src.key == "winevent:Microsoft-Windows-Windows Defender/Operational"
    assert src.event_ids == [1116, 1117]
    custom = collector.source_for({"path": "winevent:Security", "format": "winevent", "layer": "os",
                                   "event_ids": [4688]})
    assert custom.event_ids == [4688]


# ------------------------------------------------------------------ Suricata

def test_suricata_keeps_alerts_only(tmp_path):
    events = tail(tmp_path, "suricata_eve.json", "suricata", "network")
    assert len(events) == 4  # the flow and stats records are skipped
    scan, miner, sqli, notice = events
    assert scan["src_ip"] == "203.0.113.20" and scan["parsed"]["signature_id"] == 2001219
    assert scan["timestamp"] == "2026-10-26T10:00:02+08:00" and scan["host"] == "vps-real"
    # Traffic leaving the network: the outside address is the one to block, never this machine.
    assert miner["parsed"]["direction"] == "outbound" and miner["src_ip"] == "198.51.100.66"
    assert sqli["parsed"]["action"] == "blocked" and sqli["parsed"]["http_url"] == "/item?id=1 UNION SELECT"
    assert sqli["raw"].startswith("Suricata alert [blocked] ET WEB_SERVER Possible SQL Injection")
    assert notice["parsed"]["severity"] == 3


# ------------------------------------------------------------------ databases

def test_mysql_error_and_general_log(tmp_path):
    events = tail(tmp_path, "mysql_error.log", "mysql", "db")
    assert len(events) == 6  # the InnoDB note is skipped
    first, maria, aborted, old, connect, query = events
    assert (first["src_ip"], first["user"], first["timestamp"]) == ("203.0.113.30", "root", "2026-10-26T10:00:01+08:00")
    assert first["parsed"]["outcome"] == "failure" and first["asset_criticality"] == 1.5
    assert maria["user"] == "admin" and maria["parsed"]["auth_event"] == "access_denied"
    assert aborted["parsed"]["auth_event"] == "aborted_preauth" and aborted["user"] is None
    assert old["timestamp"] == "2026-10-26T10:00:05+08:00" and old["src_ip"] is None and old["user"] == "sa"
    # The query line has no address; it is the same thread as the Connect line, so it gets it.
    assert query["raw"] == "SELECT * FROM customers" and query["parsed"]["kind"] == "db_query"
    assert (query["src_ip"], query["user"]) == ("203.0.113.32", "shop")


def test_postgres_failures_get_the_client_from_connection_received(tmp_path):
    events = tail(tmp_path, "postgresql.log", "postgres", "db")
    kinds = [e["parsed"].get("auth_event") or e["parsed"]["kind"] for e in events]
    assert kinds == ["connection_received", "password_failed", "no_hba_entry", "no_such_role", "connected", "db_query"]
    failed = events[1]
    assert (failed["src_ip"], failed["user"], failed["parsed"]["outcome"]) == ("203.0.113.40", "postgres", "failure")
    assert events[2]["src_ip"] == "203.0.113.41" and events[2]["timestamp"] == "2026-10-26T10:00:02+08:00"
    assert events[3]["user"] == "oracle" and events[3]["parsed"]["invalid_user"]
    assert events[5]["raw"] == "SELECT id FROM orders WHERE id = 7"


def test_mongodb_sign_ins(tmp_path):
    events = tail(tmp_path, "mongod.log", "mongodb", "db")
    assert len(events) == 4  # the storage note is skipped
    assert [(e["src_ip"], e["user"], e["parsed"]["outcome"]) for e in events[1:]] == [
        ("203.0.113.50", "admin", "failure"), ("203.0.113.50", "root", "failure"), ("10.0.0.8", "app", "success")]


def test_other_formats_do_not_claim_each_others_lines():
    for line in lines("nginx_access.log")[:2] + lines("auth.log")[:2]:
        for fmt in ("suricata", "mysql", "postgres", "mongodb", "winevent"):
            assert parsers.parse_line(line, fmt) is None


# ------------------------------------------------------------------ setup

def test_service_logs_are_found_at_their_usual_places(tmp_path):
    for p in ("var/log/suricata/eve.json", "var/log/mysql/error.log", "var/log/postgresql/postgresql-16-main.log",
              "var/log/mongodb/mongod.log"):
        (tmp_path / p).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / p).write_text("")
    got = collector.system_log_entries(tmp_path, has_journalctl=False, windows=False)
    assert [(Path(e["path"]).name, e["layer"], e["format"]) for e in got] == [
        ("eve.json", "network", "suricata"), ("error.log", "db", "mysql"),
        ("postgresql-16-main.log", "db", "postgres"), ("mongod.log", "db", "mongodb")]


def test_a_log_folder_this_account_may_not_open_is_skipped(tmp_path, monkeypatch):
    # Ubuntu keeps /var/log/mysql as mysql:adm 2750; outside the adm group stat() fails there.
    (tmp_path / "var/log/nginx").mkdir(parents=True)
    (tmp_path / "var/log/nginx/access.log").write_text("")
    real = Path.is_file

    def is_file(self):
        if "mysql" in self.parts:
            raise PermissionError(13, "Permission denied", str(self))
        return real(self)

    monkeypatch.setattr(Path, "is_file", is_file)
    got = collector.system_log_entries(tmp_path, has_journalctl=False, windows=False)
    assert [Path(e["path"]).name for e in got] == ["access.log"]


def test_windows_gets_its_event_logs(tmp_path):
    got = collector.system_log_entries(tmp_path, windows=True)
    assert [e["path"] for e in got] == ["winevent:Security", "winevent:System", "winevent:Application",
                                        "winevent:Microsoft-Windows-Windows Defender/Operational"]
    assert all(e["format"] == "winevent" for e in got)
