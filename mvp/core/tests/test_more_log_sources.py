"""Rules for the newer log sources: Windows sign-ins and events, Suricata alerts, database sign-ins.

The events are shaped like the collector's (``parsed`` objects, see CONTRACT.md "Parsed fields");
documentation IP ranges and made-up accounts only.
"""

import pytest

from app.rules import RulesEngine

T0 = 1_790_000_000.0


def auth(n, service, outcome, ip="203.0.113.60", user="Administrator", fmt="winevent", event="logon_failed", sec=None):
    return {"event_id": f"a{n}", "timestamp": f"2026-10-26T10:{(sec if sec is not None else n) // 60:02d}:"
                                              f"{(sec if sec is not None else n) % 60:02d}+08:00",
            "host": "win-srv01", "layer": "os", "source": f"{fmt}:test", "src_ip": ip, "user": user,
            "raw": f"{service} {event} user={user} ip={ip}",
            "parsed": {"format": fmt, "kind": "auth", "service": service, "outcome": outcome, "auth_event": event}}


def win(n, win_event, **fields):
    return {"event_id": f"w{n}", "timestamp": "2026-10-26T10:00:00+08:00", "host": "win-srv01", "layer": "os",
            "source": "winevent:Security", "src_ip": None, "user": fields.pop("user", "helpdesk"),
            "raw": f"Windows Security {win_event}",
            "parsed": {"format": "winevent", "kind": "windows_event", "win_event": win_event, **fields}}


def alert(n, signature, category, severity=2, src="203.0.113.20", dest="10.0.0.5", direction="inbound", action="allowed"):
    remote = dest if direction == "outbound" else src
    return {"event_id": f"s{n}", "timestamp": "2026-10-26T10:00:00+08:00", "host": "sensor", "layer": "network",
            "source": "scout:eve.json", "src_ip": remote, "user": None, "raw": f"Suricata alert [{action}] {signature}",
            "parsed": {"format": "suricata", "kind": "network_alert", "signature": signature, "alert_category": category,
                       "severity": severity, "action": action, "src_ip": src, "dest_ip": dest, "dest_port": 22,
                       "direction": direction}}


@pytest.mark.parametrize("service,fmt,name", [("rdp", "winevent", "Remote Desktop"), ("mssql", "winevent", "SQL Server"),
                                              ("mysql", "mysql", "MySQL"), ("postgres", "postgres", "PostgreSQL"),
                                              ("mongodb", "mongodb", "MongoDB")])
def test_password_guessing_on_any_service_is_brute_force(service, fmt, name):
    r = RulesEngine()
    hits = [r.check(auth(i, service, "failure", fmt=fmt, sec=30 * i), T0) for i in range(5)]
    assert [h.category for h in hits[:4]] == ["benign"] * 4
    assert hits[4].category == "brute_force" and f"5 failed {name} sign-ins from 203.0.113.60" in hits[4].reason
    assert len(hits[4].related_event_ids) == 5


def test_guessed_password_then_success_is_flagged():
    r = RulesEngine()
    for i in range(5):
        r.check(auth(i, "rdp", "failure"), T0)
    hit = r.check(auth(9, "rdp", "success", event="logon", sec=20), T0)
    assert hit.category == "brute_force" and "SUCCEEDED after 5 failed attempts" in hit.reason


def test_a_typo_then_a_sign_in_is_benign():
    r = RulesEngine()
    r.check(auth(1, "postgres", "failure", fmt="postgres", ip="192.0.2.10", user="app"), T0)
    assert r.check(auth(2, "postgres", "success", fmt="postgres", ip="192.0.2.10", user="app"), T0).category == "benign"
    assert r.check(auth(3, "mysql", "info", fmt="mysql", event="aborted_preauth"), T0).category == "benign"


def test_failures_without_an_address_count_per_account():
    r = RulesEngine()
    hits = [r.check(auth(i, "ntlm", "failure", ip=None, user="svc-backup"), T0) for i in range(5)]
    assert hits[-1].category == "brute_force" and "svc-backup@win-srv01" in hits[-1].reason


def test_failures_spread_over_the_window_do_not_add_up():
    r = RulesEngine(ssh_window_s=600, ssh_slow_count=0)
    hits = [r.check(auth(i, "rdp", "failure", sec=200 * i), T0) for i in range(5)]  # one every 200 s
    assert all(h.category == "benign" for h in hits)


def test_windows_events_that_are_incidents():
    r = RulesEngine()
    assert r.check(win(1, "log_cleared", event_id=1102, log="Security"), T0).category == "log_tampering"
    hit = r.check(win(2, "group_member_added", group="Administrators", member="S-1-5-21-1009", by="helpdesk"), T0)
    assert hit.category == "privilege_escalation" and "'Administrators'" in hit.reason
    assert r.check(win(3, "group_member_added", group="Print Users", member="bob"), T0).category == "benign"
    hit = r.check(win(4, "malware_detected", threat="Trojan:Win32/Meterpreter.A", path="C:\\Users\\Public\\u.exe"), T0)
    assert hit.category == "malware" and "Meterpreter" in hit.reason
    assert r.check(win(5, "malware_action", threat="Trojan:Win32/Meterpreter.A"), T0).category == "benign"


@pytest.mark.parametrize("image,category", [
    ("%COMSPEC% /b /c start /b /min powershell -nop -w hidden -enc SQBFAFgA", "malware"),
    ("C:\\Users\\bob\\AppData\\Local\\Temp\\svc.exe", "malware"),
    ("%SystemRoot%\\PSEXESVC.exe", "malware"),
    ('"C:\\Program Files\\Backup Agent\\agent.exe" --service', "benign"),
    ("C:\\Windows\\System32\\svchost.exe -k netsvcs", "benign"),
])
def test_new_windows_services(image, category):
    hit = RulesEngine().check(win(1, "service_installed", event_id=7045, service_name="X", image_path=image), T0)
    assert hit.category == category


def test_windows_process_command_lines_go_through_the_text_rules():
    ev = win(1, "process_created", event_id=4688)
    ev["raw"] = "Windows Security 4688 process_created: cmdline=wevtutil cl Security"
    assert RulesEngine().check(ev, T0).category == "log_tampering"
    ev["raw"] = "Windows Security 4688 process_created: cmdline=notepad.exe report.txt"
    assert RulesEngine().check(ev, T0).category == "benign"


@pytest.mark.parametrize("signature,category,expected", [
    ("ET SCAN Potential SSH Scan", "Attempted Information Leak", "port_scan"),
    ("ET WEB_SERVER Possible SQL Injection Attempt SELECT FROM", "Web Application Attack", "sql_injection"),
    ("ET WEB_SERVER Script tag in URI Possible Cross Site Scripting Attempt", "Web Application Attack", "xss"),
    ("ET COINMINER Crypto Coin Miner Login", "Crypto Currency Mining Activity Detected", "malware"),
    ("ET MALWARE Win32/Agent Tesla CnC Checkin", "A Network Trojan was detected", "malware"),
    ("ET SCAN LibSSH Based Frequent SSH Connections Likely BruteForce Attack", "Attempted Administrator Privilege Gain",
     "brute_force"),
    ("ET EXPLOIT Apache log4j RCE Attempt", "Attempted Administrator Privilege Gain", "privilege_escalation"),
    ("ET WEB_SPECIFIC_APPS WordPress Plugin Exploit", "Web Application Attack", "port_scan"),
    ("SURICATA STREAM Packet with invalid ack", "Generic Protocol Command Decode", "benign"),
    ("ET POLICY curl User-Agent Outbound", "Attempted Information Leak", "port_scan"),
    ("ET INFO Observed DNS Query to .cloud TLD", "Potentially Bad Traffic", "benign"),
])
def test_suricata_alerts_map_to_categories(signature, category, expected):
    sev = 3 if expected == "benign" else 1
    assert RulesEngine().check(alert(1, signature, category, severity=sev), T0).category == expected


def test_unexplained_serious_suricata_alert_goes_to_the_classifier():
    assert RulesEngine().check(alert(1, "GPL MISC something odd", "Potentially Bad Traffic", severity=1), T0) is None


def test_outbound_alert_blames_the_outside_address(client):
    ev = alert(1, "ET MALWARE Win32/Agent Tesla CnC Checkin", "A Network Trojan was detected", severity=1,
               src="10.0.0.5", dest="198.51.100.66", direction="outbound")
    client.post("/events", json=[ev])
    incs = [i for i in client.get("/incidents").json() if i["category"] == "malware"]
    assert len(incs) == 1 and incs[0]["src_ip"] == "198.51.100.66"
    assert "to 198.51.100.66" in incs[0]["classification_reason"]


def test_database_queries_and_log_lines_are_read_by_the_text_rules():
    q = {"event_id": "q1", "timestamp": "2026-10-26T10:00:00+08:00", "host": "db-01", "layer": "db", "src_ip": "203.0.113.32",
         "source": "scout:postgresql.log", "raw": "SELECT id FROM orders WHERE id = 7",
         "parsed": {"format": "postgres", "kind": "db_query", "sql": "SELECT id FROM orders WHERE id = 7"}}
    r = RulesEngine()
    assert r.check(q, T0).category == "benign"
    q["raw"] = "SELECT * FROM orders WHERE id = '1' OR '1'='1'"
    assert r.check(q, T0).category == "sql_injection"
    q["raw"] = "SELECT * FROM customers"
    assert r.check(q, T0).category == "data_exfiltration"
    log = {**q, "raw": "could not receive data from client: Connection reset by peer",
           "parsed": {"format": "postgres", "kind": "log", "level": "log"}}
    assert r.check(log, T0).category == "benign"
