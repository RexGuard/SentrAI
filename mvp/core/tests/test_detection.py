"""Detection fixes: login bursts across log lines, reworded SQL injection, whole-table dumps, one-line
rules, changes that close access, and Countersign's two-signal rule for acting alone."""

import pytest

from app.agents import Needle, Proposal
from app.rules import RulesEngine


def e(n, raw, ip="203.0.113.45", source="flask_access", layer="web", sec=None, user="admin"):
    return {"event_id": f"evt-{n}", "timestamp": f"2026-10-23T10:00:{(sec if sec is not None else n) % 60:02d}+08:00",
            "source": source, "layer": layer, "src_ip": ip, "user": user, "raw": raw}


def test_auth_log_lines_join_the_burst_without_double_counting():
    r = RulesEngine()
    hits = []
    for i in range(5):
        hits.append(r.check(e(2 * i, "POST /login 401 user=admin", sec=4 * i), 0))
        hits.append(r.check(e(2 * i + 1, "login fail user=admin", source="flask_auth", sec=4 * i + 1), 0))
    # Counted on the access line only: the 5th access line (not the 3rd pair) opens the incident.
    assert [h.category for h in hits[:8]] == ["benign"] * 8
    assert hits[8].category == "brute_force" and "5 failed logins" in hits[8].reason
    # Every earlier line of the burst, from both logs, is attached to it.
    assert set(hits[8].related_event_ids) >= {f"evt-{n}" for n in range(9)}
    assert hits[9].category == "brute_force"  # the auth line of the 5th try joins the open burst


def test_slow_brute_force_over_a_day():
    r = RulesEngine(slow_count=6, slow_window_s=86400)
    hits = [r.check({"event_id": f"s{i}", "timestamp": f"2026-10-23T{i:02d}:00:00+08:00", "source": "windows_security",
                     "layer": "os", "src_ip": "203.0.113.60",
                     "raw": "EventID=4625 An account failed to log on. Account=administrator"}, 0) for i in range(6)]
    assert [h.category for h in hits[:5]] == ["benign"] * 5  # one an hour never trips the 60 s rule
    assert hits[5].category == "brute_force" and "slow brute force" in hits[5].reason
    assert len(hits[5].related_event_ids) == 6


@pytest.mark.parametrize("q", ["1 AND 1=1", "admin' #", "' uNiOn/**/SeLeCt null,version()--",
                               "x' AND extractvalue(1,concat(0x7e,database()))--"])
def test_reworded_sql_injection(q):
    hit = RulesEngine().check(e(1, f'SELECT rows=0 q="{q}"', source="db_query", layer="db"), 0)
    assert hit.category == "sql_injection"


@pytest.mark.parametrize("q", ["O'Brien", "select course", "union street campus", "#fff", "Grade 1 and 2", "C++ & Java"])
def test_ordinary_searches_stay_benign(q):
    hit = RulesEngine().check(e(1, f'SELECT rows=0 q="{q}"', source="db_query", layer="db"), 0)
    assert hit.category == "benign"


def test_a_search_for_sql_words_is_not_a_dump():
    hit = RulesEngine().check(e(1, "GET /search?q=select+*+from+users 200", source="flask_access"), 0)
    assert hit.category != "data_exfiltration"


def test_whole_sensitive_table_is_a_dump_at_any_size():
    r = RulesEngine()
    assert r.check(e(1, "SELECT rows=40 q='SELECT * FROM members'", source="db_query", layer="db"), 0).category \
        == "data_exfiltration"
    assert r.check(e(2, "SELECT rows=12 q='SELECT * FROM members WHERE program = ?'", source="db_query",
                     layer="db"), 0).category == "benign"
    assert r.check(e(3, "SELECT rows=8 q='SELECT * FROM courses'", source="db_query", layer="db"), 0).category == "benign"


@pytest.mark.parametrize("raw,category", [
    ("firewall: 214 connection attempts to 97 distinct ports from 203.0.113.9 in 10s", "port_scan"),
    ("kernel: TCP SYN to closed ports 21,22,23,25,80,110,139,443,445,3389 from 203.0.113.9", "port_scan"),
    ("blob container 'reports' access level changed to public (anonymous read)", "misconfiguration"),
    ("sudo: www-data : user NOT in sudoers ; TTY=pts/0 ; COMMAND=/bin/bash", "privilege_escalation"),
    ("s3 GetObject x 1840 objects (2.1 GB) bucket=aegis-student-docs by key AKIA...XYZ", "data_exfiltration"),
    # Closing access, or a page whose name has scary words, is not an attack.
    ("Security group sg-0a1 rule removed: ingress 0.0.0.0/0 tcp 3389", "benign"),
    ("PutBucketAcl bucket=aegis-student-docs acl=private by user=it-admin", "benign"),
    ("GET /help/download all course notes 200", "benign"),
    ("firewall: 3 connection attempts to 2 distinct ports from 192.0.2.10 in 10s", "benign"),
    ("nginx: listening on ports 80,443,8080,8443,3000", "benign"),
    ("nightly backup finished (12 GB) to /backup", "benign"),
    ("ufw: deny rule deleted: 0.0.0.0/0 tcp 22", "misconfiguration"),
    ("sudo: alice : user NOT in sudoers ; TTY=pts/0 ; COMMAND=/usr/bin/apt update", "benign"),
])
def test_one_line_rules(raw, category):
    hit = RulesEngine().check(e(1, raw, source="handcrafted", layer="os"), 0)
    assert (hit.category if hit else "benign") == category


def _incident(**kw):
    base = {"id": "RSK-1", "ai_confidence": 0.75, "needs_review": False, "classified_by": "fallback",
            "severity": "critical", "points": 60, "malicious_probability": 0.75}
    return {**base, **kw}


def test_countersign_needs_a_strong_signal_or_two_weak_ones():
    n = Needle(0.6, {"block_ip"}, set())
    p = [Proposal("block_ip", "203.0.113.45", "test")]
    weak = n.review(_incident(strong_signal=False, signals=["fallback:db_query"]), p, 90, 80)
    assert not weak.approved and "one weak signal" in weak.reasoning
    two = n.review(_incident(strong_signal=False, signals=["fallback:db_query", "fallback:flask_access"]), p, 90, 80)
    assert two.approved
    rule = n.review(_incident(strong_signal=True, signals=["rules:flask_access"], ai_confidence=1.0,
                              classified_by="rules"), p, 90, 80)
    assert rule.approved


def test_incident_records_its_signals(client):
    from tests.conftest import brute_force
    brute_force(client)
    [inc] = client.get("/incidents").json()
    assert inc["strong_signal"] is True and inc["signals"] == ["rules:flask_auth"]
