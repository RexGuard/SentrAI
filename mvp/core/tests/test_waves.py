"""Busy servers: many addresses doing the same attack become one wave (one alert, a summary, a capped
share of the risk index), and trusted addresses are never analysed."""

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.waves import network_of, wave_points

from .conftest import AUTH, ev


@pytest.fixture
def make_client(tmp_path):
    def make(**kw):
        s = Settings(db_path=tmp_path / "sentrai.db", background=False, demo_speed=60.0, **kw)
        app = create_app(s)
        c = TestClient(app, headers=AUTH)
        c.core = app.state.core  # type: ignore[attr-defined]
        return c
    return make


def scan(n, ip, host="game-01"):
    """One line from a scanner: a scanner's user agent makes it a port or web scan on its own."""
    return {"event_id": f"scan-{n}", "source": "nginx_access", "layer": "web", "host": host,
            "raw": f'{ip} - - [28/Oct/2026:14:00:{n % 60:02d} +0000] "GET /.env HTTP/1.1" 404 153 "-" "zgrab/0.x"'}


def scanners(c, count, start=0, host="game-01"):
    c.post("/events", json=[scan(start + i, f"198.51.{(start + i) // 4}.{start + i}", host) for i in range(count)])


def kinds(c):
    return [n["kind"] for n in c.core.notifications]


BUSY = dict(busy_server=True, wave_min_addresses=10, wave_window_min=15.0, wave_update_min=15.0)


def test_off_by_default_every_address_is_its_own_alert(make_client):
    c = make_client()
    scanners(c, 12)
    assert c.core.waves.enabled is False
    assert c.get("/waves").json() == []
    assert kinds(c).count("incident_opened") == 12


def test_settings_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("BUSY_SERVER", "on")
    s = Settings()
    assert s.busy_server and s.wave_min_addresses == 10
    monkeypatch.setenv("WAVE_MIN_ADDRESSES", "0")
    assert Settings().wave_min_addresses == 0
    monkeypatch.delenv("BUSY_SERVER")
    monkeypatch.delenv("WAVE_MIN_ADDRESSES")
    assert Settings().wave_min_addresses == 0


def test_tenth_scanner_starts_a_wave_and_the_rest_are_folded(make_client):
    c = make_client(**BUSY)
    scanners(c, 9)
    assert kinds(c).count("incident_opened") == 9 and c.get("/waves").json() == []
    scanners(c, 41, start=9)
    [wave] = c.get("/waves").json()
    assert wave["id"] == "WAVE-001" and wave["category"] == "port_scan" and wave["host"] == "game-01"
    assert wave["addresses"] == 50 and len(wave["incidents"]) == 50 and wave["active"]
    assert wave["networks"][0]["addresses"] == 4  # four addresses in each /24 of the test data
    # Every address keeps its own incident, marked with the wave.
    incs = c.get("/incidents").json()
    assert len(incs) == 50 and all(i["wave"] == "WAVE-001" for i in incs)
    # One alert for the wave instead of one per address; the first nine had theirs already.
    assert kinds(c).count("wave_started") == 1
    assert kinds(c).count("incident_opened") == 9
    started = next(n for n in c.core.notifications if n["kind"] == "wave_started")
    assert "addresses scanning game-01" in started["title"] and "one summary every 15 min" in started["text"]
    assert any("folded into the WAVE-001 summary" in t["text"] for i in incs for t in i["timeline"])


def test_wave_counts_like_its_worst_member_not_the_sum(make_client):
    c = make_client(**BUSY)
    scanners(c, 60)
    incs = c.get("/incidents").json()
    worst = max(i["contribution"] for i in incs)
    raw = c.get("/risk").json()["raw_score"]
    assert worst > 0 and raw <= 2 * worst + 0.1
    assert sum(i["contribution"] for i in incs) > 10 * raw  # without waves it would be the sum


def test_waves_are_per_machine(make_client):
    c = make_client(**BUSY)
    scanners(c, 9, host="game-01")
    scanners(c, 9, start=100, host="game-02")
    assert c.get("/waves").json() == []
    scanners(c, 1, start=200, host="game-02")
    [wave] = c.get("/waves").json()
    assert wave["host"] == "game-02" and wave["addresses"] == 10


def test_summary_every_update_period_with_what_was_folded(make_client):
    c = make_client(**BUSY)
    scanners(c, 10)
    scanners(c, 15, start=10)
    assert "wave_update" not in kinds(c)
    c.core.clock.advance_demo_hours(16)  # 16 real minutes at demo speed 60: past the 15
    c.core.tick()
    [update] = [n for n in c.core.notifications if n["kind"] == "wave_update"]
    assert "25 addresses scanning game-01" in update["title"]
    assert "25 new" in update["text"]  # the first ten were alerted in the same step the wave started
    c.core.tick()
    assert kinds(c).count("wave_update") == 1  # nothing new since: no second summary
    assert [r for r in c.get("/audit").json()["records"] if r["type"] == "wave_update"]


def test_a_new_address_after_the_wave_went_quiet_does_not_join_it(make_client):
    c = make_client(**BUSY)
    scanners(c, 10)
    c.core.clock.advance_demo_hours(31)
    c.core.tick()
    scanners(c, 1, start=50)
    [wave] = c.get("/waves").json()
    assert wave["addresses"] == 10 and wave["active"] is False
    assert "wave" not in c.get("/incidents").json()[-1]


def test_other_attacks_are_never_folded(make_client):
    c = make_client(**BUSY)
    scanners(c, 12)
    c.post("/events", json=ev(900, "GET /search?q=' OR 1=1 --", ip="203.0.113.77", user=None, host="game-01",
                              source="flask_access"))
    sqli = [i for i in c.get("/incidents").json() if i["category"] == "sql_injection"]
    assert sqli and "wave" not in sqli[0]


def test_waves_survive_a_restart(make_client, tmp_path):
    c = make_client(**BUSY)
    scanners(c, 12)
    c2 = make_client(**BUSY)
    [wave] = c2.get("/waves").json()
    assert wave["addresses"] == 12
    scanners(c2, 1, start=40)
    assert c2.get("/waves").json()[0]["addresses"] == 13


def test_trusted_addresses_are_not_analysed_but_decoys_still_count(make_client):
    c = make_client(trusted_ips={"198.51.0.0/16"})
    scanners(c, 5)
    assert c.get("/incidents").json() == []
    assert all(e["classified_by"] == "trusted" for e in c.core.events.values() if e.get("source") == "nginx_access")
    c.post("/events", json=ev(1, "tripwire honeypot_page: decoy touched", ip="198.51.0.9", user=None,
                              source="tripwire"))
    [inc] = c.get("/incidents").json()
    assert inc["classification_reason"].startswith("Tripwire:")


def test_helpers():
    assert network_of("203.0.113.45") == "203.0.113.0/24"
    assert network_of("2001:db8:1:2::5") == "2001:db8:1::/48"
    assert network_of("not an ip") is None
    assert wave_points([]) == 0.0
    assert wave_points([30.0]) == 30.0
    assert wave_points([30.0, 30.0]) == 33.0
    assert wave_points([30.0] * 300) == 60.0
