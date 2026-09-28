"""Cactus spines: honeypot login, honeytoken credential and rows, tarpit (off by default)."""
from __future__ import annotations

import json
import time

import pytest

from collector import collector
from target_app import create_app, db, paths, spines
from target_app.blocklist import blocklist

ATTACKER = {"X-Demo-Src-IP": "203.0.113.99"}
STAFF = {"X-Demo-Src-IP": "192.0.2.10"}


def _spine_log() -> list[dict]:
    log = paths.logs_dir() / paths.DECEPTION_LOG
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture(autouse=True)
def _clean():
    (paths.logs_dir() / paths.DECEPTION_LOG).unlink(missing_ok=True)
    blocklist.update(ips=[], users=[])
    yield
    create_app(spines_on=False)  # leave the shared test DB without bait rows


def _client(on: bool, tarpit_s: float = 0.0):
    app = create_app(spines_on=on, tarpit_s=tarpit_s)
    app.config.update(TESTING=True)
    return app, app.test_client()


def test_spines_off_by_default(monkeypatch):
    monkeypatch.delenv("CACTAI_SPINES", raising=False)
    app = create_app()
    c = app.test_client()
    assert app.config["SPINES"] is False
    assert c.get(spines.HONEYPOT_PATH).status_code == 404
    assert c.get("/robots.txt").status_code == 404
    assert not spines.honeytoken_hits(db.all_members())
    c.post("/login", data={"user": spines.DECOY_USER, "password": spines.DECOY_PASSWORD})
    assert _spine_log() == []


def test_env_switch(monkeypatch):
    monkeypatch.setenv("CACTAI_SPINES", "1")
    monkeypatch.setenv("CACTAI_TARPIT_S", "99")
    app = create_app()
    assert app.config["SPINES"] is True
    assert app.extensions["cactai_tarpit"].delay_s == 30.0  # capped


def test_honeypot_page_and_login_never_sign_in():
    _, c = _client(True)
    robots = c.get("/robots.txt").data.decode()
    assert f"Disallow: {spines.HONEYPOT_PATH}" in robots
    page = c.get(spines.HONEYPOT_PATH, headers=ATTACKER)
    assert page.status_code == 200
    assert spines.DECOY_USER.encode() in page.data  # the planted credential sits in an HTML comment
    resp = c.post(spines.HONEYPOT_PATH, data={"user": "admin", "password": "anything"}, headers=ATTACKER)
    assert resp.status_code == 401
    kinds = [r["kind"] for r in _spine_log()]
    assert kinds == [spines.HONEYPOT_PAGE, spines.HONEYPOT_LOGIN]
    login = _spine_log()[1]
    assert login["src_ip"] == "203.0.113.99"
    assert login["user"] is None  # a real account must never be locked because of the decoy
    assert "'admin'" in login["raw"]


def test_planted_credential_on_real_login():
    _, c = _client(True)
    resp = c.post("/login", data={"user": spines.DECOY_USER, "password": spines.DECOY_PASSWORD}, headers=ATTACKER)
    assert resp.status_code == 401
    [hit] = _spine_log()
    assert hit["kind"] == spines.HONEYTOKEN_CREDENTIAL and hit["user"] == spines.DECOY_USER


def test_staff_searches_never_touch_bait_rows():
    _, c = _client(True)
    for term in ("Member 0001", "member0002", "Member", "example.com"):  # attacks/benign.py terms
        assert c.get("/search", query_string={"q": term}, headers=STAFF).status_code == 200
    assert _spine_log() == []


def test_export_returns_bait_rows_and_alerts():
    _, c = _client(True)
    resp = c.get("/export", headers=ATTACKER)
    assert b"STF-0007" in resp.data
    [hit] = _spine_log()
    assert hit["kind"] == spines.HONEYTOKEN_ROW and hit["layer"] == "db" and hit["pii"] is True
    assert "STF-0007" in hit["raw"] and "STF-0012" in hit["raw"]


def test_tarpit_slows_only_pricked_ips():
    app, c = _client(True, tarpit_s=0.3)
    t0 = time.monotonic()
    c.get("/", headers=ATTACKER)
    assert time.monotonic() - t0 < 0.3  # not pricked yet
    c.get("/export", headers=ATTACKER)  # touches the bait rows
    assert "tarpit engaged" in _spine_log()[0]["raw"]
    t0 = time.monotonic()
    c.get("/", headers=ATTACKER)
    assert time.monotonic() - t0 >= 0.3
    t0 = time.monotonic()
    c.get("/", headers=STAFF)
    assert time.monotonic() - t0 < 0.3
    assert app.extensions["cactai_tarpit"].is_pricked("203.0.113.99")


def test_collector_ships_spine_events_with_their_layer():
    _, c = _client(True)
    c.get("/export", headers=ATTACKER)
    c.get(spines.HONEYPOT_PATH, headers=ATTACKER)
    events = [collector.normalize(paths.DECEPTION_LOG, r) for r in _spine_log()]
    assert [(e["layer"], e["source"]) for e in events] == [("db", "cactus_spine"), ("web", "cactus_spine")]
    assert events[0]["asset_criticality"] == 1.5
    assert events[0]["raw"].startswith("cactus-spine honeytoken_row:")
