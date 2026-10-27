"""Each machine's own page: the list opens it, its address can be shared, and its tabs work."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requests

from sentrai_ui import shaping as sh

APP = str(Path(__file__).resolve().parents[1] / "app.py")
NOW = datetime(2026, 10, 27, 2, 0, 0, tzinfo=timezone.utc)


def test_seen_ago_reads_like_people_say_it():
    assert sh.seen_ago(None) == "never"
    assert sh.seen_ago(NOW - timedelta(seconds=3), NOW) == "just now"
    assert sh.seen_ago((NOW - timedelta(seconds=42)).isoformat(), NOW) == "42 s ago"
    assert sh.seen_ago(NOW - timedelta(minutes=7), NOW) == "7 min ago"


def test_panel_cards_show_incidents_blocks_and_last_seen():
    row = sh.panel_machines([{"host": "web-01", "risk_index": 42, "open_incidents": 2, "contained_incidents": 1,
                              "blocked": 3, "last_seen": (NOW - timedelta(seconds=20)).isoformat()}],
                             [{"agent_id": "a1", "host": "web-01", "last_seen": NOW.isoformat()}], {}, now=NOW)[0]
    card = sh.machine_rows_html([row], link=True, now=NOW)
    assert "2 open · 1 contained" in card and "3 in force" in card and "just now" in card
    assert 'class="machine clickable"' in card and ">chevron_right<" in card
    status = sh.machine_rows_html([row], status=True, now=NOW)
    assert ">Protecting<" in status and 'aria-label="Machine status"' in status and "chevron_right" not in status
    # A list of machines that are not on a central panel has no incident or block figures to show.
    assert "m-stats" not in sh.machine_rows_html([sh.machine("Here", "Local", {"risk_index": 3})])


def test_machine_records_and_console_escape():
    records = [{"seq": 1, "type": "machine_joined", "data": {"host": "web-01", "agent_id": "a1"}},
               {"seq": 2, "type": "incident_opened", "data": {"incident": "RSK-1", "summary": "<b>x</b>"}},
               {"seq": 3, "type": "incident_opened", "data": {"incident": "RSK-2"}},
               {"seq": 4, "type": "machine_joined", "data": {"host": "office-pc"}}]
    mine = sh.machine_records(records, "web-01", ["RSK-1"])
    assert [r["seq"] for r in mine] == [1, 2]
    box = sh.console_html(sh.build_activity_feed(mine), "Live log for web-01")
    assert "&lt;b&gt;x&lt;/b&gt;" in box and 'tabindex="0"' in box and box.count('class="c-line"') == 2


def test_agent_facts():
    facts = dict(sh.agent_facts({"agent_id": "a1", "joined_at": "2026-10-26T06:00:00+00:00", "invited_by": "erick",
                                 "last_seen": None, "offline_total": 2,
                                 "offline": {"from": "2026-10-26T10:00:00+00:00", "to": "2026-10-26T10:40:00+00:00",
                                             "local_blocks": 2}}))
    assert facts["Agent id"] == "a1" and facts["Invited by"] == "erick" and facts["Last seen"] == "never"
    assert facts["Last time offline"].endswith("2 local blocks") and facts["Blocks made while offline"] == "2"
    assert sh.agent_facts(None) == []


def _app(fake_core, tmp_path, monkeypatch, page="machines", **params):
    import streamlit as st
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    st.cache_data.clear()
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["operator"] = "erick"
    at.session_state["page"] = page
    for k, v in params.items():
        at.query_params[k] = v
    return at


@pytest.fixture
def fresh(fake_core):
    requests.post(f"{fake_core}/dev/reset", timeout=3)
    requests.post(f"{fake_core}/dev/trigger/brute_force", timeout=3)
    yield fake_core
    requests.post(f"{fake_core}/dev/reset", timeout=3)


def test_a_machine_card_opens_its_page_and_back_returns(fresh, tmp_path, monkeypatch):
    at = _app(fresh, tmp_path, monkeypatch)
    at.run()
    assert not at.exception, at.exception
    opener = next(b for b in at.button if b.label == "Open web-01")
    opener.click().run()
    assert not at.exception, at.exception
    assert at.session_state["page"] == "machine" and at.session_state["machine"] == "web-01"
    assert at.query_params.get("machine") == "web-01"
    text = " ".join(m.value for m in at.markdown)
    assert "<h1>web-01</h1>" in text and "Machine status" in text and "Live log for web-01" in text
    next(b for b in at.button if b.key == "machine_back").click().run()
    assert not at.exception, at.exception
    assert at.session_state["page"] == "machines" and not at.query_params.get("machine")


def test_a_shared_link_opens_the_machine_on_its_tab(fresh, tmp_path, monkeypatch):
    at = _app(fresh, tmp_path, monkeypatch, page="approvals", machine="office-pc", tab="agent")
    at.run()
    assert not at.exception, at.exception
    assert at.session_state["page"] == "machine" and at.session_state["machine_tab"] == "Agent"
    text = " ".join(m.value for m in at.markdown)
    assert "<h1>office-pc</h1>" in text and "d4e5f6" in text and "1 local block" in text
    assert any(c.label == "Yes, stop accepting its key" for c in at.checkbox)


def test_an_unknown_machine_says_so(fresh, tmp_path, monkeypatch):
    at = _app(fresh, tmp_path, monkeypatch, machine="gone-01")
    at.run()
    assert not at.exception, at.exception
    assert any("No machine called gone-01" in m.value for m in at.markdown)


@pytest.mark.parametrize("tab", ["incidents", "blocks", "services", "scans"])
def test_every_tab_renders(fresh, tmp_path, monkeypatch, tab):
    at = _app(fresh, tmp_path, monkeypatch, machine="web-01", tab=tab)
    at.run()
    assert not at.exception, at.exception


def test_revoke_from_the_agent_tab(fresh, tmp_path, monkeypatch):
    at = _app(fresh, tmp_path, monkeypatch, machine="office-pc", tab="agent")
    at.run()
    revoke = next(b for b in at.button if b.key == "revoke_office-pc")
    assert revoke.disabled  # until the box is ticked
    next(c for c in at.checkbox if c.key == "revoke_sure_office-pc").check().run()
    next(b for b in at.button if b.key == "revoke_office-pc").click().run()
    assert not at.exception, at.exception
    agents = requests.get(f"{fresh}/fleet/agents", timeout=3).json()
    assert next(a for a in agents if a["host"] == "office-pc")["revoked_by"] == "erick"
    assert at.session_state["page"] == "machines" and not at.query_params.get("machine")


def test_a_machine_without_an_agent_cannot_be_asked_to_scan(fresh, tmp_path, monkeypatch):
    requests.post(f"{fresh}/fleet/agents/a1b2c3/revoke", json={"operator": "t"}, timeout=3)  # web-01: logs only now
    at = _app(fresh, tmp_path, monkeypatch, machine="web-01")
    at.run()
    assert not at.exception, at.exception
    assert next(b for b in at.button if b.key == "job_scan").disabled
    assert any("Known from logs only" in m.value for m in at.markdown)


def test_signing_in_keeps_a_machines_link(fake_core, tmp_path, monkeypatch):
    """Someone opens a shared machine link while signed out: after the sign-in they land on that machine."""
    from streamlit.testing.v1 import AppTest

    from test_sign_in import GOOD, acc, button, cfg, owner_with_authenticator, password_step, signed_in

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.delenv("SENTRAI_ACCOUNTS", raising=False)
    monkeypatch.delenv("SENTRAI_DASHBOARD_LOGIN")
    for name in (cfg.EMAIL_ENV, cfg.HASH_ENV, cfg.PASSWORD_ENV):
        monkeypatch.delenv(name, raising=False)
    secret = owner_with_authenticator()
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.query_params["machine"] = "office-pc"
    at.query_params["tab"] = "services"
    at.run()
    password_step(at, "erick@example.com", GOOD)
    at.text_input[0].input(acc.totp_code(secret))
    button(at, "Verify").click().run()
    assert not at.exception, at.exception
    assert signed_in(at)
    assert at.session_state["page"] == "machine" and at.session_state["machine"] == "office-pc"
    assert at.session_state["machine_tab"] == "Services"
