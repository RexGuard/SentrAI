"""The Incidents page as tabs, and its lists as tables with the quick buttons at the end of each row
(sentrai_ui/incident_table.mjs). Example data only."""
import json
from pathlib import Path

import pandas as pd
import pytest
import requests

from sentrai_ui import shaping as sh

APP = str(Path(__file__).resolve().parents[1] / "app.py")


# ------------------------------------------------------------------ shaping

def _inc(**kw):
    return {"id": "RSK-1", "category": "brute_force", "severity": "high", "status": "open", "acked": False,
            "owner": "On duty", "host": "web-01", **kw}


def test_each_kind_of_incident_gets_the_buttons_its_row_had():
    labels = lambda inc, **kw: [b["label"] for b in sh.quick_action_list(inc, **kw)]  # noqa: E731
    assert labels(_inc()) == ["Approve", "Reject"]
    assert labels(_inc(category=sh.ADMIN_CATEGORY)) == ["This was me", "Not me: block it"]
    assert labels(_inc(status="contained")) == ["Roll back", "Make permanent"]
    assert labels(_inc(status="resolved")) == []


def test_reject_needs_a_reason_and_make_permanent_may_have_one():
    reject = sh.quick_action_list(_inc())[1]
    assert reject["a"] == "reject" and reject["reason"] == "required"
    keep = sh.quick_action_list(_inc(status="contained"))[1]
    assert keep["reason"] == "optional" and keep["confirm"] == "Keep this block forever"


def test_read_only_and_protection_off_grey_buttons_out_and_say_why():
    ro = sh.quick_action_list(_inc(), read_only="You can look, not change")
    assert all(b["disabled"] and b["help"] == "You can look, not change" for b in ro)
    approve, reject = sh.quick_action_list(_inc(), protection_off=True)
    assert approve["disabled"] and approve["help"] == sh.PROTECTION_OFF_HELP
    assert not reject["disabled"]  # rejecting changes nothing on the machine


def test_table_data_has_a_row_per_incident_and_waves_do_not_open():
    incs = [_inc(id="RSK-1"), _inc(id="RSK-2", severity="critical", wave="W-1"), _inc(id="RSK-3", wave="W-1")]
    df = sh.board_rows(incs, group_waves=True)
    data = sh.incident_table_data(df, incs, lambda inc: sh.quick_action_list(inc), selected="RSK-1")
    by_id = {r["id"]: r for r in data["rows"]}
    assert set(by_id) == {"RSK-1", "W-1 (2)"}
    assert by_id["RSK-1"]["open"] and [b["a"] for b in by_id["RSK-1"]["actions"]] == ["approve", "reject"]
    assert not by_id["W-1 (2)"]["open"] and by_id["W-1 (2)"]["actions"] == []
    assert by_id["RSK-1"]["sev"] == sh.SEVERITY_COLORS["high"]
    assert len(data["columns"]) == len(by_id["RSK-1"]["cells"]) and data["selected"] == "RSK-1"


def test_approvals_tables_carry_the_tick_boxes_and_the_groups():
    incs = [_inc(id="RSK-1", src_ip="198.51.100.7"), _inc(id="RSK-2", src_ip="198.51.100.8")]
    plain = sh.incident_table_data(sh.board_rows(incs), incs)
    assert not plain["pick"] and plain["groups"] is None
    data = sh.incident_table_data(sh.board_rows(incs), incs, picked={"RSK-2"},
                                  groups=[("198.51.100.7", incs[:1]), ("198.51.100.8", incs[1:])])
    assert data["pick"] and data["picked"] == ["RSK-2"]
    assert data["groups"] == [{"label": "198.51.100.7", "ids": ["RSK-1"]}, {"label": "198.51.100.8", "ids": ["RSK-2"]}]


def test_an_empty_list_is_an_empty_table():
    data = sh.incident_table_data(pd.DataFrame(columns=sh.BOARD_COLUMNS), [], empty="All quiet")
    assert data["rows"] == [] and data["empty"] == "All quiet"


# ------------------------------------------------------------------ the page

@pytest.fixture
def fresh(fake_core):
    requests.post(f"{fake_core}/dev/reset", timeout=3)
    yield fake_core
    requests.post(f"{fake_core}/dev/reset", timeout=3)


def _page(url, tmp_path, monkeypatch, tab="todo"):
    import streamlit as st
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.delenv("SENTRAI_DASHBOARD_ROLE", raising=False)
    st.cache_data.clear()
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = url
    at.session_state["auto_refresh"] = False
    at.session_state["operator"] = "erick"
    at.session_state["page"] = "incidents"
    at.session_state["inc_tab"] = tab
    at.run()
    assert not at.exception, at.exception
    return at


def _components(at, name):
    return [(el, json.loads(el.proto.json)) for el in at.get("bidi_component") if el.proto.component_name.endswith(name)]


def _send(at, inc_id: str, event: str, value: dict) -> None:
    """What the table does in a browser: set its trigger, which reruns the page part."""
    try:  # Streamlit internals, not a promise: skip rather than fail when they move
        from streamlit.components.v2.bidi_component.main import _make_trigger_id
        from streamlit.proto.WidgetStates_pb2 import WidgetState
        states = at._tree.get_widget_states()
        run = at._run
    except (ImportError, AttributeError) as exc:
        pytest.skip(f"cannot press a table's button in this Streamlit's AppTest: {exc}")
    el = next(el for el, d in _components(at, "incident_table") if any(r["id"] == inc_id for r in d["rows"]))
    states.widgets.append(WidgetState(id=_make_trigger_id(el.proto.id, "events"),
                                      json_trigger_value=json.dumps([{"event": event, "value": value}])))
    run(states)


def _brute(url, n=3):
    return [requests.post(f"{url}/dev/trigger/brute_force", params={"src_ip": f"203.0.113.{i + 1}"}, timeout=3).json()
            for i in range(n)]


def test_only_the_chosen_tab_is_drawn(fresh, tmp_path, monkeypatch):
    _brute(fresh)
    at = _page(fresh, tmp_path, monkeypatch, tab="all")
    assert [d["rows"] and True for _, d in _components(at, "incident_table")] == [True]
    assert not [d for _, d in _components(at, "routing_editor") if not d.get("focus")]
    at = _page(fresh, tmp_path, monkeypatch, tab="map")
    assert not _components(at, "incident_table")
    assert [d for _, d in _components(at, "routing_editor") if not d.get("focus")]


def test_the_page_draws_one_table_not_a_card_per_incident(fresh, tmp_path, monkeypatch):
    incs = _brute(fresh, 30)
    at = _page(fresh, tmp_path, monkeypatch, tab="all")
    (_, data), = _components(at, "incident_table")
    assert {i["id"] for i in incs} <= {r["id"] for r in data["rows"]}
    assert len(at.button) < len(incs)  # the quick buttons live in the table, not as 30 x 8 Streamlit buttons


def test_reject_from_the_table_sends_the_reason(fresh, tmp_path, monkeypatch):
    inc = _brute(fresh, 1)[0]
    at = _page(fresh, tmp_path, monkeypatch, tab="all")
    _send(at, inc["id"], "act", {"id": inc["id"], "a": "reject", "reason": "Our pen tester", "n": "1"})
    assert all("fragment" in str(e.value) for e in at.exception), at.exception  # AppTest cannot rerun a page part
    got = requests.get(f"{fresh}/incidents/{inc['id']}", timeout=3).json()
    assert got["status"] == "rejected"


def test_reject_without_a_reason_does_nothing(fresh, tmp_path, monkeypatch):
    inc = _brute(fresh, 1)[0]
    at = _page(fresh, tmp_path, monkeypatch, tab="all")
    _send(at, inc["id"], "act", {"id": inc["id"], "a": "reject", "reason": "  ", "n": "1"})
    assert requests.get(f"{fresh}/incidents/{inc['id']}", timeout=3).json()["status"] == "open"


def test_clicking_a_row_opens_that_one_card(fresh, tmp_path, monkeypatch):
    inc = _brute(fresh, 2)[1]
    at = _page(fresh, tmp_path, monkeypatch, tab="all")
    _send(at, inc["id"], "open", {"id": inc["id"], "n": "1"})
    at.run()
    assert not at.exception, at.exception
    assert at.session_state["open_board_table"] == inc["id"]
    (_, data), = _components(at, "incident_table")
    assert data["selected"] == inc["id"]
    assert any(b.key == "close_board_table" for b in at.button)
