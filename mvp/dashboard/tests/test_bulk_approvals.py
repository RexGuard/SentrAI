"""Approvals: tick several incidents (or a whole group) and approve, reject, roll back or keep them in one go."""
import pytest
import requests

from conftest import ROOT
from sentrai_ui import shaping as sh

APP = str(ROOT / "app.py")


def _inc(i, status="open", ip="203.0.113.5", host="web-01", cat="brute_force", **kw):
    return {"id": i, "status": status, "src_ip": ip, "host": host, "category": cat, **kw}


def test_groups_by_attacker_machine_and_type_biggest_first():
    waiting = [_inc("A", ip="1.1.1.1"), _inc("B", ip="2.2.2.2", host="db-01", cat="port_scan"), _inc("C", ip="2.2.2.2")]
    assert [(k, [i["id"] for i in g]) for k, g in sh.group_approvals(waiting, "attacker")] == \
        [("2.2.2.2", ["B", "C"]), ("1.1.1.1", ["A"])]
    assert [k for k, _ in sh.group_approvals(waiting, "machine")] == ["web-01", "db-01"]
    assert [k for k, _ in sh.group_approvals(waiting, "type")] == ["Brute force", sh.category_label("port_scan")]
    assert sh.group_approvals(waiting, None) == [("", waiting)]


def test_attacker_falls_back_to_the_blocked_target():
    inc = {"id": "A", "actions": [{"target": "9.9.9.9", "status": "active"}]}
    assert sh.approval_group(inc, "attacker") == "9.9.9.9"
    assert sh.approval_group({"id": "B"}, "attacker") == "Unknown source"


def test_bulk_split_sends_each_incident_to_the_buttons_that_fit_it():
    picked = [_inc("A"), _inc("B", status="contained"), _inc("C", status="resolved")]
    split = sh.bulk_split(picked)
    assert [i["id"] for i in split["decide"]] == ["A"]
    assert [i["id"] for i in split["contain"]] == ["B"]


def test_bulk_result_names_what_did_not_go_through():
    assert sh.bulk_result("Rejected", ["A", "B"], []) == "Rejected 2 of 2 incidents"
    assert sh.bulk_result("Rejected", ["A"], [("B", "gone")]) == "Rejected 1 of 2 incidents. Not done: B (gone)"


def test_saved_groups_take_their_incidents_out_of_the_list():
    waiting = [_inc("A"), _inc("B"), _inc("C")]
    groups, rest = sh.saved_groups(waiting, {"Scanner": ["B", "gone"], "Empty": ["gone"], "Also": ["B", "C"]})
    assert [(n, [i["id"] for i in m]) for n, m in groups] == [("Scanner", ["B"]), ("Also", ["C"])]
    assert [i["id"] for i in rest] == ["A"]


def test_add_to_group_moves_incidents_and_drops_what_no_longer_waits():
    saved = {"Old": ["A", "B"], "Stale": ["Z"]}
    assert sh.add_to_group(saved, "New", ["B", "C"], {"A", "B", "C"}) == {"Old": ["A"], "New": ["B", "C"]}
    assert sh.add_to_group({"Old": ["A"]}, "Old", ["C"], {"A", "C"}) == {"Old": ["A", "C"]}


def test_suggested_name_is_what_they_share():
    assert sh.suggest_group_name([_inc("A"), _inc("B", host="db-01")], {}) == "203.0.113.5"
    two = [_inc("A", ip="1.1.1.1"), _inc("B", ip="2.2.2.2")]
    assert sh.suggest_group_name(two, {}) == "web-01"
    assert sh.suggest_group_name(two, {"web-01": ["X"], "Brute force": ["Y"]}) == "Group 3"


def _approvals(fake_core, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    import streamlit as st

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    st.cache_data.clear()
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["operator"] = "erick"
    at.session_state["page"] = "approvals"
    return at


def _open_two(fake_core):
    requests.post(f"{fake_core}/dev/reset", timeout=3)
    for ip in ("198.51.100.7", "198.51.100.8"):
        requests.post(f"{fake_core}/dev/trigger/brute_force", params={"src_ip": ip}, timeout=3)
    incs = requests.get(f"{fake_core}/incidents", timeout=3).json()
    return [i["id"] for i in incs if i["status"] == "open"]


def test_pick_all_then_reject_with_one_reason(fake_core, tmp_path, monkeypatch):
    ids = _open_two(fake_core)
    assert len(ids) >= 2
    at = _approvals(fake_core, tmp_path, monkeypatch)
    at.run()
    assert not at.exception, at.exception
    assert not [b for b in at.button if b.key == "bulk_clear"]  # no bar until something is picked
    next(c for c in at.checkbox if c.label.startswith("Pick all")).check().run()
    assert not at.exception, at.exception
    at.text_input(key="brj_bulk_0").set_value("Our own scanner").run()
    reject = next(b for b in at.button if b.key == "br_bulk_0")
    assert reject.label == f"Reject all {len(ids)}"
    reject.click().run()
    # AppTest cannot rerun just a fragment, so run_bulk's refresh raises here; in a browser it reruns the page part.
    assert all("fragment" in str(e.value) for e in at.exception), at.exception
    for iid in ids:
        assert requests.get(f"{fake_core}/incidents/{iid}", timeout=3).json()["status"] != "open"
    decisions = [r["data"] for r in requests.get(f"{fake_core}/audit", timeout=3).json()["records"]
                 if r["type"] == "decision"]
    assert len(decisions) >= len(ids)
    assert all(d.get("justification") == "Our own scanner" and d.get("operator") == "erick" for d in decisions[-len(ids):])


def test_group_by_attacker_shows_a_heading_per_ip(fake_core, tmp_path, monkeypatch):
    _open_two(fake_core)
    at = _approvals(fake_core, tmp_path, monkeypatch)
    at.run()
    at.segmented_control(key="appr_group").set_value("Attacker").run()
    assert not at.exception, at.exception
    text = " ".join(m.value for m in at.markdown)
    assert "198.51.100.7" in text and "198.51.100.8" in text


def test_auditor_gets_no_tick_boxes(fake_core, tmp_path, monkeypatch):
    _open_two(fake_core)
    monkeypatch.setenv("SENTRAI_DASHBOARD_ROLE", "auditor")
    at = _approvals(fake_core, tmp_path, monkeypatch)
    at.run()
    assert not at.exception, at.exception
    assert not [c for c in at.checkbox if c.label == "Pick" or c.label.startswith("Pick all")]


def test_group_picked_then_decide_the_group_and_ungroup(fake_core, tmp_path, monkeypatch):
    from sentrai_config import approval_groups

    ids = _open_two(fake_core)
    at = _approvals(fake_core, tmp_path, monkeypatch)
    at.run()
    next(c for c in at.checkbox if c.label.startswith("Pick all")).check().run()
    at.text_input(key="gname_0").set_value("Pen test").run()
    next(b for b in at.button if b.key == "gsave_0").click().run()
    assert all("fragment" in str(e.value) for e in at.exception), at.exception
    assert approval_groups() == {"Pen test": ids}
    at = _approvals(fake_core, tmp_path, monkeypatch)
    at.run()
    assert not at.exception, at.exception
    assert "Pen test" in " ".join(m.value for m in at.markdown)
    assert not [c for c in at.checkbox if c.label == "Pick"]  # everything is in the group now
    assert next(b for b in at.button if b.key == "br_grp_Pen test_0").label == f"Reject all {len(ids)}"
    next(b for b in at.button if b.key == "ungroup_Pen test").click().run()
    assert approval_groups() == {}
