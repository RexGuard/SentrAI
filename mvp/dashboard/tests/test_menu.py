"""Sidebar menu bubbles, the part views, and a smoke test of every page."""
from pathlib import Path

import pytest
import requests

from cactai_ui import shaping as sh

RECORDS = [
    {"seq": 1, "type": "core_started", "data": {}},
    {"seq": 2, "type": "incident_opened", "data": {"incident": "RSK-1"}},
    {"seq": 3, "type": "event_classified", "data": {"incident": "RSK-1", "event_id": "e1", "category": "sql_injection",
                                                   "confidence": 1.0, "malicious": 1.0, "classified_by": "rules"}},
    {"seq": 4, "type": "event_classified", "data": {"incident": "RSK-1", "event_id": "e2", "category": "sql_injection"}},
    {"seq": 5, "type": "action_applied", "data": {"incident": "RSK-1"}},
]


def test_bubbles_count_alerts_since_each_page_was_opened():
    assert sh.unseen_counts(RECORDS, {}) == {"collector": 2, "classifier": 1, "responder": 1}
    assert sh.unseen_counts(RECORDS, {"collector": 3, "classifier": 5}) == {"collector": 1, "classifier": 0, "responder": 1}


def test_bubbles_come_back_after_a_demo_reset():
    # seen seq 99 is beyond the restarted chain, so everything counts again
    assert sh.unseen_counts(RECORDS, {"collector": 99})["collector"] == 2


def test_classification_rows_newest_first():
    rows = sh.classification_rows(RECORDS)
    assert list(rows["Event"]) == ["e2", "e1"]
    assert rows.iloc[1]["Category"] == sh.category_label("sql_injection")


def test_pending_approvals_open_before_contained():
    incs = [
        {"id": "A", "status": "contained", "points": 90},
        {"id": "B", "status": "open", "points": 10},
        {"id": "C", "status": "resolved", "points": 50},
        {"id": "D", "status": "acknowledged", "points": 40},
    ]
    assert [i["id"] for i in sh.pending_approvals(incs)] == ["D", "B", "A"]


def test_risk_breakdown_counts_only_active_incidents():
    df = sh.risk_breakdown([{"id": "A", "status": "open", "points": 30, "inaction_penalty": 10},
                            {"id": "B", "status": "contained", "points": 60, "inaction_penalty": 5}])
    assert list(df["Incident"]) == ["A", "B"]
    assert list(df["Counts now"]) == [40.0, 0.0]


APP = str(Path(__file__).resolve().parents[1] / "app.py")


@pytest.mark.parametrize("page", ["config", "approvals", "collector", "classifier", "responder", "review",
                                  "reports", "audit"])
def test_every_page_renders(fake_core, page, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("CACTAI_CONFIG", str(tmp_path / "config.json"))
    requests.post(f"{fake_core}/dev/trigger/brute_force", timeout=3)
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["page"] = page
    at.run()
    assert not at.exception, at.exception
    assert any("Collector" in b.label for b in at.sidebar.button)
