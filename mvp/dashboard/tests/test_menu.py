"""Sidebar menu bubbles, the part views, and a smoke test of every page."""
import sys
from pathlib import Path

import pytest
import requests

from cactai_ui import shaping as sh

sys.path.append(str(Path(__file__).resolve().parents[2]))
import cactai_config as cfg  # noqa: E402

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


@pytest.mark.parametrize("page", ["config", "approvals", "chat", "collector", "classifier", "responder", "review",
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


def test_chat_suggestion_only_while_the_incident_allows_it():
    assert sh.suggestion_state({"status": "open", "acked": False}, "approve") == (True, "")
    assert sh.suggestion_state({"status": "open", "acked": False}, "ack") == (True, "")
    ok, why = sh.suggestion_state({"status": "resolved"}, "approve")
    assert not ok and "no longer possible" in why
    assert sh.suggestion_state({"status": "contained", "actions": [{"status": "active"}]}, "rollback")[0]
    assert sh.suggestion_state(None, "approve") == (False, "incident not found")


def test_chat_asks_and_the_suggestion_goes_through_the_normal_decision(fake_core, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("CACTAI_CONFIG", str(tmp_path / "config.json"))
    requests.post(f"{fake_core}/demo/reset", timeout=3)
    requests.post(f"{fake_core}/dev/trigger/brute_force", timeout=3)
    import streamlit as st
    st.cache_data.clear()  # earlier tests cached the incidents from before the reset
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["operator"] = "erick"
    at.session_state["page"] = "chat"
    at.run()
    at.chat_input[0].set_value("what is happening?").run()
    assert not at.exception, at.exception
    msgs = requests.get(f"{fake_core}/chat", timeout=3).json()["messages"]
    assert [m["role"] for m in msgs] == ["operator", "assistant"] and msgs[0]["operator"] == "erick"
    iid = msgs[1]["suggestions"][0]["incident"]
    assert requests.get(f"{fake_core}/incidents/{iid}", timeout=3).json()["status"] == "open"  # nothing happened yet
    confirm = next(b for b in at.button if b.label.startswith("Confirm: Approve"))
    confirm.click().run()
    assert not at.exception, at.exception
    inc = requests.get(f"{fake_core}/incidents/{iid}", timeout=3).json()
    assert inc["status"] == "contained"
    decisions = [r for r in requests.get(f"{fake_core}/audit", timeout=3).json()["records"] if r["type"] == "decision"]
    assert decisions[-1]["data"]["operator"] == "erick"


@pytest.fixture
def models_api():
    """A local OpenAI-compatible service whose /v1/models lists two models."""
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            ok = self.path == "/v1/models" and self.headers.get("Authorization") == "Bearer k"
            body = json.dumps({"data": [{"id": "small-model"}, {"id": "big-model"}]} if ok else {"error": "no"}).encode()
            self.send_response(200 if ok else 401)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}/v1"
    server.shutdown()


def test_ai_settings_fetch_the_models_and_save_the_pick(fake_core, models_api, tmp_path, monkeypatch):
    import json

    from streamlit.testing.v1 import AppTest

    path = tmp_path / "config.json"
    monkeypatch.setenv("CACTAI_CONFIG", str(path))
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["page"] = "config"
    at.run()
    at.selectbox(key="cfg_CACTAI_LLM_PROVIDER").set_value("compatible").run()
    at.text_input(key="cfg_CACTAI_LLM_BASE_URL").set_value(models_api)
    at.text_input(key="cfg_CACTAI_LLM_API_KEY").set_value("k").run()
    next(b for b in at.button if "Fetch models" in b.label).click().run()
    assert not at.exception, at.exception
    assert at.selectbox(key="ai_model_pick").options == ["big-model", "small-model"]
    at.selectbox(key="ai_model_pick").set_value("small-model").run()
    assert at.text_input(key="cfg_CACTAI_LLM_MODEL").value == "small-model"

    next(b for b in at.button if "Save settings" in b.label).click().run()
    assert not at.exception, at.exception
    assert json.loads(path.read_text())["ai"] == {"CACTAI_LLM_PROVIDER": "compatible", "CACTAI_LLM_API_KEY": "k",
                                                  "CACTAI_LLM_BASE_URL": models_api, "CACTAI_LLM_MODEL": "small-model"}

    at.text_input(key="cfg_CACTAI_LLM_API_KEY").set_value("wrong").run()
    next(b for b in at.button if "Fetch models" in b.label).click().run()
    assert any("rejected this API key" in w.value for w in at.warning)


def test_collector_page_scans_and_watches_a_log(fake_core, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("CACTAI_CONFIG", str(tmp_path / "config.json"))
    requests.post(f"{fake_core}/demo/reset", timeout=3)
    import streamlit as st
    st.cache_data.clear()
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["operator"] = "erick"
    at.session_state["page"] = "collector"
    at.run()
    assert not at.exception, at.exception
    next(b for b in at.button if b.label == "Scan running programs").click().run()
    assert not at.exception, at.exception
    watch = [b for b in at.button if b.label == "Watch"]
    assert len(watch) == 2  # nginx access.log and error.log; the lab log is already watched
    watch[0].click().run()
    assert not at.exception, at.exception
    added = requests.get(f"{fake_core}/log-sources", timeout=3).json()
    assert [x["confirmed_by"] for x in added] == ["erick"]
    assert len([b for b in at.button if b.label == "Watch"]) == 1


def test_preset_fills_the_advanced_values_and_saves_the_overrides(fake_core, tmp_path, monkeypatch):
    import json

    from streamlit.testing.v1 import AppTest

    path = tmp_path / "config.json"
    monkeypatch.setenv("CACTAI_CONFIG", str(path))
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["page"] = "config"
    at.run()
    assert at.button_group(key="cfg_CACTAI_PRESET").value == "moderate"
    at.button_group(key="cfg_CACTAI_PRESET").set_value("strict").run()
    assert not at.exception, at.exception
    assert at.text_input(key="cfg_RISK_THRESHOLD").value == cfg.preset_values("strict")["RISK_THRESHOLD"]

    at.text_input(key="cfg_SLA_HOURS").set_value("3").run()
    assert any("1 value changed by hand" in c.value for c in at.caption)
    next(b for b in at.button if "Save settings" in b.label).click().run()
    assert not at.exception, at.exception
    saved = json.loads(path.read_text())
    assert saved["preset"] == {"CACTAI_PRESET": "strict"}
    values = cfg.read()
    assert values["BRUTE_FORCE_COUNT"] == cfg.preset_values("strict")["BRUTE_FORCE_COUNT"]
    assert cfg.overrides(values) == {"SLA_HOURS": "3"}

    next(b for b in at.button if "Reset to preset" in b.label).click().run()
    assert at.text_input(key="cfg_SLA_HOURS").value == cfg.preset_values("strict")["SLA_HOURS"]
