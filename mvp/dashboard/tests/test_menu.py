"""Sidebar menu bubbles, the part views, and a smoke test of every page."""
import copy
import json
import sys
from pathlib import Path

import pytest
import requests

from sentrai_ui import shaping as sh
from sentrai_ui.api import READ_ONLY_MESSAGE, CoreClient, CoreError

sys.path.append(str(Path(__file__).resolve().parents[2]))
import sentrai_config as cfg  # noqa: E402

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


def test_bubbles_come_back_after_a_fresh_chain():
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


@pytest.mark.parametrize("page", ["flow", "config", "approvals", "incidents", "staff", "chat", "collector", "classifier", "responder",
                                  "machines", "review", "reports", "audit", "backups", "extensions"])
def test_every_page_renders(fake_core, page, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
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

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    requests.post(f"{fake_core}/dev/reset", timeout=3)
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
    monkeypatch.setenv("SENTRAI_CONFIG", str(path))
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["page"] = "config"
    at.run()
    at.selectbox(key="cfg_SENTRAI_LLM_PROVIDER").set_value("compatible").run()
    at.text_input(key="cfg_SENTRAI_LLM_BASE_URL").set_value(models_api)
    at.text_input(key="cfg_SENTRAI_LLM_API_KEY").set_value("k").run()
    next(b for b in at.button if "Fetch models" in b.label).click().run()
    assert not at.exception, at.exception
    assert at.selectbox(key="ai_model_pick").options == ["big-model", "small-model"]
    at.selectbox(key="ai_model_pick").set_value("small-model").run()
    assert at.text_input(key="cfg_SENTRAI_LLM_MODEL").value == "small-model"

    next(b for b in at.button if "Save settings" in b.label).click().run()
    assert not at.exception, at.exception
    assert json.loads(path.read_text())["ai"] == {"SENTRAI_LLM_PROVIDER": "compatible", "SENTRAI_LLM_API_KEY": "k",
                                                  "SENTRAI_LLM_BASE_URL": models_api, "SENTRAI_LLM_MODEL": "small-model"}

    at.text_input(key="cfg_SENTRAI_LLM_API_KEY").set_value("wrong").run()
    next(b for b in at.button if "Fetch models" in b.label).click().run()
    assert any("rejected this API key" in w.value for w in at.warning)


def test_collector_page_scans_and_watches_a_log(fake_core, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    requests.post(f"{fake_core}/dev/reset", timeout=3)
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


def test_scout_proposals_are_approved_or_dismissed_on_the_collector_page(fake_core, tmp_path, monkeypatch):
    import streamlit as st
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    requests.post(f"{fake_core}/dev/reset", timeout=3)
    for name in ("auth.log", "syslog"):
        requests.post(f"{fake_core}/_fake/scout-proposal", json={"name": name, "path": f"/var/log/{name}"}, timeout=3)
    st.cache_data.clear()
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["operator"] = "erick"
    at.session_state["page"] = "collector"
    at.run()
    assert not at.exception, at.exception
    assert any("Scout proposals" in m.value for m in at.markdown)
    next(b for b in at.button if b.key.startswith("scout_yes_")).click().run()
    assert not at.exception, at.exception
    next(b for b in at.button if b.key.startswith("scout_no_")).click().run()
    assert not at.exception, at.exception
    assert requests.get(f"{fake_core}/log-sources/pending", timeout=3).json() == []
    added = requests.get(f"{fake_core}/log-sources", timeout=3).json()
    assert [(x["path"], x["found_by"]) for x in added if x.get("found_by") == "Scout"] == [("/var/log/auth.log", "Scout")]
    assert not any(b.key and b.key.startswith("scout_") for b in at.button)


def test_preset_fills_the_values_and_a_change_by_hand_switches_to_advanced(fake_core, tmp_path, monkeypatch):
    import json

    from streamlit.testing.v1 import AppTest

    path = tmp_path / "config.json"
    monkeypatch.setenv("SENTRAI_CONFIG", str(path))
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["page"] = "config"
    at.run()
    preset = at.button_group(key="cfg_SENTRAI_PRESET")
    assert preset.value == "moderate" and preset.options[-1] == "Advanced"
    preset.set_value("strict").run()
    assert not at.exception, at.exception
    assert at.text_input(key="cfg_RISK_THRESHOLD").value == cfg.preset_values("strict")["RISK_THRESHOLD"]

    at.text_input(key="cfg_SLA_HOURS").set_value("3").run()
    assert at.button_group(key="cfg_SENTRAI_PRESET").value == "advanced"
    next(b for b in at.button if "Save settings" in b.label).click().run()
    assert not at.exception, at.exception
    assert json.loads(path.read_text())["preset"] == {"SENTRAI_PRESET": "advanced"}
    values = cfg.read()
    assert values["BRUTE_FORCE_COUNT"] == cfg.preset_values("strict")["BRUTE_FORCE_COUNT"]
    assert values["SLA_HOURS"] == "3"

    at.button_group(key="cfg_SENTRAI_PRESET").set_value("balanced").run()
    assert at.text_input(key="cfg_SLA_HOURS").value == cfg.preset_values("balanced")["SLA_HOURS"]


def test_threat_paths_are_shown_escaped(fake_core, tmp_path, monkeypatch):
    """A scanned file name is chosen by whoever uploaded it, so it must never reach the page as HTML."""
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    requests.post(f"{fake_core}/threats/scan", json={"operator": "erick"}, timeout=3)
    import streamlit as st
    st.cache_data.clear()
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["page"] = "collector"
    at.run()
    assert not at.exception, at.exception
    shown = [m.value for m in at.markdown if "img.php" in m.value]
    assert shown and all("<code>/var/lib/pterodactyl/volumes/a1b2/plugins/web/upload/img.php</code>" in v for v in shown)


def test_start_page_is_approvals_only_when_something_waits():
    assert sh.start_page([{"id": "A", "status": "open"}]) == "approvals"
    assert sh.start_page([{"id": "A", "status": "contained"}]) == "approvals"
    assert sh.start_page([{"id": "A", "status": "resolved"}]) == "review"
    assert sh.start_page(None) == "review"


def test_status_labels_are_plain_words():
    assert sh.status_label("contained") == "Contained"
    assert sh.status_label("needs_review") == "Needs review"


def test_console_opens_on_what_needs_a_decision(fake_core, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    conf = tmp_path / "config.json"
    conf.write_text('{"setup_done": "dashboard"}', encoding="utf-8")
    monkeypatch.setenv("SENTRAI_CONFIG", str(conf))
    monkeypatch.setenv("SENTRAI_CORE_URL", fake_core)
    requests.post(f"{fake_core}/dev/trigger/brute_force", params={"src_ip": "203.0.113.77", "user": "landing"},
                  timeout=3)
    import streamlit as st
    st.cache_data.clear()  # an earlier test's incident list may still be cached
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.run()
    assert not at.exception, at.exception
    assert at.session_state["page"] == "approvals"


def _report_page(fake_core, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("SENTRAI_DASHBOARD_LOGIN", "on")  # the report page needs no sign-in even when it is on
    at = AppTest.from_file(APP, default_timeout=20)
    at.query_params["report"] = ""
    at.session_state["core_url"] = fake_core
    at.run()
    return at


def test_staff_report_page_sends_without_sign_in(fake_core, tmp_path, monkeypatch):
    at = _report_page(fake_core, tmp_path, monkeypatch)
    assert not at.exception, at.exception
    assert not at.sidebar.button  # no menu, nothing from SentrAI
    at.text_area[0].input("I got an email asking for my password and I clicked the link.")
    at.text_input[0].input("Mei")
    at.button[0].click().run()
    assert not at.exception, at.exception
    assert any("reached the security team" in s.value for s in at.success)
    reports = requests.get(f"{fake_core}/staff-reports", timeout=3).json()["reports"]
    assert reports[0]["reporter"] == "Mei" and reports[0]["channel"] == "dashboard"
    assert reports[0]["host"] is None  # "Not sure" sends no machine


def test_staff_report_page_names_the_machine(fake_core, tmp_path, monkeypatch):
    at = _report_page(fake_core, tmp_path, monkeypatch)
    picker = at.selectbox[0]
    assert picker.label == "Which computer is it about?" and "office-pc" in picker.options
    at.text_area[0].input("The office PC keeps opening pop-ups about a prize.")
    picker.select("office-pc")
    at.button[0].click().run()
    assert not at.exception, at.exception
    r = requests.get(f"{fake_core}/staff-reports", timeout=3).json()["reports"][0]
    assert r["host"] == "office-pc"
    assert requests.get(f"{fake_core}/incidents/{r['incident']}", timeout=3).json()["host"] == "office-pc"


def test_staff_report_page_asks_for_the_code_when_set(fake_core, tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRAI_REPORT_CODE", "lighthouse")
    at = _report_page(fake_core, tmp_path, monkeypatch)
    before = len(requests.get(f"{fake_core}/staff-reports", timeout=3).json()["reports"])
    at.text_area[0].input("A stranger was using the front desk computer at lunch.")
    at.text_input[3].input("wrong")
    at.button[0].click().run()
    assert any("report code is not right" in e.value for e in at.error)
    assert len(requests.get(f"{fake_core}/staff-reports", timeout=3).json()["reports"]) == before


def test_staff_reports_page_closes_a_report_with_a_note(fake_core, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    rid = requests.post(f"{fake_core}/staff-reports", timeout=3,
                        json={"text": "My laptop shows pop-ups asking me to call Microsoft.", "reporter": "Arif"}).json()["id"]
    import streamlit as st
    st.cache_data.clear()  # the staff page render in an earlier test may have cached the list without it
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["page"] = "staff"
    at.run()
    assert not at.exception, at.exception
    assert any(rid in e.label for e in at.expander)
    resolve = next(b for b in at.button if b.label == "Resolved")
    resolve.click().run()
    assert any("Add a short note" in w.value for w in at.warning)  # no note, no close
    note = next(t for t in at.text_input if t.label == "Note")
    note.input("Scam pop-up; browser reset.")
    next(b for b in at.button if b.label == "Resolved").click().run()
    assert not at.exception, at.exception
    r = next(r for r in requests.get(f"{fake_core}/staff-reports", timeout=3).json()["reports"] if r["id"] == rid)
    assert r["status"] == "resolved" and r["notes"][-1]["text"] == "Scam pop-up; browser reset."


def _extensions_page(fake_core, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["page"] = "extensions"
    at.run()
    assert not at.exception, at.exception
    return at


def test_extensions_page_shows_each_extension_and_its_test(fake_core, tmp_path, monkeypatch):
    requests.post(f"{fake_core}/dev/reset", timeout=3)
    at = _extensions_page(fake_core, tmp_path, monkeypatch)
    text = " ".join(m.value for m in at.markdown)
    for name in ("Cloudflare", "AbuseIPDB", "Slack", "Telegram", "TypeSafe", "Added", "Available", "Built in"):
        assert name in text
    next(b for b in at.button if b.key == "test_cloudflare").click().run()
    assert not at.exception, at.exception
    assert any("fake core does not call outside services" in e.value for e in at.error)
    next(b for b in at.button if b.key == "set_cloudflare").click().run()
    assert at.session_state["page"] == "config" and at.session_state["cfg_search"] == "cloudflare"
    assert any("Cloudflare extension" in m.value for m in at.markdown)  # its settings show there


def test_extensions_are_added_and_removed_after_a_confirm(fake_core, tmp_path, monkeypatch):
    requests.post(f"{fake_core}/dev/reset", timeout=3)
    at = _extensions_page(fake_core, tmp_path, monkeypatch)
    next(b for b in at.button if b.key == "add_slack").click().run()
    assert not at.exception, at.exception
    assert next(r for r in requests.get(f"{fake_core}/extensions", timeout=3).json() if r["name"] == "slack")["added"]
    next(b for b in at.button if b.key == "remove_cloudflare").click().run()
    assert any("Blocks it added at Cloudflare are taken out" in m.value for m in at.markdown)
    assert next(r for r in requests.get(f"{fake_core}/extensions", timeout=3).json() if r["name"] == "cloudflare")["added"]
    next(b for b in at.button if b.key == "remove_yes_cloudflare").click().run()
    assert not at.exception, at.exception
    rows = {r["name"]: r for r in requests.get(f"{fake_core}/extensions", timeout=3).json()}
    assert not rows["cloudflare"]["added"] and rows["cloudflare"]["changed_by"]
    assert any(b.key == "add_cloudflare" for b in at.button)


def test_telegram_link_codes_show_only_while_telegram_is_added(fake_core, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    requests.post(f"{fake_core}/dev/reset", timeout=3)
    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))

    def incidents():
        import streamlit as st
        st.cache_data.clear()
        at = AppTest.from_file(APP, default_timeout=20)
        at.session_state["core_url"] = fake_core
        at.session_state["auto_refresh"] = False
        at.session_state["page"] = "incidents"
        at.run()
        assert not at.exception, at.exception
        return any(b.key == "tg_code" for b in at.button)

    assert incidents()
    requests.post(f"{fake_core}/extensions/telegram/remove", json={"operator": "t"}, timeout=3)
    assert not incidents()


def test_when_the_server_decides_the_buttons_are_off(fake_core, tmp_path, monkeypatch):
    requests.post(f"{fake_core}/dev/reset", timeout=3)
    requests.post(f"{fake_core}/dev/extensions/managed?on=1", timeout=3)
    try:
        at = _extensions_page(fake_core, tmp_path, monkeypatch)
        assert any("SENTRAI_EXTENSIONS" in i.value for i in at.info)
        assert all(b.disabled for b in at.button if b.key and b.key.startswith(("add_", "remove_")))
    finally:
        requests.post(f"{fake_core}/dev/reset", timeout=3)


def test_approvals_rows_roll_back_in_one_click(fake_core, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    requests.post(f"{fake_core}/dev/reset", timeout=3)
    requests.post(f"{fake_core}/dev/trigger/brute_force", timeout=3)
    iid = requests.get(f"{fake_core}/incidents", timeout=3).json()
    iid = (iid.get("incidents") if isinstance(iid, dict) else iid)[-1]["id"]
    requests.post(f"{fake_core}/incidents/{iid}/decision", json={"operator": "t", "decision": "approve"}, timeout=3)
    import streamlit as st
    st.cache_data.clear()
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["operator"] = "erick"
    at.session_state["page"] = "approvals"
    at.run()
    assert not at.exception, at.exception
    quick = [b for b in at.button if b.key == f"qb_appr_{iid}"]
    assert quick, [b.key for b in at.button]
    quick[0].click().run()
    # AppTest cannot rerun just a fragment, so run_action's refresh raises here; in a browser it reruns the page part.
    assert all("fragment" in str(e.value) for e in at.exception), at.exception
    inc = requests.get(f"{fake_core}/incidents/{iid}", timeout=3).json()
    assert inc["actions"] and all(a["status"] != "active" for a in inc["actions"]), inc["actions"]
    assert any(a["status"] == "rolled_back" for a in inc["actions"])


# ------------------------------------------- Incidents: "Who gets what" as a map (sentrai_ui/routing_editor.mjs)

def _incidents_page(fake_core, tmp_path, monkeypatch, role: str = "", operator: str = "erick"):
    """The Incidents page with sign-in off, seen as `role` (SENTRAI_DASHBOARD_ROLE; empty: the default Owner)."""
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    if role:
        monkeypatch.setenv("SENTRAI_DASHBOARD_ROLE", role)
    else:
        monkeypatch.delenv("SENTRAI_DASHBOARD_ROLE", raising=False)
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["operator"] = operator
    at.session_state["page"] = "incidents"
    at.run()
    return at


def _maps(at):
    """Every "Who gets what" map on the page with the data Python gave it. AppTest has no element class for a
    components v2 component: it lists it as a "bidi_component" whose proto carries that data as JSON."""
    return [(el, json.loads(el.proto.json)) for el in at.get("bidi_component")
            if el.proto.component_name.endswith("routing_editor")]


def _routing_editor(at):
    """The whole team's map (one person's own part is drawn by the same component, with a focus)."""
    found = [(el, data) for el, data in _maps(at) if not data.get("focus")]
    assert len(found) == 1, f"expected the whole map once, found {len(found)}"
    return found[0]


def _my_map(at):
    found = [(el, data) for el, data in _maps(at) if data.get("focus")]
    assert len(found) <= 1, f"expected at most one person's own map, found {len(found)}"
    return found[0] if found else (None, None)


def _press_save(at, event: dict) -> None:
    """What the editor's Save does in a browser: set its "save" trigger to the event, which reruns the page part.
    AppTest cannot set a component's trigger, so this adds the widget state the browser would send."""
    try:  # Streamlit internals, not a promise: skip rather than fail when they move
        from streamlit.components.v2.bidi_component.main import _make_trigger_id
        from streamlit.proto.WidgetStates_pb2 import WidgetState
        states = at._tree.get_widget_states()
        run = at._run
    except (ImportError, AttributeError) as exc:
        pytest.skip(f"cannot press the editor's Save in this Streamlit's AppTest: {exc}")
    el, _ = _routing_editor(at)
    states.widgets.append(WidgetState(id=_make_trigger_id(el.proto.id, "events"),
                                      json_trigger_value=json.dumps([{"event": "save", "value": event}])))
    run(states)


def test_incidents_page_draws_who_gets_what_as_a_map_to_edit(fake_core, tmp_path, monkeypatch):
    at = _incidents_page(fake_core, tmp_path, monkeypatch)
    assert not at.exception, at.exception
    _, data = _routing_editor(at)
    routing = requests.get(f"{fake_core}/routing", timeout=3).json()
    assert data == sh.routing_editor_data(routing)  # an Owner may change it, and has not saved anything yet


def _show_whole_map(at):
    """An Auditor sees their own part first; the whole team's map waits behind a switch."""
    assert not [d for _, d in _maps(at) if not d.get("focus")]
    at.toggle(key="whole_map").set_value(True).run()


def test_incidents_page_as_an_auditor_shows_the_map_read_only(fake_core, tmp_path, monkeypatch):
    at = _incidents_page(fake_core, tmp_path, monkeypatch, role="auditor")
    assert not at.exception, at.exception
    _show_whole_map(at)
    assert not at.exception, at.exception
    _, data = _routing_editor(at)
    routing = requests.get(f"{fake_core}/routing", timeout=3).json()
    assert data == sh.routing_editor_data(routing, read_only=True, lock_reason=READ_ONLY_MESSAGE)


def test_an_auditor_who_is_one_of_the_people_sees_their_own_part(fake_core, tmp_path, monkeypatch):
    at = _incidents_page(fake_core, tmp_path, monkeypatch, role="auditor", operator="Team lead")
    assert not at.exception, at.exception
    _, data = _my_map(at)
    assert data["focus"] == "team_lead" and data["read_only"]
    assert data["numbers"] == [1, 2, 3]  # told about Critical, Attacker inside and High, by their places in the list
    assert {c["id"] for c in data["routing"]["contacts"]} == {"team_lead", "on_duty", "it_manager"}  # not the CXO
    assert "part_as" not in [s.key for s in at.selectbox]  # only Owners and Admins look as someone else
    assert any("You are told about" in m.value for m in at.markdown)


def test_someone_who_is_not_one_of_the_people_is_told_how_to_become_one(fake_core, tmp_path, monkeypatch):
    at = _incidents_page(fake_core, tmp_path, monkeypatch, role="auditor", operator="Visitor")
    assert not at.exception, at.exception
    assert _my_map(at) == (None, None)
    assert any("not one of the people" in i.value for i in at.info)


def test_an_owner_can_see_the_page_as_anyone(fake_core, tmp_path, monkeypatch):
    at = _incidents_page(fake_core, tmp_path, monkeypatch)
    assert _my_map(at) == (None, None)  # "erick" is none of the people yet
    at.selectbox(key="part_as").set_value("IT manager").run()
    assert not at.exception, at.exception
    _, data = _my_map(at)
    assert data["focus"] == "it_manager" and data["read_only"]
    _routing_editor(at)  # the whole map stays, to change


def test_how_it_works_draws_every_step_and_each_opens_a_page(fake_core, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["page"] = "flow"
    at.run()
    assert not at.exception, at.exception
    found = [json.loads(el.proto.json) for el in at.get("bidi_component") if el.proto.component_name.endswith("flow_map")]
    assert len(found) == 1
    data = found[0]
    pages = {"approvals", "incidents", "collector", "classifier", "responder", "review", "audit", "extensions", "config"}
    assert {n["id"] for n in data["nodes"]} == {"logs", "sort", "score", "ask", "auto", "block", "edge", "owner",
                                                "alerts", "record"}
    assert {n["page"] for n in data["nodes"]} <= pages
    ids = {n["id"] for n in data["nodes"]}
    assert all(e["from"] in ids and e["to"] in ids for e in data["edges"])


def _flow_page(fake_core, tmp_path, monkeypatch, role: str = ""):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    if role:
        monkeypatch.setenv("SENTRAI_DASHBOARD_ROLE", role)
    else:
        monkeypatch.delenv("SENTRAI_DASHBOARD_ROLE", raising=False)
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["page"] = "flow"
    at.run()
    return at


def _limits_map(at):
    found = [el for el in at.get("bidi_component") if el.proto.component_name.endswith("limits_map")]
    assert len(found) == 1
    return found[0], json.loads(found[0].proto.json)


def _press(at, el, event: str, value: dict) -> None:
    """What a component's trigger does in a browser (see _press_save)."""
    try:
        from streamlit.components.v2.bidi_component.main import _make_trigger_id
        from streamlit.proto.WidgetStates_pb2 import WidgetState
        states = at._tree.get_widget_states()
        run = at._run
    except (ImportError, AttributeError) as exc:
        pytest.skip(f"cannot press a component's trigger in this Streamlit's AppTest: {exc}")
    states.widgets.append(WidgetState(id=_make_trigger_id(el.proto.id, "events"),
                                      json_trigger_value=json.dumps([{"event": event, "value": value}])))
    run(states)


def test_the_limits_map_saves_to_the_settings_file(fake_core, tmp_path, monkeypatch):
    import sentrai_config as cfg

    at = _flow_page(fake_core, tmp_path, monkeypatch)
    assert not at.exception, at.exception
    el, data = _limits_map(at)
    assert not data["read_only"] and data["settings"]["AUTO_ACTIONS"] == "block_ip,rate_limit,waf_rule"
    sent = data["settings"] | {"AUTO_ACTIONS": "lock_user,block_ip", "RISK_THRESHOLD": "70"}
    _press(at, el, "save", {"id": "save-1", "settings": sent})
    assert all("fragment" in str(e.value) for e in at.exception), at.exception  # as with the routing editor
    saved = cfg.read()
    assert saved["AUTO_ACTIONS"] == "block_ip,lock_user" and saved["RISK_THRESHOLD"] == "70"
    at.run()
    _, data = _limits_map(at)
    assert data["result"]["ok"] and data["settings"]["RISK_THRESHOLD"] == "70"

    el, _ = _limits_map(at)
    _press(at, el, "save", {"id": "save-2", "settings": sent | {"NEEDLE_MIN_CONFIDENCE": "7"}})
    at.run()
    _, data = _limits_map(at)
    assert data["result"] == {"id": "save-2", "ok": False, "message": "Not saved: How sure it must be is out of range."}
    assert cfg.read()["NEEDLE_MIN_CONFIDENCE"] == "0.6"


def test_an_auditor_sees_the_limits_but_never_saves_them(fake_core, tmp_path, monkeypatch):
    import sentrai_config as cfg

    at = _flow_page(fake_core, tmp_path, monkeypatch, role="auditor")
    el, data = _limits_map(at)
    assert data["read_only"] and data["lock_reason"] == READ_ONLY_MESSAGE
    _press(at, el, "save", {"id": "save-1", "settings": data["settings"] | {"RISK_THRESHOLD": "1"}})
    assert not at.exception, at.exception
    assert cfg.read().get("RISK_THRESHOLD") != "1"


def test_saving_the_map_reaches_the_core_and_the_editor_hears_how_it_went(fake_core, tmp_path, monkeypatch):
    original = requests.get(f"{fake_core}/routing", timeout=3).json()
    at = _incidents_page(fake_core, tmp_path, monkeypatch)
    _, data = _routing_editor(at)
    routing = data["routing"]
    routing["rules"][0]["name"] = "Critical, all hands"
    routing["layout"] = {"incident": [0, 160], "rules": [[220, 0], [220, 90], [220, 180], [220, 270]],
                         "contacts": {"on_duty": [640, 40]}}
    try:
        _press_save(at, {"id": "save-1", "routing": routing, "summary": "Renamed Critical"})
        # AppTest runs the whole script, so the save's rerun of just the page part raises here; a browser reruns it.
        assert all("fragment" in str(e.value) for e in at.exception), at.exception
        saved = requests.get(f"{fake_core}/routing", timeout=3).json()
        assert saved["rules"][0]["name"] == "Critical, all hands" and saved["layout"] == routing["layout"]
        record = [r for r in requests.get(f"{fake_core}/audit", timeout=3).json()["records"]
                  if r["type"] == "routing_changed"][-1]["data"]
        assert record["operator"] == "erick" and record["summary"] == "Renamed Critical"
        at.run()
        assert not at.exception, at.exception
        _, data = _routing_editor(at)
        assert data["result"] == {"id": "save-1", "ok": True, "message": "Saved. Renamed Critical"}
        assert data["version"] == sh.routing_version(saved)  # the editor takes the saved routing as its own
        assert any("Who gets what saved" in t.value for t in at.toast)

        refused = copy.deepcopy(data["routing"])
        refused["rules"][0]["owner"] = "ghost"
        _press_save(at, {"id": "save-2", "routing": refused, "summary": "Gave Critical to a ghost"})
        at.run()
        _, data = _routing_editor(at)
        assert data["result"] == {"id": "save-2", "ok": False,  # the core's own words, for the editor to show
                                  "message": "rule 'Critical, all hands' needs an owner who is one of the people"}
        assert any("Who gets what not saved" in t.value for t in at.toast)
        assert requests.get(f"{fake_core}/routing", timeout=3).json() == saved
    finally:  # the fake core is shared by this file's tests: put the routing back
        requests.post(f"{fake_core}/routing", timeout=3, json={
            "routing": {**sh.routing_doc(original), "layout": original.get("layout") or {}}, "operator": "test"})


def test_an_auditors_map_never_saves(fake_core, tmp_path, monkeypatch):
    """Even when an Auditor's browser sends a Save (from the developer tools, say), nothing reaches the core."""
    before = requests.get(f"{fake_core}/routing", timeout=3).json()
    at = _incidents_page(fake_core, tmp_path, monkeypatch, role="auditor")
    _show_whole_map(at)
    _, data = _routing_editor(at)
    data["routing"]["rules"][0]["name"] = "Changed by an auditor"
    _press_save(at, {"id": "save-1", "routing": data["routing"], "summary": "Should not happen"})
    assert not at.exception, at.exception
    assert requests.get(f"{fake_core}/routing", timeout=3).json() == before
    assert "rt_result" not in at.session_state


def test_a_routing_blip_keeps_the_map_on_screen(fake_core, tmp_path, monkeypatch):
    """When one read of the routing fails, the map keeps the last copy, and with it a change half made there."""
    real = CoreClient.routing
    down = {"now": True}

    def routing(self):
        if down["now"]:
            raise CoreError("Core unreachable (ConnectionError)")
        return real(self)

    monkeypatch.setattr(CoreClient, "routing", routing)  # AppTest runs the app in this process
    at = _incidents_page(fake_core, tmp_path, monkeypatch)
    assert not at.exception, at.exception
    assert not at.get("bidi_component")  # no copy yet: nothing to draw
    assert any("Could not load the routing rules" in c.value for c in at.caption)
    down["now"] = False
    at.run()
    _, before = _routing_editor(at)
    down["now"] = True
    at.run()
    assert not at.exception, at.exception
    _, data = _routing_editor(at)
    assert data == before  # the same routing and version: the editor keeps what is on screen
    assert any("Showing the last copy" in c.value for c in at.caption)
