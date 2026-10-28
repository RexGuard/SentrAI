"""The Pipeline overview as a canvas (sentrai_ui/flow_canvas.mjs, shaping.flow_canvas_data): every step, machine
and extension is a block with its live numbers and its own settings; the layout saves itself next to the
settings; a block's settings are checked and written like the Configuration page writes them; a new machine
joins through the same join code as the Machines page; Auditors look and change nothing."""
import json
import sys
from pathlib import Path

import pytest
import requests

sys.path.append(str(Path(__file__).resolve().parents[2]))
import sentrai_config as cfg  # noqa: E402
from sentrai_ui import shaping as sh  # noqa: E402

APP = str(Path(__file__).resolve().parents[1] / "app.py")
SECRETS = {f.env for f in cfg.FIELDS.values() if f.secret or f.generated}


def _flow(**kw):
    args = dict(risk={"risk_index": 0, "band": "green", "threshold": 80}, incidents=[], agents=[], blocklist={},
                extensions=[], records=[], settings={}, chain_ok=True)
    return sh.flow_map_data(**(args | kw))


# ------------------------------------------------- the data the canvas draws

def test_every_step_machine_and_extension_is_a_block_and_no_secret_goes_to_the_browser():
    exts = [{"name": "cloudflare", "title": "Cloudflare", "kind": "Blocking", "added": True, "configured": True, "what": "Edge."},
            {"name": "slack", "title": "Slack", "kind": "Alerts", "added": False, "configured": False, "what": "Chat."},
            {"name": "typesafe", "title": "TypeSafe", "kind": "Classifier", "added": True, "configured": False},
            {"name": "email", "title": "Email", "kind": "Alerts", "built_in": True, "added": True}]
    machines = [{"name": "web-01", "host": "web-01", "place": "Agent", "online": True, "index": 42.0, "band": "amber",
                 "threshold": 80.0, "monitor_only": False, "open": 1, "contained": 0, "blocked": 2, "last_seen": None,
                 "services": [{"name": "sshd", "port": 22}]},
                {"name": "office-pc", "host": "office-pc", "place": "Agent", "online": False, "waiting": True, "index": None,
                 "band": "unknown", "threshold": 80.0, "monitor_only": False, "open": 0, "contained": 0, "blocked": 0}]
    settings = {f.env: f.default for f in cfg.FIELDS.values()} | {"CLOUDFLARE_API_TOKEN": "cf-secret", "RISK_THRESHOLD": "75"}
    ext_fields = {n: [f.env for f in s.fields] for n, s in cfg.EXTENSION_SECTIONS.items()}
    data = sh.flow_canvas_data(_flow(extensions=exts, settings=settings), machines, exts, settings, cfg.FIELDS, ext_fields,
                               {"hidden": ["machine:office-pc"]}, panel=True)
    by_id = {b["id"]: b for b in data["blocks"]}
    assert {k for k in by_id if k.startswith("step:")} == {f"step:{s}" for s in
                                                            ("logs", "sort", "score", "ask", "auto", "block", "edge", "owner", "alerts", "record")}
    assert {k for k in by_id if k.startswith("machine:")} == {"machine:web-01", "machine:office-pc"}
    assert {k for k in by_id if k.startswith("ext:")} == {"ext:cloudflare", "ext:slack", "ext:typesafe"}  # built-ins are steps already
    # on by default: every step and machine, and the extensions that are added; Slack waits under + Add
    assert "ext:cloudflare" in data["defaults"] and "ext:typesafe" in data["defaults"] and "ext:slack" not in data["defaults"]
    assert "machine:office-pc" in data["defaults"] and data["doc"]["hidden"] == ["machine:office-pc"]
    # each block's settings are its own, never a key or token, and show the saved value
    sent = {s["env"] for b in data["blocks"] for s in b["settings"]}
    assert sent and not sent & SECRETS, sent & SECRETS
    assert "cf-secret" not in json.dumps(data)
    score = {s["env"]: s for s in by_id["step:score"]["settings"]}
    assert score["RISK_THRESHOLD"]["value"] == "75" and score["RISK_THRESHOLD"]["kind"] == "int"
    auto = {s["env"]: s for s in by_id["step:auto"]["settings"]}
    assert auto["AUTO_ACTIONS"]["kind"] == "set" and ["block_ip", "block an address"] in auto["AUTO_ACTIONS"]["choices"]
    assert {s["env"] for s in by_id["ext:cloudflare"]["settings"]} == {"CLOUDFLARE_ZONE_ID", "CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_METHOD",
                                                                      "CLOUDFLARE_LIST_ID", "CLOUDFLARE_MODE", "CLOUDFLARE_TIMEOUT_S"}
    # machines: the risk number, the state, facts for the panel, and a way to their own page
    web = by_id["machine:web-01"]
    assert web["value"] == "42" and web["unit"] == "/ 100" and web["state"] == "alert" and web["page"] == "machine" and web["host"] == "web-01"
    assert ["Blocks", "2 in force"] in web["facts"] and any(f[0] == "Services" and "sshd" in f[1] for f in web["facts"])
    assert by_id["machine:office-pc"]["state"] == "unknown" and "waiting" in by_id["machine:office-pc"]["note"]
    # extensions: a switch, which way they plug in, and the words said before turning one off
    cf = by_id["ext:cloudflare"]
    assert cf["switch"] == {"name": "cloudflare", "title": "Cloudflare", "on": True, "managed": False,
                            "off_note": sh.extension_removal_note("Blocking", "Cloudflare")}
    assert cf["state"] == "ok" and cf["badge"] == "On" and cf["step"] == "edge"
    assert by_id["ext:typesafe"]["state"] == "alert" and "needs its key" in by_id["ext:typesafe"]["note"]
    assert by_id["ext:slack"]["state"] == "off" and by_id["ext:slack"]["badge"] == "Off"
    wires = {(w["from"], w["to"]) for w in data["wires"]}
    assert ("machine:web-01", "step:logs") in wires and ("step:edge", "ext:cloudflare") in wires
    assert ("ext:typesafe", "step:sort") in wires and ("step:alerts", "ext:slack") in wires
    ids = set(by_id)
    assert all(a in ids and b in ids for a, b in wires)
    assert len(data["version"]) == 16 and not data["read_only"]


def test_without_a_central_panel_the_machine_blocks_open_the_machines_page():
    found = [sh.machine("This computer", "Local", {"risk_index": 12, "band": "green", "threshold": 80})]
    data = sh.flow_canvas_data(_flow(), found, [], {}, cfg.FIELDS, {}, None, panel=False)
    m = next(b for b in data["blocks"] if b["kind"] == "machine")
    assert m["id"] == "machine:This computer" and m["page"] == "machines" and m["host"] == "" and m["value"] == "12"


def test_the_saved_layout_file_is_cleaned_so_junk_never_breaks_the_page():
    doc = sh.clean_canvas_doc({"version": 9, "hidden": ["step:score", "step:score", 3, ""], "added": "no", "junk": 1,
                               "notes": {"note:1": "fine", "note:x": "bad id", "note:2": 5, "note:3": "y" * 5000},
                               "pos": {"step:logs": [1.6, -2.2], "step:sort": [1], "ext:a": ["1", "2"], "far": [1e9, 5],
                                       "nan": [1, float("nan")], "step:score": [True, 1]},
                               "wires": {"added": [["a", "b"], ["a", "b"], ["a", "a"], ["a"]], "removed": "x"}})
    assert doc == {"version": 1, "hidden": ["step:score"], "added": [], "notes": {"note:1": "fine", "note:3": "y" * 2000},
                   "pos": {"step:logs": [2, -2], "far": [100_000, 5]}, "wires": {"added": [["a", "b"]], "removed": []}}
    assert sh.clean_canvas_doc("nonsense") == {"version": 1, "hidden": [], "added": [], "notes": {}, "pos": {},
                                               "wires": {"added": [], "removed": []}}


def test_a_block_s_settings_are_checked_by_kind_and_only_its_own_are_taken():
    specs = sh.setting_specs(sh.BLOCK_SETTINGS["auto"] + sh.BLOCK_SETTINGS["alerts"], cfg.FIELDS,
                             {f.env: f.default for f in cfg.FIELDS.values()})
    assert sh.check_block_settings({"MAX_AUTO_ACTIONS_PER_HOUR": " 7 ", "AUTO_ACTIONS": "rate_limit, block_ip"}, specs) == {
        "MAX_AUTO_ACTIONS_PER_HOUR": "7", "AUTO_ACTIONS": "block_ip,rate_limit"}
    with pytest.raises(ValueError, match="whole number"):
        sh.check_block_settings({"MAX_AUTO_ACTIONS_PER_HOUR": "7.5"}, specs)
    with pytest.raises(ValueError, match="must be a number"):
        sh.check_block_settings({"NEEDLE_MIN_CONFIDENCE": "inf"}, specs)
    with pytest.raises(ValueError, match="one of"):
        sh.check_block_settings({"SMTP_SECURITY": "tls"}, specs)
    with pytest.raises(ValueError, match="does not know"):
        sh.check_block_settings({"AUTO_ACTIONS": "block_ip,format_disk"}, specs)
    with pytest.raises(ValueError, match="not a setting of this block"):
        sh.check_block_settings({"SMTP_PASSWORD": "x"}, specs)
    with pytest.raises(ValueError, match="nothing changed"):
        sh.check_block_settings({}, specs)


# ------------------------------------------------- the page

def _page(fake_core, tmp_path, monkeypatch, role: str = ""):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    if role:
        monkeypatch.setenv("SENTRAI_DASHBOARD_ROLE", role)
    else:
        monkeypatch.delenv("SENTRAI_DASHBOARD_ROLE", raising=False)
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.session_state["operator"] = "erick"
    at.session_state["page"] = "flow"
    at.run()
    assert not at.exception, at.exception
    return at


def _canvas(at):
    found = [el for el in at.get("bidi_component") if el.proto.component_name.endswith("flow_canvas")]
    assert len(found) == 1
    return found[0], json.loads(found[0].proto.json)


def _press(at, el, event: str, value: dict) -> None:
    """What the canvas's trigger does in a browser: the event lands in the fragment, which answers with a rerun."""
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
    assert not at.exception, at.exception


def _answer(at, event_id: str) -> dict:
    at.run()
    assert not at.exception, at.exception
    _, data = _canvas(at)
    return next(r for r in data["results"] if r["id"] == event_id)


def _html(at) -> str:
    return "\n".join(m.value for m in at.markdown)


def test_the_canvas_shows_the_fake_panel_s_machines_and_extensions(fake_core, tmp_path, monkeypatch):
    at = _page(fake_core, tmp_path, monkeypatch)
    _, data = _canvas(at)
    ids = {b["id"] for b in data["blocks"]}
    assert {"machine:web-01", "machine:office-pc", "ext:cloudflare", "ext:telegram", "ext:slack"} <= ids
    assert data["panel"] and not data["read_only"] and data["doc"]["pos"] == {}
    assert "ext:slack" not in data["defaults"]  # not added: under + Add


def test_moving_blocks_saves_the_layout_next_to_the_settings(fake_core, tmp_path, monkeypatch):
    at = _page(fake_core, tmp_path, monkeypatch)
    el, _ = _canvas(at)
    doc = {"version": 1, "hidden": ["machine:office-pc"], "added": ["ext:slack"], "notes": {"note:1": "Watch web-01 tonight"},
           "pos": {"step:logs": [10, 20], "ext:slack": [600, 400], "note:1": [900, 0]},
           "wires": {"added": [["ext:slack", "step:logs"]], "removed": [["step:block", "step:edge"]]}, "junk": True}
    _press(at, el, "save_layout", {"id": "layout-1", "doc": doc})
    saved = json.loads((tmp_path / "overview-canvas.json").read_text(encoding="utf-8"))
    assert saved == {k: v for k, v in doc.items() if k != "junk"}
    answer = _answer(at, "layout-1")
    assert answer["ok"] and answer["message"] == "Layout saved."
    _, data = _canvas(at)
    assert data["doc"]["notes"] == {"note:1": "Watch web-01 tonight"} and data["doc"]["pos"]["step:logs"] == [10, 20]


def test_saving_a_block_s_settings_writes_the_settings_file_and_notes_a_guardrail_change(fake_core, tmp_path, monkeypatch):
    at = _page(fake_core, tmp_path, monkeypatch)
    el, _ = _canvas(at)
    _press(at, el, "save_settings", {"id": "set-1", "block": "step:sort", "title": "Sorted", "changes": {"BRUTE_FORCE_COUNT": "9"}})
    assert cfg.read()["BRUTE_FORCE_COUNT"] == "9"
    assert not (tmp_path / "guardrails-changed.json").exists()  # not a guardrail
    answer = _answer(at, "set-1")
    assert answer["ok"] and "Restart SentrAI" in answer["message"]
    el, data = _canvas(at)
    sort = next(b for b in data["blocks"] if b["id"] == "step:sort")
    assert next(s["value"] for s in sort["settings"] if s["env"] == "BRUTE_FORCE_COUNT") == "9"
    _press(at, el, "save_settings", {"id": "set-2", "block": "step:auto", "title": "Acts on its own",
                                     "changes": {"MAX_AUTO_ACTIONS_PER_HOUR": "4", "AUTO_ACTIONS": "block_ip"}})
    saved = cfg.read()
    assert saved["MAX_AUTO_ACTIONS_PER_HOUR"] == "4" and saved["AUTO_ACTIONS"] == "block_ip" and saved["BRUTE_FORCE_COUNT"] == "9"
    note = json.loads((tmp_path / "guardrails-changed.json").read_text(encoding="utf-8"))
    assert note["by"] == "erick"
    assert _answer(at, "set-2")["ok"]


def test_a_wrong_value_is_refused_with_a_reason_and_nothing_is_written(fake_core, tmp_path, monkeypatch):
    at = _page(fake_core, tmp_path, monkeypatch)
    el, _ = _canvas(at)
    before = cfg.read()
    _press(at, el, "save_settings", {"id": "set-bad", "block": "step:score", "title": "Danger score", "changes": {"RISK_THRESHOLD": "180"}})
    answer = _answer(at, "set-bad")
    assert not answer["ok"] and "out of range" in answer["message"]
    assert cfg.read() == before
    el, _ = _canvas(at)
    _press(at, el, "save_settings", {"id": "set-bad2", "block": "step:score", "title": "Danger score", "changes": {"SMTP_HOST": "x"}})
    assert "not a setting of this block" in _answer(at, "set-bad2")["message"]


def test_the_switch_on_an_extension_block_adds_and_removes_it(fake_core, tmp_path, monkeypatch):
    at = _page(fake_core, tmp_path, monkeypatch)
    el, _ = _canvas(at)
    _press(at, el, "toggle", {"id": "tog-1", "block": "ext:slack", "name": "slack", "title": "Slack", "on": True})
    assert next(r for r in requests.get(f"{fake_core}/extensions", timeout=3).json() if r["name"] == "slack")["added"]
    answer = _answer(at, "tog-1")
    assert answer["ok"] and answer["message"].startswith("Added Slack")
    el, data = _canvas(at)
    assert "ext:slack" in data["defaults"]
    _press(at, el, "toggle", {"id": "tog-2", "block": "ext:slack", "name": "slack", "title": "Slack", "on": False})
    assert not next(r for r in requests.get(f"{fake_core}/extensions", timeout=3).json() if r["name"] == "slack")["added"]
    assert _answer(at, "tog-2")["message"].startswith("Removed Slack")
    el, _ = _canvas(at)
    _press(at, el, "toggle", {"id": "tog-3", "block": "ext:x", "name": "../x", "title": "x", "on": True})
    assert "not an extension's name" in _answer(at, "tog-3")["message"]


def test_new_machine_opens_the_join_form_under_the_canvas(fake_core, tmp_path, monkeypatch):
    at = _page(fake_core, tmp_path, monkeypatch)
    el, _ = _canvas(at)
    assert not any(b.label == "Make join code" for b in at.button)
    _press(at, el, "add_machine", {"id": "machine-1"})
    at.run()
    assert not at.exception, at.exception
    next(b for b in at.button if b.label == "Make join code").click()
    at.run()
    assert "K7QM-2XPA-9RTD" in _html(at)  # the fake core's code, with the join commands
    next(b for b in at.button if b.label == "Close").click()
    at.run()
    assert not at.exception, at.exception
    assert not any(b.label == "Make join code" for b in at.button)
    _canvas(at)  # the canvas is still there


def test_an_auditor_looks_but_changes_nothing(fake_core, tmp_path, monkeypatch):
    at = _page(fake_core, tmp_path, monkeypatch, role="auditor")
    el, data = _canvas(at)
    assert data["read_only"] and data["lock_reason"]
    before = cfg.read()
    _press(at, el, "save_layout", {"id": "ro-1", "doc": {"pos": {"step:logs": [1, 1]}}})
    assert not (tmp_path / "overview-canvas.json").exists()
    assert not _answer(at, "ro-1")["ok"]
    el, _ = _canvas(at)
    _press(at, el, "save_settings", {"id": "ro-2", "block": "step:score", "title": "Danger score", "changes": {"RISK_THRESHOLD": "70"}})
    assert cfg.read() == before and not _answer(at, "ro-2")["ok"]
    el, _ = _canvas(at)
    _press(at, el, "add_machine", {"id": "ro-3"})
    at.run()
    assert not any(b.label == "Make join code" for b in at.button)
