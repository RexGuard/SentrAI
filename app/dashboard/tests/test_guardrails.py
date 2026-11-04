"""The pipeline overview, split from Automation guardrails: the map's cards (counts, badges, tips), the
guardrails page (its own page, checked saves, who changed it last), each step's "How this step works" and
the "awaiting review" line under the risk index."""
import ast
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentrai_ui import shaping as sh

APP = str(Path(__file__).resolve().parents[1] / "app.py")


def _nodes(**kw):
    args = dict(risk={"risk_index": 0, "band": "green", "threshold": 80}, incidents=[], agents=[], blocklist={},
                extensions=[], records=[], settings={"AUTO_ACTIONS": "block_ip,rate_limit", "HOTPATCH_TTL_HOURS": "2"},
                chain_ok=True)
    return {n["id"]: n for n in sh.flow_map_data(**(args | kw))["nodes"]}


# ------------------------------------------------- the map's cards

def test_switches_are_badges_and_the_big_number_is_always_a_count():
    nodes = _nodes(extensions=[{"name": "cloudflare", "added": True, "configured": True}])
    assert nodes["auto"]["badge"] == "On" and nodes["auto"]["value"] == "2"
    assert nodes["edge"]["badge"] == "On" and nodes["edge"]["value"] is None
    for n in nodes.values():
        assert n["value"] is None or n["value"] == "-" or n["value"].replace(",", "").isdigit(), n


def test_the_danger_score_reads_as_a_score_not_a_count_of_things_scored():
    score = _nodes()["score"]
    assert score["title"] == "Danger score" and score["value"] == "0" and score["unit"] == "/ 100"
    assert "acts on its own from 80" in score["note"]


def test_every_card_explains_itself_in_full_for_the_hover_tip():
    for n in _nodes().values():
        assert n["what"].endswith(".") and len(n["what"]) > 40, n["id"]
    assert _nodes()["auto"]["page"] == "guardrails"


def test_the_ribbon_carries_the_pipeline_s_live_numbers_in_order():
    waiting = {"id": "1", "status": "open", "category": "brute_force", "recommended_action": "block_ip",
               "requires_approval": True}
    cells = sh.pipeline_ribbon(sh.flow_map_data({"risk_index": 50}, [waiting], [{"name": "a", "analyzed": 2716}],
                                                {"ips": ["203.0.113.4"]}, [], [], {}, True))
    assert [(c["value"], c["label"]) for c in cells] == [("2,716", "lines read"), ("0", "sorted as attacks"),
                                                          ("1", "waiting for a person"), ("1", "blocked now")]


# ------------------------------------------------- guardrails: checks and "last changed"

LIMITS = {"AUTO_ACTIONS": "block_ip", "NEEDLE_MIN_CONFIDENCE": "0.6", "RISK_THRESHOLD": "80",
          "MAX_AUTO_ACTIONS_PER_HOUR": "10", "HOTPATCH_TTL_HOURS": "2", "MAX_TTL_HOURS": "24",
          "PROTECTED_IPS": "127.0.0.1,::1,localhost", "PROTECTED_USERS": ""}


@pytest.mark.parametrize("text", ["127.0.0.1", "10.0.0.0/8", "::1", "2001:db8::/32", "localhost", "db-1.internal"])
def test_never_touched_takes_addresses_networks_and_host_names(text):
    assert sh.protected_address_ok(text)


@pytest.mark.parametrize("text", ["10.0.0.300", "10.0.0", "10.0.0.0/33", "fe80:::1", "-bad", "a b"])
def test_never_touched_refuses_typos(text):
    assert not sh.protected_address_ok(text)


def test_a_save_with_a_typo_in_never_touched_is_refused_and_repeats_are_dropped():
    with pytest.raises(ValueError, match="10.0.0.300"):
        sh.check_limits(LIMITS | {"PROTECTED_IPS": "127.0.0.1,10.0.0.300"})
    with pytest.raises(ValueError, match="space"):
        sh.check_limits(LIMITS | {"PROTECTED_USERS": "two words"})
    assert sh.check_limits(LIMITS | {"PROTECTED_IPS": "127.0.0.1, 127.0.0.1,::1"})["PROTECTED_IPS"] == "127.0.0.1,::1"


def test_last_changed_says_who_and_when_and_falls_back_to_the_file_time():
    now = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)
    earlier = (now - timedelta(hours=2, minutes=5)).isoformat()
    assert sh.guardrails_changed({"at": earlier, "by": "Erick S"}, None, now) == "Changed 2 h 5 min ago by Erick S"
    assert sh.guardrails_changed({}, (now - timedelta(minutes=5)).timestamp(), now) == "Changed 5 min ago"
    assert sh.guardrails_changed(None, None, now) == "Never changed"


# ------------------------------------------------- the pages

def _functions():
    tree = ast.parse(Path(APP).read_text(encoding="utf-8"))
    return {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}


def test_the_guardrails_page_never_refreshes_itself_and_the_overview_holds_no_settings():
    fns = _functions()
    assert not fns["page_guardrails"].decorator_list  # an auto-refresh would redraw it under someone's typing
    overview = ast.unparse(fns["page_flow"])
    assert "LIMITS_MAP" not in overview and "limits_map(" not in overview
    assert len(fns["page_flow"].decorator_list) == 1


def _page(fake_core, tmp_path, monkeypatch, page: str, role: str = ""):
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
    at.session_state["page"] = page
    at.run()
    assert not at.exception, at.exception
    return at


def _html(at) -> str:
    return "\n".join(m.value for m in at.markdown)


def test_saving_the_guardrails_notes_who_changed_them(fake_core, tmp_path, monkeypatch):
    try:
        from streamlit.components.v2.bidi_component.main import _make_trigger_id
        from streamlit.proto.WidgetStates_pb2 import WidgetState
    except ImportError as exc:
        pytest.skip(f"cannot press a component's trigger in this Streamlit's AppTest: {exc}")
    at = _page(fake_core, tmp_path, monkeypatch, "guardrails")
    assert "Policy: active" in _html(at)
    el = next(e for e in at.get("bidi_component") if e.proto.component_name.endswith("limits_map"))
    data = json.loads(el.proto.json)
    states = at._tree.get_widget_states()
    states.widgets.append(WidgetState(id=_make_trigger_id(el.proto.id, "events"), json_trigger_value=json.dumps(
        [{"event": "save", "value": {"id": "save-1", "settings": data["settings"] | {"NEEDLE_MIN_CONFIDENCE": "0.75"}}}])))
    at._run(states)
    note = json.loads((tmp_path / "guardrails-changed.json").read_text(encoding="utf-8"))
    assert note["by"] == "erick" and datetime.fromisoformat(note["at"])
    at.run()
    assert "Changed just now by erick" in _html(at)


def test_step_help_starts_open_and_turns_into_the_ribbon_once_put_away(fake_core, tmp_path, monkeypatch):
    at = _page(fake_core, tmp_path, monkeypatch, "classifier")
    assert "How this step works" in _html(at) and 'class="ribbon"' not in _html(at)
    next(b for b in at.button if b.label == "Got it, hide this").click()
    at.run()
    assert 'class="ribbon"' in _html(at) and "sorted as attacks" in _html(at)
    seen = json.loads((tmp_path / "help-dismissed.json").read_text(encoding="utf-8"))
    assert seen == {"_": ["classifier"]}
    # put away on one step only: the next step still explains itself
    at.session_state["page"] = "responder"
    at.run()
    assert 'class="ribbon"' not in _html(at) and "How this step works" in _html(at)


def test_the_sidebar_says_how_many_actions_wait_under_the_risk_index(fake_core, tmp_path, monkeypatch):
    import requests

    at = _page(fake_core, tmp_path, monkeypatch, "flow")
    side = "\n".join(m.value for m in at.sidebar.markdown)
    waiting = len(sh.pending_approvals(requests.get(f"{fake_core}/incidents", timeout=3).json()))
    if waiting:
        assert f"{sh.plural(waiting, 'action')} awaiting review" in side
    else:
        assert 'class="side-waiting"' not in side
