"""Sentry's proactive side: the briefing, the safety drill and "what happened then" (app/briefing.py)."""
import sentrai_llm
from app.chat import OperatorChat

from .conftest import brute_force, ev
from .test_chat import FakeProvider, call

INC = "RSK-2026-081"


def _contained(client):
    brute_force(client)
    client.post("/events", json=ev(10, "GET /search?q=' OR 1=1 -- 200", ip="198.51.100.7", source="flask_access"))


def test_briefing_splits_needs_you_from_handled(client):
    assert client.get("/chat/briefing").json()["headline"] == "All quiet. Nothing needs you."
    _contained(client)
    b = client.get("/chat/briefing").json()
    handled = {x["incident"] for x in b["handled"]}
    needs = {x["incident"] for x in b["needs_you"]}
    assert INC in handled and INC not in needs and handled.isdisjoint(needs)
    item = next(x for x in b["handled"] if x["incident"] == INC)
    assert item["did"] and item["fix_check"] == "check pending" and item["how_sure"].startswith("sure")
    assert b["handled_count"] == len(b["handled"]) and "handled" in b["headline"]
    assert "203.0.113.45" not in str(b)  # no raw addresses in the briefing


def test_briefing_lists_an_open_incident_that_needs_a_decision(client):
    brute_force(client)
    b = client.get("/chat/briefing").json()
    assert [x["incident"] for x in b["needs_you"]] == [INC]
    assert b["headline"].startswith("1 thing needs you")
    assert client.get(f"/incidents/{INC}").json()["status"] == "open"  # read-only


def test_drill_spots_every_pretend_attack_and_changes_nothing(client):
    before = (client.get("/incidents").json(), client.get("/blocklist").json())
    d = client.post("/chat/drill").json()
    assert [a["spotted"] for a in d["attacks"]] == [True] * 4
    assert {c["check"] for c in d["checks"]} >= {"Protection is switched on", "Every computer is reporting in"}
    assert (client.get("/incidents").json(), client.get("/blocklist").json()) == before
    assert client.get("/audit").json()["records"][-1]["type"] == "safety_drill"
    assert "Nothing was sent" in d["note"]


def test_drill_does_not_disturb_live_detection(client):
    brute_force(client, count=4)  # one guess short of an incident
    client.post("/chat/drill")
    brute_force(client, start=4, count=1)  # the fifth live guess still opens it: the drill used its own rules
    assert client.get(f"/incidents/{INC}").json()["category"] == "brute_force"


def test_drill_flags_paused_protection(client):
    client.post("/protection", json={"on": False, "operator": "erick", "reason": "testing"})
    d = client.post("/chat/drill").json()
    assert not d["passed"]
    assert next(c for c in d["checks"] if c["check"] == "Protection is switched on")["ok"] is False


def test_fallback_answers_drill_and_briefing_questions(client):
    r = client.post("/chat", json={"operator": "erick", "message": "Am I protected?"}).json()
    assert r["looked_at"] == ["safety drill"] and "only a drill" in r["text"]
    brute_force(client)
    r = client.post("/chat", json={"operator": "erick", "message": "What did I miss?"}).json()
    assert r["looked_at"] == ["briefing"] and INC in r["text"]
    assert [s["decision"] for s in r["suggestions"]] == ["approve"]


def test_timeline_finds_what_happened_in_a_window(client):
    brute_force(client)
    core = client.core
    now = core.clock.now()
    chat = client.app.state.chat
    out = chat._dispatch("get_timeline", {"from": core.clock.iso(now - 3600), "to": core.clock.iso(now + 60)}, [], [])
    assert INC in out and '"detected"' in out
    empty = chat._dispatch("get_timeline", {"from": core.clock.iso(now - 7200), "to": core.clock.iso(now - 3600)}, [], [])
    assert "Nothing happened" in empty


def test_model_gets_the_time_and_how_sure(client):
    brute_force(client)
    turns = [
        sentrai_llm.Turn(tool_calls=[call("get_incident", incident=INC)], stop="tool_use"),
        sentrai_llm.Turn(texts=["You're safe."]),
    ]
    p = FakeProvider(turns)
    chat = OperatorChat(client.core, p)
    chat.ask("erick", "how sure are you?")
    convo = p.convos[0]
    assert "Current time:" in convo.sent[0]
    assert "how_sure" in convo.results[0][0][1]
