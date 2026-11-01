"""Operator chat: read-only answers, suggestions as buttons, never a state change by itself."""

import sentrai_llm
from app.chat import OperatorChat

from .conftest import brute_force, ev

INC = "RSK-2026-081"


class FakeConvo:
    """Stands in for the model: plays scripted turns and records the tool results it got back."""

    def __init__(self, turns):
        self.turns, self.sent, self.results = list(turns), [], []

    def send_user(self, text):
        self.sent.append(text)
        return self.turns.pop(0)

    def send_tool_results(self, results):
        self.results.append(results)
        return self.turns.pop(0)


class FakeProvider(sentrai_llm.Provider):
    name, model = "fake", "fake-1"

    def __init__(self, turns=None, error=None):
        self.turns, self.error, self.convos = turns or [], error, []

    def conversation(self, system, tools):
        if self.error:
            raise sentrai_llm.LLMError(self.error)
        c = FakeConvo(self.turns)
        self.convos.append(c)
        return c


def call(name, **args):
    return sentrai_llm.ToolCall(f"t-{name}", name, args)


def test_chat_without_a_key_explains_from_the_core(client):
    brute_force(client)
    r = client.post("/chat", json={"operator": "erick", "message": f"why is {INC} open?"})
    assert r.status_code == 200
    reply = r.json()
    assert reply["role"] == "assistant" and reply["source"] == "fallback"
    assert INC in reply["text"] and reply["looked_at"] == [f"explanation for {INC}"]
    assert [x["decision"] for x in reply["suggestions"]] == ["approve"]  # buttons only; nothing applied
    assert client.get(f"/incidents/{INC}").json()["status"] == "open"
    hist = client.get("/chat").json()
    assert [m["role"] for m in hist["messages"]] == ["operator", "assistant"]
    assert hist["messages"][0]["operator"] == "erick"
    audit = client.get("/audit").json()["records"]
    assert audit[-1]["type"] == "operator_chat" and audit[-1]["data"]["question"] == f"why is {INC} open?"


def test_chat_about_a_blocked_ip_offers_keep_or_roll_back(client):
    brute_force(client)
    client.post("/events", json=ev(10, "GET /search?q=' OR 1=1 -- 200", ip="198.51.100.7", source="flask_access"))  # over 80: contained
    assert client.get(f"/incidents/{INC}").json()["status"] == "contained"
    reply = client.post("/chat", json={"operator": "erick", "message": "why is 203.0.113.45 blocked?"}).json()
    assert "203.0.113.45" in reply["text"]
    assert [x["decision"] for x in reply["suggestions"]] == ["make_permanent", "rollback"]
    assert "203.0.113.45" in client.get("/blocklist").json()["ips"]  # still just a suggestion


def test_chat_overview_when_nothing_is_named(client):
    brute_force(client)
    reply = client.post("/chat", json={"operator": "erick", "message": "what's going on?"}).json()
    assert "Risk index is" in reply["text"] and INC in reply["text"]


def test_empty_message_is_rejected(client):
    assert client.post("/chat", json={"operator": "erick", "message": "   "}).status_code == 400


def test_clear_empties_the_chat(client):
    client.post("/chat", json={"operator": "erick", "message": "status?"})
    client.post("/chat/clear")
    assert client.get("/chat").json()["messages"] == []


def test_model_reads_with_tools_and_can_only_suggest(client):
    brute_force(client)
    core = client.core
    before = core.get_incident(INC)["status"]
    provider = FakeProvider([
        sentrai_llm.Turn(tool_calls=[call("get_incident", incident=INC)], stop="tool_use"),
        sentrai_llm.Turn(tool_calls=[call("suggest_action", incident=INC, decision="approve",
                                         reason="Guessing the admin password from one address")], stop="tool_use"),
        sentrai_llm.Turn(texts=[f"{INC} is a password-guessing attack. Press the button to block it."]),
    ])
    chat = OperatorChat(core, provider)
    reply = chat.ask("erick", "should I block it?", INC)
    assert reply["source"] == "ai" and "password-guessing" in reply["text"]
    assert reply["looked_at"] == [f"incident {INC}"]
    assert reply["suggestions"] == [{"incident": INC, "decision": "approve", "label": f"Approve & patch {INC}",
                                     "reason": "Guessing the admin password from one address", "status": before}]
    assert core.get_incident(INC)["status"] == before  # a suggestion changes nothing
    convo = provider.convos[0]
    assert f"incident {INC} selected" in convo.sent[0]
    assert '"latest_events"' in convo.results[0][0][1]


def test_unknown_incident_is_a_tool_error_not_a_crash(client):
    provider = FakeProvider([
        sentrai_llm.Turn(tool_calls=[call("suggest_action", incident="RSK-9999-999", decision="approve", reason="x")],
                        stop="tool_use"),
        sentrai_llm.Turn(texts=["I could not find that incident."]),
    ])
    reply = OperatorChat(client.core, provider).ask("erick", "approve RSK-9999-999")
    assert reply["suggestions"] == []
    assert provider.convos[0].results[0][0][2] is True  # is_error


def test_model_failure_falls_back(client):
    brute_force(client)
    reply = OperatorChat(client.core, FakeProvider(error="timeout")).ask("erick", f"explain {INC}")
    assert reply["source"] == "fallback" and "unavailable" in reply["text"] and INC in reply["text"]


def test_earlier_messages_are_passed_to_the_model(client):
    provider = FakeProvider([sentrai_llm.Turn(texts=["first"]), sentrai_llm.Turn(texts=["second"])])
    chat = OperatorChat(client.core, provider)
    chat.ask("erick", "hello")
    chat.ask("erick", "and again?")
    prompt = provider.convos[1].sent[0]
    assert "Operator: hello" in prompt and f"{client.core.name}: first" in prompt


class SetupProvider(sentrai_llm.Provider):
    name, model = "fake", "fake-1"

    def __init__(self, out=None, error=None):
        self.out, self.error, self.asked = out, error, []

    def complete_json(self, system, user, schema):
        if self.error:
            raise sentrai_llm.LLMError(self.error)
        self.asked.append((user, schema))
        return self.out


SETUP = {"question": "What does SentrAI guard?", "answer": "a dental clinic",
         "options": [{"value": "sensitive", "label": "Sensitive records"}, {"value": "office", "label": "Office"}]}


def test_setup_interpret_without_a_key_leaves_the_script_in_charge(client):
    r = client.post("/chat/setup/interpret", json=SETUP)
    assert r.status_code == 200 and r.json() == {"ai": False, "choice": "", "reply": ""}


def test_setup_interpret_maps_an_answer_to_an_option(client):
    chat = client.app.state.chat
    chat.provider = SetupProvider({"choice": "sensitive", "reply": "Patient records are sensitive."})
    r = client.post("/chat/setup/interpret", json=SETUP).json()
    assert r == {"ai": True, "choice": "sensitive", "reply": "Patient records are sensitive."}
    user, schema = chat.provider.asked[0]
    assert "a dental clinic" in user and schema["properties"]["choice"]["enum"] == ["sensitive", "office", ""]
    chat.provider = SetupProvider({"choice": "made-up", "reply": ""})  # never an option that was not offered
    assert client.post("/chat/setup/interpret", json=SETUP).json()["choice"] == ""
    chat.provider = SetupProvider(error="boom")
    assert client.post("/chat/setup/interpret", json=SETUP).json()["ai"] is False


def test_overview_carries_figures_table_chart_and_followups(client):
    brute_force(client)
    reply = client.post("/chat", json={"operator": "erick", "message": "are we safe?"}).json()
    kinds = [b["type"] for b in reply["blocks"]]
    assert kinds[:2] == ["stats", "table"]
    table = reply["blocks"][1]
    assert table["link"] == "incident" and table["rows"][0][0] == INC
    assert reply["followups"] and reply["question"] == "are we safe?"


def test_week_question_draws_a_chart(client):
    brute_force(client)
    reply = client.post("/chat", json={"operator": "erick", "message": "Summarise this week for me"}).json()
    chart = next(b for b in reply["blocks"] if b["type"] == "chart")
    assert chart["kind"] == "bar" and len(chart["labels"]) == 7 and sum(chart["series"][0]["values"]) >= 1


def test_model_can_draw_tables_and_charts():
    from app.chat import OperatorChat as OC
    oc = OC(None)
    rich = {"blocks": [], "followups": []}
    OC._dispatch(oc, "show_table", {"title": "T", "columns": ["a"], "rows": [["1"]]}, [], [], rich)
    OC._dispatch(oc, "show_chart", {"title": "C", "kind": "line", "labels": ["x", "y"],
                                    "series": [{"name": "s", "values": [1, 2]}], "unit": "n"}, [], [], rich)
    OC._dispatch(oc, "suggest_followups", {"questions": ["a?", "b?", "c?", "d?"]}, [], [], rich)
    assert [b["type"] for b in rich["blocks"]] == ["table", "chart"] and rich["followups"] == ["a?", "b?", "c?"]


def test_feedback_is_kept_and_counted(client):
    reply = client.post("/chat", json={"operator": "erick", "message": "are we safe?"}).json()
    r = client.post(f"/chat/{reply['id']}/feedback", json={"vote": "down", "note": "too technical"})
    assert r.status_code == 200 and r.json()["feedback"]["vote"] == "down"
    assert client.get("/chat").json()["messages"][-1]["feedback"]["note"] == "too technical"
    assert client.post(f"/chat/{reply['id']}/feedback", json={"vote": "meh"}).status_code == 400
    assert client.post("/chat/9999/feedback", json={"vote": "up"}).status_code == 404
    assert client.post(f"/chat/{reply['id'] - 1}/feedback", json={"vote": "up"}).status_code == 404  # a question
    assert client.get("/ui/tuning").json()["answers"]["down"] == 1
    assert client.get("/audit").json()["records"][-1]["type"] == "chat_feedback"


def test_rich_blocks_are_cut_to_size():
    from app import chat as chatmod
    t = chatmod.table("Active", ["Incident", "What"], [["RSK-1", "x" * 500, "extra"]], link="incident")
    assert t["rows"][0] == ["RSK-1", "x" * 200] and t["link"] == "incident"
    c = chatmod.chart("Per day", "bar", ["a", "b"], [{"name": "n", "values": [1, True, 3]}])
    assert c["series"][0]["values"] == [1.0, 0.0]
    import pytest
    with pytest.raises(ValueError):
        chatmod.chart("x", "pie", ["a"], [{"name": "n", "values": [1]}])


def test_stream_sends_steps_text_and_done(client):
    import json as _json
    brute_force(client)
    with client.stream("POST", "/chat/stream", json={"operator": "erick", "message": "are we safe?"}) as r:
        assert r.status_code == 200 and r.headers["content-type"].startswith("application/x-ndjson")
        events = [_json.loads(x) for x in r.iter_lines() if x]
    kinds = [e["type"] for e in events]
    assert kinds[0] == "step" and "text" in kinds and kinds[-1] == "done"
    text = "".join(e["delta"] for e in events if e["type"] == "text")
    assert text == events[-1]["message"]["text"] and events[-1]["message"]["blocks"]
    assert client.post("/chat/stream", json={"operator": "erick", "message": "  "}).status_code == 400


def test_stop_keeps_what_was_sent(client):
    import threading as _t
    r = client.post("/chat", json={"operator": "erick", "message": "are we safe?"}).json()
    assert "stopped" not in r
    # Stop before any work: nothing but the note is kept.
    oc = client.app.state.chat
    stop = _t.Event(); stop.set()
    out = oc.ask("erick", "are we safe?", stop=stop, deliver=lambda t: t)
    assert out["text"] == "_(Stopped.)_" and out["stopped"] and out["blocks"] == []
    # Stop while the answer is going out: the sent part is kept, buttons and tables are dropped.
    out = oc.ask("erick", "are we safe?", deliver=lambda t: t[:10])
    assert out["stopped"] and out["text"].startswith("Risk index") and out["blocks"] == []


def test_attached_log_is_read_with_rules_and_pictures_need_a_model(client):
    log = "\n".join([f"Oct 1 sshd: Failed password for root from 203.0.113.9 port {i}" for i in range(7)] +
                    ["Oct 1 sshd: Accepted publickey for erick from 192.0.2.1"])
    r = client.post("/chat", json={"operator": "erick", "message": "",
                                   "attachments": [{"name": "auth.log", "kind": "text", "text": log}]}).json()
    assert "auth.log" in r["text"] and "203.0.113.9" in r["text"]
    assert r["blocks"][0]["rows"][0][:3] == ["203.0.113.9", "7", "7"]
    q = client.get("/chat").json()["messages"][-2]
    assert q["attachments"] == [{"name": "auth.log", "kind": "text", "size": len(log.encode())}]
    r = client.post("/chat", json={"operator": "erick", "message": "what is this?", "attachments": [
        {"name": "shot.png", "kind": "image", "media_type": "image/png", "data": "iVBORw0KGgo="}]}).json()
    assert "pictures" in r["text"]
    bad = client.post("/chat", json={"operator": "erick", "message": "x", "attachments": [
        {"name": "x.svg", "kind": "image", "media_type": "image/svg+xml", "data": "AAAA"}]})
    assert bad.status_code == 400
    four = [{"name": f"{i}.log", "kind": "text", "text": "x"} for i in range(4)]
    assert client.post("/chat", json={"operator": "erick", "message": "x", "attachments": four}).status_code == 400
