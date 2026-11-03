"""Operator chat: read-only answers, suggestions as buttons, never a state change by itself."""
import json

import pytest
import sentrai_llm
from app.chat import OperatorChat
from app.config import Settings
from app.main import create_app
from fastapi.testclient import TestClient

from .conftest import AUTH, brute_force, ev

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
    assert "a quick look from you" in reply["text"] and INC in reply["text"]


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
    assert reply["source"] == "fallback" and "not answering right now" in reply["text"] and INC in reply["text"]


def test_answers_without_a_model_use_everyday_words(client):
    """Sentry talks to business owners: no risk points, scores or internal part names in its own answers."""
    brute_force(client)
    said = {}
    for question in (f"explain {INC}", "what's going on?", "why is 203.0.113.45 blocked?"):
        said[question] = text = client.post("/chat", json={"operator": "erick", "message": question}).json()["text"]
        for word in ("points", "Countersign", "Warden", "Scribe", "Cyanide", "classifier", "threshold",
                     "Risk index", "Configuration, section"):
            assert word not in text, (question, word, text)
    assert "Password guessing" in said[f"explain {INC}"] and "a quick look from you" in said["what's going on?"]


def test_default_prompt_is_written_for_business_owners():
    from app.chat import SETUP_SYSTEM, SYSTEM
    prompt = SYSTEM.format(name="Sentry")
    assert "no IT" in prompt and "120 words" in prompt and "Never name SentrAI's internal parts" in prompt
    assert "SentrAI's team can set that up for you" in prompt
    assert "not an IT person" in SETUP_SYSTEM.format(name="Sentry")


def test_words_before_a_lookup_are_not_part_of_the_answer(client):
    brute_force(client)
    provider = FakeProvider([
        sentrai_llm.Turn(texts=["Let me check that."], tool_calls=[call("get_incident", incident=INC)], stop="tool_use"),
        sentrai_llm.Turn(texts=["You're safe. Someone tried to guess passwords."]),
    ])
    reply = OperatorChat(client.core, provider).ask("erick", "am I safe?")
    assert reply["text"] == "You're safe. Someone tried to guess passwords."


def test_answer_written_next_to_a_button_is_kept(client):
    brute_force(client)
    provider = FakeProvider([
        sentrai_llm.Turn(tool_calls=[call("get_incident", incident=INC)], stop="tool_use"),
        sentrai_llm.Turn(texts=["You're safe. SentrAI suggests blocking that address."],
                         tool_calls=[call("suggest_action", incident=INC, decision="approve", reason="x")],
                         stop="tool_use"),
        sentrai_llm.Turn(texts=["The button is below."]),
    ])
    reply = OperatorChat(client.core, provider).ask("erick", "am I safe?")
    assert reply["text"] == "You're safe. SentrAI suggests blocking that address."  # the pointer line is dropped


def test_prompt_keeps_sentry_to_looked_up_facts_and_real_buttons():
    from app.chat import SYSTEM
    prompt = SYSTEM.format(name="Sentry")
    assert "Only say what you looked up" in prompt and "only a proposal" in prompt
    assert "BELOW your answer" in prompt and "Never invent buttons" in prompt


def test_earlier_messages_are_passed_to_the_model(client):
    provider = FakeProvider([sentrai_llm.Turn(texts=["first"]), sentrai_llm.Turn(texts=["second"])])
    chat = OperatorChat(client.core, provider)
    chat.ask("erick", "hello")
    chat.ask("erick", "and again?")
    prompt = provider.convos[1].sent[0]
    assert "Operator: hello" in prompt and "Sentry: first" in prompt


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
    assert out["stopped"] and out["text"].startswith("**You're s") and out["blocks"] == []


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


def test_memory_is_taught_in_chat_and_read_back(client):
    r = client.post("/chat", json={"operator": "erick", "message": "Remember that 203.0.113.45 is our office router"}).json()
    assert "203.0.113.45 is our office router" in r["text"]
    mem = client.get("/chat/memory").json()
    assert [f["text"] for f in mem["facts"]] == ["203.0.113.45 is our office router"]
    brute_force(client)
    r = client.post("/chat", json={"operator": "erick", "message": "why is 203.0.113.45 blocked?"}).json()
    assert "What the team told me" in r["text"] and "office router" in r["text"]
    r = client.post("/chat", json={"operator": "erick", "message": "What do you remember?"}).json()
    assert r["blocks"][0]["rows"][0][0] == "203.0.113.45 is our office router"
    fid = mem["facts"][0]["id"]
    assert client.delete(f"/chat/memory/facts/{fid}").json()["ok"]
    assert client.get("/chat/memory").json()["facts"] == []
    assert client.delete(f"/chat/memory/facts/{fid}").status_code == 404
    assert client.post("/chat/memory/facts", json={"text": "  "}).status_code == 400
    types = [x["type"] for x in client.get("/audit").json()["records"]]
    assert "chat_memory_added" in types and "chat_memory_forgot" in types


def test_model_sees_memory_and_can_remember(client):
    client.post("/chat/memory", json={"instructions": "Answer in plain words."})
    client.post("/chat/memory/facts", json={"text": "rexguard is our game server"})
    chat = client.app.state.chat
    assert "plain words" in chat.memory.prompt() and "rexguard" in chat.memory.prompt()
    out = chat._dispatch("remember", {"text": "backups run at 2am"}, [], [], {"blocks": [], "followups": [], "by": "erick"})
    assert "Saved" in out and any(f["text"] == "backups run at 2am" for f in client.get("/chat/memory").json()["facts"])


def test_share_a_chat(client):
    r = client.post("/chat", json={"operator": "erick", "message": "are we safe?"}).json()
    share = client.post("/chat/shares", json={"title": "Safe?", "message_ids": [r["id"] - 1, r["id"]]}).json()
    assert share["to"] == ["everyone"] and share["count"] == 2
    assert client.get("/chat/shares").json()["shares"][0]["id"] == share["id"]
    full = client.get(f"/chat/shares/{share['id']}").json()
    assert [m["role"] for m in full["messages"]] == ["operator", "assistant"]
    assert client.post("/chat/shares", json={"message_ids": [9999]}).status_code == 400
    assert client.delete(f"/chat/shares/{share['id']}").json()["ok"]
    assert client.get(f"/chat/shares/{share['id']}").status_code == 404


@pytest.fixture
def panel(tmp_path):
    """Each machine scored on its own, so two attacks on two machines stay open."""
    settings = Settings(db_path=tmp_path / "sentrai.db", background=False, demo_speed=60.0, risk_scope="host")
    app = create_app(settings)
    with TestClient(app, headers=AUTH) as c:
        c.core = app.state.core  # type: ignore[attr-defined]
        yield c


def two_machines(client):
    """An overdue password-guessing risk on web-01 and a fresh one on db-01."""
    brute_force(client)
    client.core.advance(3)  # past the 2 h time limit with nobody looking: overdue
    for i in range(5):
        client.post("/events", json=ev(20 + i, "POST /login 401 user=admin", ip="198.51.100.9", host="db-01"))
    incs = {i["host"]: i["id"] for i in client.get("/incidents").json()}
    return incs["web-01"], incs["db-01"]


def test_machine_scope_without_a_model_cleans_up_only_that_machine(panel):
    web, db = two_machines(panel)
    reply = panel.post("/chat", json={"operator": "erick", "message": "Clean up the overdue risks",
                                       "machine": "web-01"}).json()
    assert reply["machine"] == "web-01" and "overdue" in reply["text"] and "web-01" in reply["text"]
    [s] = reply["suggestions"]
    assert s["kind"] == "bulk" and s["decision"] == "ack" and s["incidents"] == [web]
    assert panel.get(f"/incidents/{web}").json()["acked"] is False  # still only a button


def test_machine_named_by_its_given_name_in_the_question(panel):
    web, _ = two_machines(panel)
    chat = OperatorChat(panel.core)
    chat.names = lambda: {"web-01": "RexGuard Machine"}
    reply = chat.ask("erick", "Clean up the overdue risks for RexGuard Machine")
    assert "RexGuard Machine" in reply["text"] and reply["suggestions"][0]["incidents"] == [web]
    assert chat.ask("erick", "how is it going?", machine="RexGuard Machine")["machine"] == "web-01"


def test_unknown_machine_is_refused(client):
    r = client.post("/chat", json={"operator": "erick", "message": "hi", "machine": "nope"})
    assert r.status_code == 404


def test_model_sees_the_selected_machine_and_can_offer_one_button_for_many(panel):
    web, db = two_machines(panel)
    provider = FakeProvider([
        sentrai_llm.Turn(tool_calls=[call("get_machine", machine="web-01")], stop="tool_use"),
        sentrai_llm.Turn(tool_calls=[call("suggest_bulk_action", incidents=[web, db, "RSK-9999-999"], decision="ack",
                                         label="Acknowledge 2 overdue risks", reason="Looked at in chat")],
                         stop="tool_use"),
        sentrai_llm.Turn(texts=["Two risks are overdue on this computer."]),
    ])
    chat = OperatorChat(panel.core, provider)
    reply = chat.ask("erick", "clean up", machine="web-01")
    assert "host web-01" in provider.convos[0].sent[0] and web in provider.convos[0].sent[0]
    assert '"overdue":true' in provider.convos[0].results[0][0][1]
    [s] = reply["suggestions"]
    assert s["kind"] == "bulk" and s["incidents"] == [web, db]  # the unknown one is left out
    assert "RSK-9999-999 not found" in provider.convos[0].results[1][0][1]


def test_no_button_for_a_decision_that_is_no_longer_possible(client):
    brute_force(client)
    client.post(f"/incidents/{INC}/ack", json={"operator": "erick"})
    provider = FakeProvider([
        sentrai_llm.Turn(tool_calls=[call("suggest_action", incident=INC, decision="ack", reason="x")], stop="tool_use"),
        sentrai_llm.Turn(texts=["Someone already looked at it."]),
    ])
    reply = OperatorChat(client.core, provider).ask("erick", "acknowledge it")
    assert reply["suggestions"] == []
    out, err = provider.convos[0].results[0][0][1:]
    assert err is True and "no longer possible" in out


def test_buttons_without_words_never_show_no_answer(client):
    brute_force(client)
    provider = FakeProvider([
        sentrai_llm.Turn(tool_calls=[call("suggest_action", incident=INC, decision="approve", reason="x")],
                         stop="tool_use"),
        sentrai_llm.Turn(texts=[]),
    ])
    reply = OperatorChat(client.core, provider).ask("erick", "what now?")
    assert reply["text"] != "(no answer)" and f"Approve & patch {INC}" in reply["text"]


def test_nothing_at_all_from_the_model_falls_back(client):
    brute_force(client)
    reply = OperatorChat(client.core, FakeProvider([sentrai_llm.Turn(texts=[])])).ask("erick", "what's going on?")
    assert reply["source"] == "fallback" and "a quick look from you" in reply["text"]


def test_answer_written_before_a_last_lookup_is_kept(client):
    brute_force(client)
    long = "Someone tried to guess the admin password on your website many times, and SentrAI is watching it closely."
    provider = FakeProvider([
        sentrai_llm.Turn(texts=[long], tool_calls=[call("get_incident", incident=INC)], stop="tool_use"),
        sentrai_llm.Turn(texts=[]),
    ])
    assert OperatorChat(client.core, provider).ask("erick", "what now?")["text"] == long


def test_overview_for_the_model_counts_everything_and_lists_only_the_urgent(client):
    for n in range(20):
        brute_force(client, ip=f"198.51.100.{n + 1}", start=n * 5)
    chat = OperatorChat(client.core, None)
    out = json.loads(chat._dispatch("get_overview", {"status": "", "severity": "", "computer": "", "category": "",
                                                     "limit": 0}, [], [], None))
    assert out["counts"]["total"] == 20 and out["matching"] == out["counts"]["still_open"]
    assert len(out["incidents"]) == 15 and out["not_listed"] == out["matching"] - 15
    assert "acked" not in out["incidents"][0]  # false fields are left out
    none = json.loads(chat._dispatch("get_overview", {"status": "", "severity": "low", "computer": "", "category": "",
                                                      "limit": 5}, [], [], None))
    assert none["matching"] == 0 and "incidents" not in none and none["counts"]["total"] == 20


def test_incident_lookup_folds_repeated_lines():
    from app.chat import lean
    assert lean({"a": None, "b": False, "c": [], "d": 0, "snapshot_hash": "x", "e": {"f": ""}}) == {"d": 0}
