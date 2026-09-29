"""Operator chat: read-only answers, suggestions as buttons, never a state change by itself."""

import cactai_llm
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


class FakeProvider(cactai_llm.Provider):
    name, model = "fake", "fake-1"

    def __init__(self, turns=None, error=None):
        self.turns, self.error, self.convos = turns or [], error, []

    def conversation(self, system, tools):
        if self.error:
            raise cactai_llm.LLMError(self.error)
        c = FakeConvo(self.turns)
        self.convos.append(c)
        return c


def call(name, **args):
    return cactai_llm.ToolCall(f"t-{name}", name, args)


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


def test_reset_clears_the_chat(client):
    client.post("/chat", json={"operator": "erick", "message": "status?"})
    client.post("/demo/reset")
    assert client.get("/chat").json()["messages"] == []


def test_model_reads_with_tools_and_can_only_suggest(client):
    brute_force(client)
    core = client.core
    before = core.get_incident(INC)["status"]
    provider = FakeProvider([
        cactai_llm.Turn(tool_calls=[call("get_incident", incident=INC)], stop="tool_use"),
        cactai_llm.Turn(tool_calls=[call("suggest_action", incident=INC, decision="approve",
                                         reason="Guessing the admin password from one address")], stop="tool_use"),
        cactai_llm.Turn(texts=[f"{INC} is a password-guessing attack. Press the button to block it."]),
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
        cactai_llm.Turn(tool_calls=[call("suggest_action", incident="RSK-9999-999", decision="approve", reason="x")],
                        stop="tool_use"),
        cactai_llm.Turn(texts=["I could not find that incident."]),
    ])
    reply = OperatorChat(client.core, provider).ask("erick", "approve RSK-9999-999")
    assert reply["suggestions"] == []
    assert provider.convos[0].results[0][0][2] is True  # is_error


def test_model_failure_falls_back(client):
    brute_force(client)
    reply = OperatorChat(client.core, FakeProvider(error="timeout")).ask("erick", f"explain {INC}")
    assert reply["source"] == "fallback" and "unavailable" in reply["text"] and INC in reply["text"]


def test_earlier_messages_are_passed_to_the_model(client):
    provider = FakeProvider([cactai_llm.Turn(texts=["first"]), cactai_llm.Turn(texts=["second"])])
    chat = OperatorChat(client.core, provider)
    chat.ask("erick", "hello")
    chat.ask("erick", "and again?")
    prompt = provider.convos[1].sent[0]
    assert "Operator: hello" in prompt and f"{client.core.name}: first" in prompt


class SetupProvider(cactai_llm.Provider):
    name, model = "fake", "fake-1"

    def __init__(self, out=None, error=None):
        self.out, self.error, self.asked = out, error, []

    def complete_json(self, system, user, schema):
        if self.error:
            raise cactai_llm.LLMError(self.error)
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
