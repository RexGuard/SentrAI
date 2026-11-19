"""A second AI provider takes over when the first fails, and a failing provider is rested (sentrai_llm.py)."""
import pytest

import sentrai_llm
from sentrai_llm import BudgetError, FallbackProvider, Health, LLMError, ServiceError, Turn

SCHEMA = {"type": "object"}


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Fake(sentrai_llm.Provider):
    def __init__(self, name, fail=None):
        self.name, self.model, self.fail, self.calls = name, name + "-1", fail, 0

    def complete_json(self, system, user, schema):
        self.calls += 1
        if self.fail:
            raise self.fail
        return {"by": self.name}

    def conversation(self, system, tools):
        me = self

        class C(sentrai_llm.Conversation):
            def send_user(self, text, images=None):
                me.calls += 1
                if me.fail:
                    raise me.fail
                return Turn(texts=[f"{me.name}: {text}"], stop="tool_use")

            def send_tool_results(self, results):
                me.calls += 1
                if me.fail:
                    raise me.fail
                return Turn(texts=[f"{me.name} done"])
        return C()


@pytest.fixture
def health(tmp_path):
    return Health(str(tmp_path / "ai-health.json"), clock=Clock())


def test_second_answers_when_first_has_no_credit_and_first_rests(health):
    first = Fake("anthropic", ServiceError("BadRequestError: Your credit balance is too low"))
    second = Fake("deepseek")
    p = FallbackProvider([first, second], health)
    assert p.complete_json("s", "u", SCHEMA) == {"by": "deepseek"}
    assert p.name == "deepseek" and "second" in p.label
    assert health.resting(first.label)  # a hard failure rests at once
    p.complete_json("s", "u", SCHEMA)
    assert first.calls == 1  # skipped while resting
    health.clock.t += 61
    first.fail = None
    assert p.complete_json("s", "u", SCHEMA) == {"by": "anthropic"} and p.name == "anthropic"
    assert health.get(first.label)["rests"] == 0  # a success forgets the rests


def test_busy_rests_only_after_three_in_a_row_and_rests_grow(health):
    first, second = Fake("openai", ServiceError("RateLimitError: 429 slow down")), Fake("deepseek")
    p = FallbackProvider([first, second], health)
    for _ in range(2):
        p.complete_json("s", "u", SCHEMA)
        assert not health.resting(first.label)
    p.complete_json("s", "u", SCHEMA)
    until = health.get(first.label)["rest_until"]
    assert until == health.clock.t + 60
    health.clock.t = until + 1
    for _ in range(3):
        p.complete_json("s", "u", SCHEMA)
    assert health.get(first.label)["rest_until"] == health.clock.t + 300  # second rest: 5 minutes


def test_bad_answers_and_budget_do_not_switch(health):
    first, second = Fake("anthropic", LLMError("answer was not JSON")), Fake("deepseek")
    p = FallbackProvider([first, second], health)
    with pytest.raises(LLMError):
        p.complete_json("s", "u", SCHEMA)
    first.fail = BudgetError("used up")
    with pytest.raises(BudgetError):
        p.complete_json("s", "u", SCHEMA)
    assert second.calls == 0 and not health.resting(first.label)


def test_all_resting_still_tries_and_raises_the_last_error(health):
    a, b = Fake("anthropic", ServiceError("AuthenticationError: 401")), Fake("openai", ServiceError("APIConnectionError"))
    p = FallbackProvider([a, b], health)
    with pytest.raises(ServiceError, match="APIConnectionError"):
        p.complete_json("s", "u", SCHEMA)
    with pytest.raises(ServiceError):
        p.complete_json("s", "u", SCHEMA)
    assert a.calls == 2  # resting, but nothing else could answer


def test_conversation_moves_on_first_message_then_sticks(health):
    first, second = Fake("anthropic", ServiceError("APIStatusError: 529 overloaded")), Fake("deepseek")
    p = FallbackProvider([first, second], health)
    c = p.conversation("sys", [])
    assert c.send_user("hi").texts == ["deepseek: hi"]
    first.fail = None
    assert c.send_tool_results([("1", "x", False)]).texts == ["deepseek done"]  # stays with who answered
    second.fail = ServiceError("APIConnectionError")
    with pytest.raises(ServiceError):
        c.send_tool_results([("1", "x", False)])
    assert health.get(second.label)["fails"] == 1


def test_rests_are_shared_through_the_file(tmp_path):
    path, clock = str(tmp_path / "h.json"), Clock()
    Health(path, clock).failed("anthropic:x", "Your credit balance is too low")
    other = Health(path, clock)
    assert other.resting("anthropic:x")
    other.reset()
    assert not Health(path, clock).resting("anthropic:x")


def test_from_env_adds_the_second_provider_and_model_applies_to_first(monkeypatch):
    for k in ("SENTRAI_LLM_PROVIDER", "OPENAI_API_KEY", "SENTRAI_LLM_API_KEY", "SENTRAI_LLM_MODEL",
              "SENTRAI_LLM_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "COMMANDCODE_API_KEY", "DEEPSEEK_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "a")
    assert not isinstance(sentrai_llm.from_env(), FallbackProvider)  # nothing set: exactly as before
    monkeypatch.setenv("SENTRAI_LLM_SECOND_PROVIDER", "deepseek")
    assert sentrai_llm.second_name() is None  # no key for it yet
    monkeypatch.setenv("SENTRAI_LLM_SECOND_API_KEY", "d")
    p = sentrai_llm.from_env()
    assert isinstance(p, FallbackProvider) and [m.name for m in p.members] == ["anthropic", "deepseek"]
    p.model = "claude-sonnet-5-5"
    assert p.members[0].model == "claude-sonnet-5-5" and p.members[1].model == "deepseek-chat"


def test_hard_failures():
    assert sentrai_llm.is_hard_failure("Error code: 401 - invalid x-api-key")
    assert sentrai_llm.is_hard_failure("insufficient_quota")
    assert not sentrai_llm.is_hard_failure("RateLimitError: Error code: 429")
    assert not sentrai_llm.is_hard_failure("timed out after 4013 ms")


def test_panel_shows_providers_and_forgets_rests(client, tmp_path, monkeypatch):
    monkeypatch.setattr(sentrai_llm, "HEALTH", Health(str(tmp_path / "h.json")))
    chat = client.app.state.chat
    chat.provider = FallbackProvider([Fake("anthropic"), Fake("deepseek")])
    sentrai_llm.HEALTH.failed("deepseek:deepseek-1", "credit balance is too low")
    rows = client.get("/ai").json()["providers"]
    assert [(r["role"], r["provider"], r["resting"]) for r in rows] == [("first", "anthropic", False),
                                                                         ("second", "deepseek", True)]
    rows = client.post("/ai/rests/reset").json()["providers"]
    assert not any(r["resting"] for r in rows)
