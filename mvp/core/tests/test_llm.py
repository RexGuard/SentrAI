"""The provider layer (mvp/cactai_llm.py): picking a provider and speaking each API's format."""

import json
from types import SimpleNamespace as NS

import pytest

import cactai_llm
from cactai_llm import AnthropicProvider, OpenAIProvider

KEYS = ("CACTAI_LLM_PROVIDER", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "DEEPSEEK_API_KEY",
        "COMMANDCODE_API_KEY", "CACTAI_LLM_API_KEY", "CACTAI_LLM_BASE_URL", "CACTAI_LLM_MODEL")
SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"], "additionalProperties": False}
TOOLS = [{"name": "list_dir", "description": "List a folder",
          "input_schema": {"type": "object", "properties": {"path": {"type": "string"}},
                           "required": ["path"], "additionalProperties": False}}]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in KEYS:
        monkeypatch.delenv(k, raising=False)


def test_auto_picks_the_first_key_that_is_set(monkeypatch):
    assert cactai_llm.provider_name() is None
    monkeypatch.setenv("DEEPSEEK_API_KEY", "d")
    assert cactai_llm.provider_name() == "deepseek"
    monkeypatch.setenv("OPENAI_API_KEY", "o")
    assert cactai_llm.provider_name() == "openai"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "a")
    assert cactai_llm.provider_name() == "anthropic"
    monkeypatch.setenv("CACTAI_LLM_PROVIDER", "deepseek")
    assert cactai_llm.provider_name() == "deepseek"
    monkeypatch.delenv("DEEPSEEK_API_KEY")
    assert cactai_llm.provider_name() is None  # chosen provider without its key: off, not a silent switch


def test_from_env_builds_each_provider(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "d")
    p = cactai_llm.from_env()
    assert (p.name, p.model, str(p.client.base_url).rstrip("/")) == ("deepseek", "deepseek-chat", "https://api.deepseek.com")
    monkeypatch.setenv("CACTAI_LLM_PROVIDER", "commandcode")
    monkeypatch.setenv("COMMANDCODE_API_KEY", "cc")
    with pytest.raises(cactai_llm.LLMError):
        cactai_llm.from_env()  # no default model: the name must be set
    monkeypatch.setenv("CACTAI_LLM_MODEL", "cc-model")
    p = cactai_llm.from_env()
    assert (p.name, str(p.client.base_url).rstrip("/")) == ("commandcode", "https://api.commandcode.ai/provider/v1")
    monkeypatch.delenv("CACTAI_LLM_MODEL")
    monkeypatch.setenv("CACTAI_LLM_PROVIDER", "compatible")
    monkeypatch.setenv("CACTAI_LLM_API_KEY", "c")
    with pytest.raises(cactai_llm.LLMError):
        cactai_llm.from_env()  # needs a base URL and a model
    monkeypatch.setenv("CACTAI_LLM_BASE_URL", "https://llm.example.com/v1")
    monkeypatch.setenv("CACTAI_LLM_MODEL", "some-model")
    assert cactai_llm.from_env().label == "compatible:some-model"


class FakeOpenAI:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []
        self.chat = NS(completions=self)

    def create(self, **kw):
        self.calls.append(json.loads(json.dumps(kw)))  # snapshot: the history list keeps growing
        return self.replies.pop(0)


def reply(content=None, calls=(), finish="stop"):
    tcs = [NS(id=f"call_{i}", function=NS(name=n, arguments=json.dumps(a))) for i, (n, a) in enumerate(calls)]
    return NS(choices=[NS(finish_reason=finish, message=NS(content=content, tool_calls=tcs or None))])


def test_openai_json_uses_strict_schema_and_deepseek_describes_it():
    fake = FakeOpenAI([reply('{"ok": true}')])
    assert OpenAIProvider(client=fake).complete_json("sys", "hi", SCHEMA) == {"ok": True}
    assert fake.calls[0]["response_format"]["type"] == "json_schema"
    fake = FakeOpenAI([reply('```json\n{"ok": false}\n```')])
    assert OpenAIProvider(name="deepseek", model="deepseek-chat", client=fake).complete_json("sys", "hi", SCHEMA) == {"ok": False}
    assert fake.calls[0]["response_format"] == {"type": "json_object"}
    assert "JSON schema" in fake.calls[0]["messages"][0]["content"]


def test_openai_conversation_round_trip():
    fake = FakeOpenAI([reply("Looking in /var/log.", [("list_dir", {"path": "/var/log"})], "tool_calls"),
                       reply("Done.")])
    convo = OpenAIProvider(client=fake).conversation("sys", TOOLS)
    turn = convo.send_user("find logs")
    assert turn.stop == "tool_use" and turn.texts == ["Looking in /var/log."]
    assert turn.tool_calls[0].name == "list_dir" and turn.tool_calls[0].input == {"path": "/var/log"}
    assert fake.calls[0]["tools"][0]["function"]["strict"] is True
    turn = convo.send_tool_results([("call_0", "auth.log", False)])
    assert turn.stop == "end" and turn.texts == ["Done."]
    sent = fake.calls[1]["messages"]
    assert [m["role"] for m in sent] == ["system", "user", "assistant", "tool"]
    assert sent[2]["tool_calls"][0]["id"] == "call_0" and sent[3]["tool_call_id"] == "call_0"


def test_errors_become_llm_error():
    class Broken:
        def __init__(self):
            self.chat = NS(completions=self)
            self.messages = self

        def create(self, **kw):
            raise RuntimeError("connection refused")

    with pytest.raises(cactai_llm.LLMError):
        OpenAIProvider(client=Broken()).complete_json("s", "u", SCHEMA)
    with pytest.raises(cactai_llm.LLMError):
        AnthropicProvider(client=Broken()).complete_json("s", "u", SCHEMA)


def test_cyanide_planner_uses_whichever_provider_is_set(monkeypatch):
    from app.cyanide import default_planner

    monkeypatch.setenv("CYANIDE_ENABLED", "1")
    assert default_planner() is None
    monkeypatch.setenv("OPENAI_API_KEY", "o")
    p = default_planner()
    assert p.status == "online (openai:gpt-5)"
    p.provider.client = FakeOpenAI([reply('{"assessment": "x", "actions": [], "allow_autonomous": false, "hold_reason": "y"}')])
    assert p.plan({"incident": {}})["hold_reason"] == "y"
    p.provider.client = FakeOpenAI([reply("not json")])
    assert p.plan({}) is None and p.failures == 1


def test_one_shared_key_serves_whichever_provider_is_chosen(monkeypatch):
    monkeypatch.setenv("CACTAI_LLM_API_KEY", "shared")
    monkeypatch.setenv("CACTAI_LLM_PROVIDER", "deepseek")
    p = cactai_llm.from_env()
    assert (p.name, p.client.api_key) == ("deepseek", "shared")
    monkeypatch.setenv("CACTAI_LLM_PROVIDER", "anthropic")
    p = cactai_llm.from_env()
    assert (p.name, p.client.api_key) == ("anthropic", "shared")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "own")  # a provider's own variable still wins
    assert cactai_llm.from_env().client.api_key == "own"


def test_auto_reads_a_claude_key_in_the_shared_field_as_anthropic(monkeypatch):
    monkeypatch.setenv("CACTAI_LLM_API_KEY", "sk-ant-api03-x")
    assert cactai_llm.provider_name() == "anthropic"
    monkeypatch.setenv("CACTAI_LLM_BASE_URL", "https://llm.example.com/v1")
    assert cactai_llm.provider_name() == "compatible"


@pytest.fixture
def models_api():
    """A local stand-in for the providers' model-list endpoints. Key "bad" is rejected."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers))
            if "bad" in (self.headers.get("x-api-key", "") + self.headers.get("Authorization", "")):
                return self._send(401, {"error": "invalid key"})
            if self.path.startswith("/v1/models"):  # Anthropic: paged, newest first
                if "after_id=m2" in self.path:
                    return self._send(200, {"data": [{"id": "claude-old"}], "has_more": False, "last_id": "claude-old"})
                return self._send(200, {"data": [{"id": "claude-new"}, {"id": "claude-mid"}], "has_more": True,
                                        "last_id": "m2"})
            if self.path == "/openai/models":
                return self._send(200, {"data": [{"id": "gpt-5"}, {"id": "text-embedding-3-small"}, {"id": "gpt-4.1"}]})
            self._send(404, {"error": "not found"})

        def _send(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}", seen
    server.shutdown()


def test_list_models_reads_every_page_and_keeps_chat_models(models_api):
    base, seen = models_api
    assert cactai_llm.list_models("anthropic", "k", base) == ["claude-new", "claude-mid", "claude-old"]
    assert seen[0][1]["x-api-key"] == "k"
    assert cactai_llm.list_models("openai", "k", base + "/openai") == ["gpt-4.1", "gpt-5"]
    assert seen[-1][1]["Authorization"] == "Bearer k"


def test_list_models_explains_what_went_wrong(models_api):
    base, _ = models_api
    with pytest.raises(cactai_llm.LLMError, match="rejected this API key"):
        cactai_llm.list_models("openai", "bad", base + "/openai")
    with pytest.raises(cactai_llm.LLMError, match="does not list its models"):
        cactai_llm.list_models("compatible", "k", base + "/nothing-here")
    with pytest.raises(cactai_llm.LLMError, match="base URL"):
        cactai_llm.list_models("compatible", "k")
    with pytest.raises(cactai_llm.LLMError, match="API key first"):
        cactai_llm.list_models("openai", "")
    with pytest.raises(cactai_llm.LLMError, match="could not reach"):
        cactai_llm.list_models("openai", "k", "http://127.0.0.1:9")
