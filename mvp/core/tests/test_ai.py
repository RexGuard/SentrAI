"""/ai: why the AI model is off, reloading saved settings without a restart, and the connection test."""

import json
import os

import pytest

import cactai_config
import cactai_llm

KEYS = ("CACTAI_LLM_PROVIDER", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "DEEPSEEK_API_KEY",
        "COMMANDCODE_API_KEY", "CACTAI_LLM_API_KEY", "CACTAI_LLM_BASE_URL", "CACTAI_LLM_MODEL", "CYANIDE_MODEL")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in KEYS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(cactai_config, "_LOADED", {})


class PingProvider(cactai_llm.Provider):
    def __init__(self, name="anthropic", model="claude-test", error=None):
        self.name, self.model, self.error, self.asked = name, model, error, []

    def complete_json(self, system, user, schema):
        self.asked.append(schema)
        if self.error:
            raise cactai_llm.LLMError(self.error)
        return {"ok": True}


def save_ai(path, **ai):
    path.write_text(json.dumps({"ai": ai}), encoding="utf-8")


def test_status_says_why_the_model_is_off(client, monkeypatch):
    assert "CYANIDE_ENABLED=0" in client.get("/chat").json()["model"]  # as the tests start the core
    monkeypatch.setenv("CYANIDE_ENABLED", "1")
    body = client.post("/ai/reload").json()
    assert body["online"] is False
    assert "no API key" in body["off_reason"]
    assert "no API key" in client.get("/chat").json()["model"]  # the chat page shows the reason too


def test_missing_model_and_missing_package_are_named(monkeypatch):
    from app import ai

    monkeypatch.setenv("CYANIDE_ENABLED", "1")
    monkeypatch.setenv("CACTAI_LLM_PROVIDER", "commandcode")
    monkeypatch.setenv("CACTAI_LLM_API_KEY", "cc")
    assert "needs CACTAI_LLM_MODEL" in ai.why_off()

    def no_sdk(**_):
        raise ImportError("No module named 'anthropic'")

    monkeypatch.setenv("CACTAI_LLM_PROVIDER", "anthropic")
    monkeypatch.setattr(cactai_llm, "AnthropicProvider", no_sdk)
    assert "'anthropic' Python package is not installed" in ai.why_off()


def test_reload_picks_up_a_key_saved_while_running(client, monkeypatch, tmp_path):
    monkeypatch.setenv("CYANIDE_ENABLED", "1")
    cfg = tmp_path / "config.json"
    monkeypatch.setenv("CACTAI_CONFIG", str(cfg))
    assert client.get("/ai").json()["online"] is False
    save_ai(cfg, CACTAI_LLM_PROVIDER="openai", CACTAI_LLM_API_KEY="sk-first", CACTAI_LLM_MODEL="gpt-test")
    body = client.post("/ai/reload").json()
    assert (body["online"], body["provider"], body["model"]) == (True, "openai", "gpt-test")
    assert body["key_source"] == "CACTAI_LLM_API_KEY"
    assert client.core.planner.status == "online (openai:gpt-test)"
    assert client.get("/chat").json()["model"] == "online (openai:gpt-test)"
    # A second save replaces the first one's values (they came from the file, not the environment).
    save_ai(cfg, CACTAI_LLM_PROVIDER="openai", CACTAI_LLM_API_KEY="", CACTAI_LLM_MODEL="")
    body = client.post("/ai/reload").json()
    assert body["online"] is False and "no API key for OpenAI" in body["off_reason"]
    assert "CACTAI_LLM_API_KEY" not in os.environ


def test_reload_never_overrides_a_real_environment_variable(monkeypatch, tmp_path):
    cfg = tmp_path / "config.json"
    monkeypatch.setenv("CACTAI_CONFIG", str(cfg))
    monkeypatch.setenv("CACTAI_LLM_MODEL", "from-env")
    save_ai(cfg, CACTAI_LLM_MODEL="from-file")
    cactai_config.load(refresh=True)
    assert os.environ["CACTAI_LLM_MODEL"] == "from-env"


def test_connection_test_uses_the_form_values(client, monkeypatch):
    built = {}

    def build(name, key, model=None, base_url=None, **kw):
        built.update(name=name, key=key, model=model, base_url=base_url)
        return PingProvider(name, model or "default")

    monkeypatch.setattr(cactai_llm, "build", build)
    r = client.post("/ai/test", json={"provider": "deepseek", "api_key": " k ", "model": "deepseek-chat"}).json()
    assert r["ok"] is True and r["tested"] == "form" and r["model"] == "deepseek-chat"
    assert built == {"name": "deepseek", "key": "k", "model": "deepseek-chat", "base_url": None}
    assert client.get("/ai").json()["online"] is False  # testing never switches what Cyanide uses


def test_connection_test_explains_a_rejected_key(client, monkeypatch):
    monkeypatch.setattr(cactai_llm, "build", lambda *a, **k: PingProvider(
        error="AuthenticationError: Error code: 401 - invalid x-api-key"))
    r = client.post("/ai/test", json={"provider": "anthropic", "api_key": "bad"}).json()
    assert r["ok"] is False and "401" in r["error"] and "rejected the key" in r["hint"]
    r = client.post("/ai/test", json={"provider": "anthropic", "api_key": ""}).json()
    assert r["ok"] is False and r["error"] == "enter the API key first"


def test_connection_test_without_a_body_tests_what_cyanide_uses(client):
    r = client.post("/ai/test").json()
    assert r["ok"] is False and r["tested"] == "running" and "Cyanide has no AI model" in r["error"]
    client.core.planner = type("P", (), {"provider": PingProvider(), "status": "online"})()
    r = client.post("/ai/test").json()
    assert r["ok"] is True and (r["provider"], r["model"]) == ("anthropic", "claude-test")
