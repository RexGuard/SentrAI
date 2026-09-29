"""Which AI model SentrAI talks to. One small interface over several providers.

Cyanide (core) and Scout (lab) only need two things from a model:
  * ``complete_json(system, user, schema)``: one answer as JSON matching a schema
  * ``conversation(system, tools)``: a tool-use conversation (send text, get tool calls,
    send tool results back) that keeps each provider's own message format inside it

Providers:
  anthropic  ANTHROPIC_API_KEY  Claude, through the ``anthropic`` package
  openai     OPENAI_API_KEY     OpenAI, through the ``openai`` package
  deepseek   DEEPSEEK_API_KEY   DeepSeek's OpenAI-compatible API (``openai`` package)
  commandcode COMMANDCODE_API_KEY  Command Code's OpenAI-compatible API (needs CACTAI_LLM_MODEL)
  compatible CACTAI_LLM_BASE_URL: any other OpenAI-compatible service

The setup wizard keeps one key for all of them: CACTAI_LLM_API_KEY is used by whichever
provider CACTAI_LLM_PROVIDER names (a provider's own variable above still wins when set).
"auto" (the default) takes the first provider whose own key is set, in the order above.
CACTAI_LLM_MODEL overrides the provider's default model; ``list_models()`` asks the provider
which models the key can use.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

PROVIDERS = ("anthropic", "openai", "deepseek", "commandcode", "compatible")
KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "deepseek": "DEEPSEEK_API_KEY",
           "commandcode": "COMMANDCODE_API_KEY", "compatible": "CACTAI_LLM_API_KEY"}
DEFAULT_MODEL = {"anthropic": "claude-opus-5", "openai": "gpt-5", "deepseek": "deepseek-chat", "commandcode": "",
                 "compatible": ""}
LABEL = {"anthropic": "Anthropic (Claude)", "openai": "OpenAI", "deepseek": "DeepSeek", "commandcode": "Command Code",
         "compatible": "Other OpenAI-compatible service"}
GENERIC_KEY_ENV = "CACTAI_LLM_API_KEY"
BASE_URL = {"anthropic": "https://api.anthropic.com", "openai": "https://api.openai.com/v1", "deepseek": "https://api.deepseek.com", "commandcode": "https://api.commandcode.ai/provider/v1"}


class LLMError(Exception):
    """The provider could not give a usable answer (network, key, refusal, bad output)."""


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class Turn:
    texts: list[str] = field(default_factory=list)
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop: str = "end"  # "tool_use", "end", or the provider's reason for stopping early


def api_key(name: str) -> str | None:
    """The key for one provider: its own variable, else the shared CACTAI_LLM_API_KEY."""
    return os.getenv(KEY_ENV[name]) or os.getenv(GENERIC_KEY_ENV) or None


def provider_name() -> str | None:
    """The provider to use, or None when no key is configured."""
    choice = os.getenv("CACTAI_LLM_PROVIDER", "auto").strip().lower() or "auto"
    if choice != "auto":
        return choice if choice in PROVIDERS and api_key(choice) else None
    if os.getenv("ANTHROPIC_AUTH_TOKEN"):
        return "anthropic"
    name = next((p for p in PROVIDERS if os.getenv(KEY_ENV[p])), None)
    if name == "compatible" and os.getenv(GENERIC_KEY_ENV, "").startswith("sk-ant-") \
            and not os.getenv("CACTAI_LLM_BASE_URL"):
        return "anthropic"  # a Claude key in the shared field, with no other service named
    return name


def off_reason() -> str:
    """Why from_env() has no provider, in words a person can act on."""
    choice = os.getenv("CACTAI_LLM_PROVIDER", "auto").strip().lower() or "auto"
    if choice != "auto" and choice not in PROVIDERS:
        return f"unknown provider {choice!r} in CACTAI_LLM_PROVIDER"
    if choice != "auto":
        return f"no API key for {LABEL[choice]}: enter one under Configuration, section 5"
    return "no API key set: enter one under Configuration, section 5"


def key_source(name: str) -> str | None:
    """The environment variable the key for this provider comes from (it tells an old variable apart)."""
    if name == "anthropic" and not os.getenv(KEY_ENV[name]) and not os.getenv(GENERIC_KEY_ENV) \
            and os.getenv("ANTHROPIC_AUTH_TOKEN"):
        return "ANTHROPIC_AUTH_TOKEN"
    return next((env for env in (KEY_ENV[name], GENERIC_KEY_ENV) if os.getenv(env)), None)


def from_env(effort: str = "medium", timeout_s: float = 120.0) -> "Provider | None":
    name = provider_name()
    if name is None:
        return None
    return build(name, api_key(name), os.getenv("CACTAI_LLM_MODEL"), os.getenv("CACTAI_LLM_BASE_URL"),
                 effort=effort, timeout_s=timeout_s)


def build(name: str, key: str | None, model: str | None = None, base_url: str | None = None,
          effort: str = "medium", timeout_s: float = 120.0) -> "Provider":
    """One provider from explicit settings (from_env and the connection test both use this).

    Raises LLMError when a setting is missing or the provider's Python package is not installed.
    """
    if name not in PROVIDERS:
        raise LLMError(f"unknown provider {name!r}")
    model = model or DEFAULT_MODEL[name]
    base_url = base_url or BASE_URL.get(name)
    if name != "anthropic" and (not model or (name == "compatible" and not base_url)):
        raise LLMError(f"the {name} provider needs CACTAI_LLM_MODEL" + (" and CACTAI_LLM_BASE_URL" if name == "compatible" else ""))
    try:
        if name == "anthropic":
            return AnthropicProvider(model=model, effort=effort, timeout_s=timeout_s, api_key=key)
        return OpenAIProvider(name=name, model=model, api_key=key, base_url=base_url, timeout_s=timeout_s)
    except ImportError as e:
        package = "anthropic" if name == "anthropic" else "openai"
        raise LLMError(f"the '{package}' Python package is not installed for this part of SentrAI. Run "
                       f"stop_demo.ps1, then run_demo.ps1 again: it installs new packages when it starts") from e


PING_SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"],
               "additionalProperties": False}


def check(provider: "Provider") -> dict[str, Any]:
    """One tiny real request through the same call Cyanide makes, so a pass means Cyanide can plan.

    Returns {"ok", "provider", "model", "ms", "error", "hint"}.
    """
    started = time.monotonic()
    error = None
    try:
        provider.complete_json("You are a connection test for SentrAI.", 'Reply with {"ok": true}.', PING_SCHEMA)
    except LLMError as e:
        error = str(e)[:600]
    return {"ok": error is None, "provider": provider.name, "model": provider.model,
            "ms": round((time.monotonic() - started) * 1000), "error": error, "hint": hint(error) if error else None}


def hint(error: str) -> str | None:
    """A plain next step for the errors people hit most when setting up a key."""
    e = error.lower()
    if "authentication" in e or "401" in e or "invalid x-api-key" in e or "incorrect api key" in e:
        return "The provider rejected the key. Copy it again (no spaces) and check it belongs to the provider chosen above."
    if "permission" in e or "403" in e:
        return "The key works but may not use this model. Pick another model with Fetch models."
    if "not_found" in e or "404" in e or "model_not_found" in e or "does not exist" in e:
        return "The provider does not know this model name. Use Fetch models and pick one from the list."
    if "credit" in e or "billing" in e or "quota" in e or "insufficient" in e or "429" in e:
        return "The key has no credit left or hit a rate limit. Check billing on the provider's website."
    if "effort" in e or "output_config" in e or "json_schema" in e or "response_format" in e:
        return "This model does not support the structured answers Cyanide needs. Try the provider's default model."
    if "connection" in e or "timeout" in e or "timed out" in e or "could not reach" in e:
        return "The provider could not be reached. Check the internet connection, proxy or base URL."
    return None


# Model ids in OpenAI's list that cannot hold a conversation.
_NOT_CHAT = ("embedding", "tts", "whisper", "dall-e", "moderation", "transcribe", "image", "realtime", "audio",
             "davinci", "babbage", "sora")


def list_models(name: str, key: str, base_url: str | None = None, timeout_s: float = 15.0) -> list[str]:
    """The model ids this key can use at this provider, newest first where the provider says so.

    Raises LLMError with a sentence a person can act on: the key was rejected, the service
    could not be reached, or it does not list its models (then type the model name).
    """
    if name not in PROVIDERS:
        raise LLMError(f"unknown provider {name!r}")
    if not key:
        raise LLMError("enter the API key first")
    base = (base_url or BASE_URL.get(name) or "").rstrip("/")
    if not base:
        raise LLMError("enter the service's base URL first")
    if name == "anthropic":
        headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
        ids: list[str] = []
        after = ""
        while True:  # the list is paged; newest models come first
            page = _get_json(f"{base}/v1/models?limit=1000{after}", headers, timeout_s)
            ids += [m["id"] for m in page.get("data", []) if isinstance(m, dict) and m.get("id")]
            if not page.get("has_more") or not page.get("last_id"):
                return list(dict.fromkeys(ids))
            after = f"&after_id={page['last_id']}"
    page = _get_json(f"{base}/models", {"Authorization": f"Bearer {key}"}, timeout_s)
    ids = [m["id"] for m in page.get("data", []) if isinstance(m, dict) and m.get("id")]
    if name == "openai":
        ids = [i for i in ids if not any(word in i for word in _NOT_CHAT)]
    return sorted(set(ids))


def _get_json(url: str, headers: dict[str, str], timeout_s: float) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "cactai", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as r:
            data = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise LLMError("the service rejected this API key") from e
        if e.code in (404, 405):
            raise LLMError("this service does not list its models; type the model name instead") from e
        raise LLMError(f"the service answered HTTP {e.code}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise LLMError(f"could not reach {url.split('?')[0]}: {getattr(e, 'reason', e)}") from e
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise LLMError("this service does not list its models; type the model name instead") from e
    if not isinstance(data, dict) or not isinstance(data.get("data"), list):
        raise LLMError("this service does not list its models; type the model name instead")
    return data


class Provider:
    name = "provider"
    model = ""

    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def conversation(self, system: str, tools: list[dict[str, Any]]) -> "Conversation":
        raise NotImplementedError

    @property
    def label(self) -> str:
        return f"{self.name}:{self.model}"


class Conversation:
    def send_user(self, text: str) -> Turn:
        raise NotImplementedError

    def send_tool_results(self, results: list[tuple[str, str, bool]]) -> Turn:
        """results: (tool_call_id, output text, is_error)."""
        raise NotImplementedError


# ------------------------------------------------------------------ Anthropic
class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(self, model: str = DEFAULT_MODEL["anthropic"], effort: str = "medium", timeout_s: float = 120.0,
                 client: Any = None, api_key: str | None = None) -> None:
        if client is None:
            import anthropic

            # No key given: the SDK reads ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN itself.
            client = anthropic.Anthropic(timeout=timeout_s, max_retries=1, **({"api_key": api_key} if api_key else {}))
        self.client, self.model, self.effort = client, model, effort

    def _create(self, **kw: Any) -> Any:
        try:
            return self.client.messages.create(model=self.model, max_tokens=16000, **kw)
        except Exception as e:  # SDK errors vary by version; the caller only needs "it failed"
            raise LLMError(f"{type(e).__name__}: {e}") from e

    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> dict[str, Any]:
        r = self._create(system=system, messages=[{"role": "user", "content": user}],
                         output_config={"effort": self.effort, "format": {"type": "json_schema", "schema": schema}})
        if r.stop_reason != "end_turn":
            raise LLMError(f"stop_reason {r.stop_reason}")
        return _parse_json(next((b.text for b in r.content if b.type == "text"), ""))

    def conversation(self, system: str, tools: list[dict[str, Any]]) -> Conversation:
        return _AnthropicConversation(self, system, [{**t, "strict": True} for t in tools])


class _AnthropicConversation(Conversation):
    def __init__(self, p: AnthropicProvider, system: str, tools: list[dict[str, Any]]) -> None:
        self.p, self.system, self.tools, self.messages = p, system, tools, []

    def _step(self) -> Turn:
        r = self.p._create(system=self.system, tools=self.tools, messages=self.messages,
                           output_config={"effort": self.p.effort})
        self.messages.append({"role": "assistant", "content": r.content})  # keep thinking blocks unchanged
        turn = Turn(stop="tool_use" if r.stop_reason == "tool_use" else
                    "end" if r.stop_reason in ("end_turn", "stop_sequence") else str(r.stop_reason))
        for b in r.content:
            if b.type == "text" and b.text.strip():
                turn.texts.append(b.text.strip())
            elif b.type == "tool_use":
                turn.tool_calls.append(ToolCall(b.id, b.name, dict(b.input)))
        return turn

    def send_user(self, text: str) -> Turn:
        self.messages.append({"role": "user", "content": text})
        return self._step()

    def send_tool_results(self, results: list[tuple[str, str, bool]]) -> Turn:
        self.messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": i, "content": out, **({"is_error": True} if err else {})}
            for i, out, err in results]})
        return self._step()


# ------------------------------------------- OpenAI and OpenAI-compatible APIs
class OpenAIProvider(Provider):
    def __init__(self, name: str = "openai", model: str = DEFAULT_MODEL["openai"], api_key: str | None = None,
                 base_url: str | None = None, timeout_s: float = 120.0, client: Any = None) -> None:
        if client is None:
            import openai

            client = openai.OpenAI(api_key=api_key, base_url=base_url, timeout=timeout_s, max_retries=1)
        self.client, self.name, self.model = client, name, model

    def _create(self, **kw: Any) -> Any:
        try:
            return self.client.chat.completions.create(model=self.model, **kw)
        except Exception as e:
            raise LLMError(f"{type(e).__name__}: {e}") from e

    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> dict[str, Any]:
        if self.name == "openai":  # strict JSON schema output
            fmt: dict[str, Any] = {"type": "json_schema", "json_schema": {"name": "answer", "schema": schema, "strict": True}}
        else:  # DeepSeek and most compatible APIs only promise "some JSON": describe the shape instead
            fmt = {"type": "json_object"}
            system += f"\n\nAnswer with one JSON object that matches this JSON schema:\n{json.dumps(schema)}"
        r = self._create(messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                         response_format=fmt)
        choice = r.choices[0]
        if choice.finish_reason != "stop":
            raise LLMError(f"finish_reason {choice.finish_reason}")
        return _parse_json(choice.message.content or "")

    def conversation(self, system: str, tools: list[dict[str, Any]]) -> Conversation:
        fns = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                 "parameters": t["input_schema"],
                                                 **({"strict": True} if self.name == "openai" else {})}}
               for t in tools]
        return _OpenAIConversation(self, system, fns)


class _OpenAIConversation(Conversation):
    def __init__(self, p: OpenAIProvider, system: str, tools: list[dict[str, Any]]) -> None:
        self.p, self.tools = p, tools
        self.messages: list[dict[str, Any]] = [{"role": "system", "content": system}]

    def _step(self) -> Turn:
        r = self.p._create(messages=self.messages, tools=self.tools)
        choice = r.choices[0]
        msg = choice.message
        calls = list(msg.tool_calls or [])
        entry: dict[str, Any] = {"role": "assistant", "content": msg.content or ""}
        if calls:
            entry["tool_calls"] = [{"id": c.id, "type": "function",
                                    "function": {"name": c.function.name, "arguments": c.function.arguments}}
                                   for c in calls]
        self.messages.append(entry)
        turn = Turn(texts=[msg.content.strip()] if (msg.content or "").strip() else [],
                    stop="tool_use" if calls else "end" if choice.finish_reason == "stop" else str(choice.finish_reason))
        for c in calls:
            try:
                args = json.loads(c.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {"_invalid_json": c.function.arguments}
            turn.tool_calls.append(ToolCall(c.id, c.function.name, args if isinstance(args, dict) else {}))
        return turn

    def send_user(self, text: str) -> Turn:
        self.messages.append({"role": "user", "content": text})
        return self._step()

    def send_tool_results(self, results: list[tuple[str, str, bool]]) -> Turn:
        for i, out, err in results:
            self.messages.append({"role": "tool", "tool_call_id": i, "content": f"ERROR: {out}" if err else out})
        return self._step()


def _parse_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):  # some compatible APIs wrap JSON in a code fence
        text = text.strip("`").removeprefix("json").strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise LLMError(f"answer was not JSON: {e}") from e
    if not isinstance(data, dict):
        raise LLMError("answer was not a JSON object")
    return data
