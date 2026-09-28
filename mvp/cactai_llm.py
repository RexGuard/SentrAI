"""Which AI model CactAI talks to. One small interface over several providers.

Cyanide (core) and Scout (lab) only need two things from a model:
  * ``complete_json(system, user, schema)``: one answer as JSON matching a schema
  * ``conversation(system, tools)``: a tool-use conversation (send text, get tool calls,
    send tool results back) that keeps each provider's own message format inside it

Providers:
  anthropic  ANTHROPIC_API_KEY  Claude, through the ``anthropic`` package
  openai     OPENAI_API_KEY     OpenAI, through the ``openai`` package
  deepseek   DEEPSEEK_API_KEY   DeepSeek's OpenAI-compatible API (``openai`` package)
  compatible CACTAI_LLM_API_KEY + CACTAI_LLM_BASE_URL: any other OpenAI-compatible service

CACTAI_LLM_PROVIDER picks one; "auto" (the default) takes the first provider whose key is
set, in the order above. CACTAI_LLM_MODEL overrides the provider's default model.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

PROVIDERS = ("anthropic", "openai", "deepseek", "compatible")
KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "deepseek": "DEEPSEEK_API_KEY",
           "compatible": "CACTAI_LLM_API_KEY"}
DEFAULT_MODEL = {"anthropic": "claude-opus-5", "openai": "gpt-5", "deepseek": "deepseek-chat", "compatible": ""}
BASE_URL = {"deepseek": "https://api.deepseek.com"}


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


def provider_name() -> str | None:
    """The provider to use, or None when no key is configured."""
    choice = os.getenv("CACTAI_LLM_PROVIDER", "auto").strip().lower() or "auto"
    if choice != "auto":
        return choice if choice in PROVIDERS and os.getenv(KEY_ENV[choice]) else None
    if os.getenv("ANTHROPIC_AUTH_TOKEN"):
        return "anthropic"
    return next((p for p in PROVIDERS if os.getenv(KEY_ENV[p])), None)


def from_env(effort: str = "medium", timeout_s: float = 120.0) -> "Provider | None":
    name = provider_name()
    if name is None:
        return None
    model = os.getenv("CACTAI_LLM_MODEL") or DEFAULT_MODEL[name]
    if name == "anthropic":
        return AnthropicProvider(model=model, effort=effort, timeout_s=timeout_s)
    base_url = os.getenv("CACTAI_LLM_BASE_URL") or BASE_URL.get(name)
    if name == "compatible" and not (base_url and model):
        raise LLMError("the compatible provider needs CACTAI_LLM_BASE_URL and CACTAI_LLM_MODEL")
    return OpenAIProvider(name=name, model=model, api_key=os.getenv(KEY_ENV[name]), base_url=base_url,
                          timeout_s=timeout_s)


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
                 client: Any = None) -> None:
        if client is None:
            import anthropic

            client = anthropic.Anthropic(timeout=timeout_s, max_retries=1)
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
