"""The AI model behind Cyanide and the chat: which one is in use, why it is off, reload and test.

The dashboard's Configuration page uses these through ``/ai``: saving the AI settings reloads
them here (no restart needed), and "Test connection" makes one real request through the same
code Cyanide plans with, so a pass means Cyanide can plan and a failure says why.
"""
from __future__ import annotations

import os
from typing import Any

from .config import sentrai_config  # the setup wizard's module (config.py puts mvp/ on sys.path)
from .saguaro import Saguaro

import sentrai_llm  # noqa: E402


def why_off() -> str | None:
    """Why the core runs without an AI model, or None when a model is configured."""
    if os.getenv("SENTRAI_ENGINE", "cyanide").lower() == "saguaro":
        return "SENTRAI_ENGINE=saguaro runs Warden's fixed playbooks only"
    if os.getenv("CYANIDE_ENABLED", "1") == "0":
        return "CYANIDE_ENABLED=0 turns the AI model off"
    if sentrai_llm.provider_name() is None:
        return sentrai_llm.off_reason()
    try:
        sentrai_llm.from_env()
    except sentrai_llm.LLMError as e:
        return str(e)
    return None


def status(core: Saguaro, chat: Any) -> dict[str, Any]:
    """What the running core uses right now, for the dashboard."""
    name = sentrai_llm.provider_name()
    provider = chat.provider or getattr(getattr(core, "planner", None), "provider", None)
    return {"engine": core.name,
            "planner": core.planner_status() if hasattr(core, "planner_status") else "fixed playbooks",
            "chat": chat.status, "online": provider is not None,
            "provider": provider.name if provider else name, "model": provider.model if provider else None,
            "key_source": sentrai_llm.key_source(name) if name else None, "off_reason": why_off()}


def reload(core: Saguaro, chat: Any) -> dict[str, Any]:
    """Read the saved settings again and rebuild Cyanide's planner and the chat's model."""
    from .chat import default_chat_provider
    from .cyanide import Cyanide, default_planner

    sentrai_config.load(refresh=True)
    if isinstance(core, Cyanide):
        core.planner = default_planner()
        chat.provider = default_chat_provider()
    chat.off_reason = core.ai_off_reason = why_off()
    return status(core, chat)


def test(core: Saguaro, chat: Any, settings: dict[str, str] | None = None) -> dict[str, Any]:
    """One real request. With settings (from the Configuration form, maybe unsaved) test those;
    without, test what Cyanide uses now. Never changes what the core uses."""
    timeout = float(os.getenv("CYANIDE_TIMEOUT_S", "20"))
    effort = os.getenv("CYANIDE_EFFORT", "low")
    if settings:
        name = (settings.get("provider") or "").strip()
        key = (settings.get("api_key") or "").strip()
        if not key:
            return {"ok": False, "provider": name, "model": None, "ms": 0, "error": "enter the API key first",
                    "hint": None, "tested": "form"}
        try:
            provider = sentrai_llm.build(name, key, (settings.get("model") or "").strip() or None,
                                        (settings.get("base_url") or "").strip() or None, effort=effort,
                                        timeout_s=timeout)
        except sentrai_llm.LLMError as e:
            return {"ok": False, "provider": name, "model": settings.get("model") or None, "ms": 0,
                    "error": str(e), "hint": None, "tested": "form"}
        provider.model = os.getenv("CYANIDE_MODEL") or provider.model
        return {**sentrai_llm.check(provider), "tested": "form"}
    planner = getattr(core, "planner", None)
    provider = getattr(planner, "provider", None) or chat.provider
    if provider is None:
        return {"ok": False, "provider": None, "model": None, "ms": 0, "tested": "running",
                "error": f"Cyanide has no AI model: {why_off() or 'unknown reason'}", "hint": None}
    return {**sentrai_llm.check(provider), "tested": "running"}
