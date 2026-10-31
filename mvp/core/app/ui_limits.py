"""What the web dashboard's Automation guardrails page needs: the limits map's data and its Save.

GET /ui/limits is the Streamlit console's limits_map_data() (canvas_model, generated from shaping.py); the save
checks the map's settings again with check_limits() and writes them to the same settings file the Configuration
page uses, then leaves the small "who changed it last" note the "last changed" chip reads.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request

import sentrai_accounts as acc  # noqa: E402
from . import canvas_model as cm
from .config import sentrai_config as cfg

NOTE = "guardrails-changed.json"  # who saved the guardrails last, and when; next to the settings file
LOCKED = "Your role can read everything but change nothing."


def current() -> dict[str, str]:
    return {f.env: f.default for f in cfg.FIELDS.values()} | cfg.read()


def note() -> dict[str, Any]:
    try:
        meta = json.loads((cfg.config_path().parent / NOTE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        meta = {}
    return meta if isinstance(meta, dict) else {}


def install(app: FastAPI) -> None:
    @app.get("/ui/limits")
    def get_limits(request: Request) -> dict[str, Any]:
        account = getattr(request.state, "account", None)
        off = bool(account) and not acc.can(account.get("role"), "configure")
        return {**cm.limits_map_data(current(), read_only=off, lock_reason=LOCKED if off else ""),
                "changed": note()}

    @app.post("/ui/limits")
    def post_limits(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """The map's Save: {"settings": {...}}. Checked again here; nothing is written unless all of it is fine."""
        account = getattr(request.state, "account", None)
        if account and not acc.can(account.get("role"), "configure"):
            raise HTTPException(403, LOCKED)
        try:
            changed = cm.check_limits(body.get("settings"))
        except ValueError as exc:
            raise HTTPException(400, f"Not saved: {exc}.") from exc
        path = cfg.save(current() | changed)
        who = (account or {}).get("email") or str(body.get("operator") or "dashboard")
        try:
            (Path(path).parent / NOTE).write_text(json.dumps(
                {"at": datetime.now(timezone.utc).isoformat(), "by": who}), encoding="utf-8")
        except OSError:
            pass  # the chip falls back to the settings file's time
        return {"message": f"Saved to {Path(path).name}. Restart SentrAI (run.sh or run.ps1) so the core uses the new limits."}
