"""What the web dashboard's Overview canvas needs: everything it draws, and the three things it can save.

GET /ui/overview is the console's canvas_data() (canvas_model.flow_canvas_data, the Streamlit console's own
functions); the saves are its save_canvas_layout, save_block_settings and toggle_extension_block, with the same
checks. The layout is one file next to the settings, shared by everyone who opens a console.
"""
from __future__ import annotations

import json
import platform
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import Body, FastAPI, HTTPException, Request

import sentrai_accounts as acc  # noqa: E402
from . import canvas_model as cm
from . import integrations
from .config import sentrai_config as cfg

CANVAS_FILE = "overview-canvas.json"  # next to the settings file
GUARDRAILS_NOTE = "guardrails-changed.json"
_NAME = re.compile(r"[a-z][a-z0-9_]{1,31}")  # an extension's name


def canvas_path() -> Path:
    return cfg.config_path().parent / CANVAS_FILE


def canvas_doc() -> dict:
    try:
        raw = json.loads(canvas_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raw = {}
    return cm.clean_canvas_doc(raw)


def install(app: FastAPI, core: Any, fleet: Any, health: Any, reload_extensions: Callable[[], Any]) -> None:
    def build(request: Request) -> dict:
        account = getattr(request.state, "account", None)
        read_only = bool(account) and not acc.can(account.get("role"), "configure")
        risk = core.risk(history=600, host=None)
        panel = risk.get("risk_scope") == "host"
        incidents = core.list_incidents(host=None)
        agents = core.agents_status()
        exts = [r for r in integrations.status(core) if isinstance(r, dict)]
        valid, _ = core.audit.verify_recent(wait=False)
        settings = {f.env: f.default for f in cfg.FIELDS.values()} | cfg.read()
        flow = cm.flow_map_data(risk, incidents, agents, core.blocklist(), exts, core.audit.snapshot(), settings, valid)
        found = cm.panel_machines(core.machines(), core.fleet_agents() if hasattr(core, "fleet_agents") else [], risk) \
            if panel else [cm.machine(platform.node() or "this computer", "Local", risk, None)]
        return cm.flow_canvas_data(
            flow, found, exts, settings, cfg.FIELDS, {n: [f.env for f in s.fields] for n, s in cfg.EXTENSION_SECTIONS.items()},
            canvas_doc(), read_only=read_only,
            lock_reason="Your role can read everything but change nothing." if read_only else "", panel=panel,
            ext_managed=any(r.get("added_by") == "SENTRAI_EXTENSIONS" for r in exts))

    @app.get("/ui/overview")
    def get_overview(request: Request) -> dict[str, Any]:
        return build(request)

    @app.post("/ui/overview/layout")
    def post_layout(body: dict = Body(...)) -> dict[str, Any]:
        """Where the blocks sit, which are hidden, the notes and the hand-drawn wires."""
        doc = cm.clean_canvas_doc(body.get("doc"))
        path = canvas_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
        except OSError as exc:
            raise HTTPException(500, f"could not write {path.name} ({exc.strerror or exc})") from exc
        return {"message": "Layout saved."}

    @app.post("/ui/overview/settings")
    def post_block_settings(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """A block's Save: only the settings that block offers, checked like the Configuration page checks them,
        the guardrail limits checked like Automation guardrails does, then written to the settings file."""
        data = build(request)
        block = next((b for b in data["blocks"] if b["id"] == body.get("block")), None)
        if block is None:
            raise HTTPException(404, "That block is not on the canvas any more.")
        try:
            changed = cm.check_block_settings(body.get("changes"), block.get("settings"))
            values = {f.env: f.default for f in cfg.FIELDS.values()} | cfg.read() | changed
            limits = any(env in cm.LIMIT_FIELDS for env in changed)
            if limits:
                values |= cm.check_limits(values)
        except ValueError as exc:
            raise HTTPException(400, f"Not saved: {exc}.") from exc
        path = cfg.save(values)
        if limits:
            try:
                (Path(path).parent / GUARDRAILS_NOTE).write_text(json.dumps({
                    "at": datetime.now(timezone.utc).isoformat(),
                    "by": (getattr(request.state, "account", None) or {}).get("name") or "operator"}), encoding="utf-8")
            except OSError:
                pass
        if block["kind"] == "ext":
            try:
                reload_extensions()
                note = "The extension uses the new settings now."
            except Exception:  # noqa: BLE001
                note = "Restart SentrAI (run.sh or run.ps1) so the extension picks them up."
            return {"message": f"Saved to {Path(path).name}. {note}"}
        return {"message": f"Saved to {Path(path).name}. Restart SentrAI (run.sh or run.ps1) so the core uses the new values."}

    @app.post("/ui/overview/toggle")
    def post_toggle(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """The switch on an extension's block: Add or Remove, as on the Extensions page."""
        name, on = str(body.get("name") or ""), bool(body.get("on"))
        title = str(body.get("title") or name)
        if not _NAME.fullmatch(name):
            raise HTTPException(400, "That is not an extension's name.")
        op = (getattr(request.state, "account", None) or {}).get("email") or str(body.get("operator") or "dashboard")
        try:
            if on:
                out = core.extensions.add(name, op)
                return {"message": f"Added {title}" + ("." if out.get("configured") else ". Save its key in its settings to set it up.")}
            core.extensions.remove(name, op)
            return {"message": f"Removed {title}."}
        except KeyError as exc:
            raise HTTPException(404, f"no extension called {name} is installed") from exc
        except Exception as exc:  # noqa: BLE001 - the extension's own refusal, in its words
            raise HTTPException(400, str(exc)) from exc
