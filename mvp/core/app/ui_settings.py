"""The web dashboard's Configuration page: every setting the setup wizard knows, grouped by section, and a save.

Same rules as the Streamlit console (page_config): the saved values over the defaults, the same validation
(sentrai_config.valid), the same file (sentrai_config.save). Secrets and the generated API token are never sent
to the browser: a field shows only whether it is set, and a blank secret on save keeps what is saved.
"""
from __future__ import annotations

from typing import Any, Callable

from fastapi import Body, FastAPI, HTTPException

from .config import sentrai_config as cfg


def field_row(f: Any, current: dict[str, str]) -> dict[str, Any]:
    value = current.get(f.env, f.default)
    hidden = f.secret or f.generated
    return {"env": f.env, "prompt": f.prompt, "kind": f.kind.__name__, "secret": bool(f.secret),
            "generated": bool(f.generated), "choices": list(f.choices), "preset_field": f.env in cfg.PRESET_FIELDS,
            "value": "" if hidden else value, "is_set": bool(value), "default": "" if hidden else f.default}


def install(app: FastAPI, reload_after_save: Callable[[], Any]) -> None:
    @app.get("/ui/settings")
    def get_settings() -> dict[str, Any]:
        current = {f.env: f.default for f in cfg.FIELDS.values()} | cfg.read()
        sections = [{"key": s.key, "title": s.title, "about": s.about, "extension": s.key.startswith("extension:"),
                     "fields": [field_row(f, current) for f in s.fields]} for s in cfg.ALL_SECTIONS]
        return {"path": cfg.config_path().name, "sections": sections,
                "presets": {name: {"label": cfg.preset_label(name), "about": cfg.PRESETS[name].about,
                                   "values": cfg.preset_values(name)} for name in cfg.PRESETS},
                "advanced": cfg.ADVANCED, "advanced_about": cfg.ADVANCED_ABOUT}

    @app.post("/ui/settings")
    def post_settings(body: dict = Body(...)) -> dict[str, Any]:
        """Save changed settings: {"values": {ENV: value}}. A blank secret keeps the saved one; generated fields
        cannot be changed here. Everything is checked before anything is written."""
        sent = body.get("values")
        if not isinstance(sent, dict):
            raise HTTPException(400, "send {\"values\": {...}}")
        values = {f.env: f.default for f in cfg.FIELDS.values()} | cfg.read()
        bad: list[str] = []
        for env, raw in sent.items():
            f = cfg.FIELDS.get(str(env))
            if f is None or f.generated:
                raise HTTPException(400, f"{env} is not a setting that can be changed here")
            text = str(raw).strip()
            if f.secret and not text:
                continue
            if not cfg.valid(f, text):
                bad.append(f.prompt)
            else:
                values[f.env] = text
        if bad:
            raise HTTPException(400, "Please check: " + "; ".join(bad))
        cfg.save(values)
        cfg.mark_setup_done("dashboard")
        try:
            reload_after_save()
            note = "Cyanide and the extensions use the new settings now. Restart SentrAI (stop, then run) for the other settings."
        except Exception:  # noqa: BLE001 - saved is saved; a reload that fails must not look like a failed save
            note = "Start SentrAI (run.ps1 or run.sh) so the core picks them up."
        return {"saved": sorted(str(k) for k in sent), "message": f"Saved. {note}"}
