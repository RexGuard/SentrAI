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


def contacts(text: str) -> list[dict[str, str]]:
    """SENTRAI_CONTACTS ("Name | Role | email | phone; ...") as rows. Blank parts stay blank."""
    out = []
    for item in str(text or "").split(";"):
        parts = [p.strip() for p in item.split("|")][:4]
        if parts and parts[0]:
            parts += [""] * (4 - len(parts))
            out.append(dict(zip(("name", "role", "email", "phone"), parts)))
    return out[:20]


def install(app: FastAPI, reload_after_save: Callable[[], Any]) -> None:
    @app.get("/ui/contacts")
    def get_contacts() -> dict[str, Any]:
        """The Contact Us button: the team's contacts from the SENTRAI_CONTACTS setting."""
        f = cfg.FIELDS.get("SENTRAI_CONTACTS")
        saved = cfg.read().get("SENTRAI_CONTACTS")
        return {"contacts": contacts(saved if saved is not None else (f.default if f else ""))}

    @app.get("/ui/settings")
    def get_settings() -> dict[str, Any]:
        current = {f.env: f.default for f in cfg.FIELDS.values()} | cfg.read()
        found = cfg.sentrai_extensions.installed() if cfg.sentrai_extensions else {}
        features = {m.section for m in found.values() if m.feature}
        sections = [{"key": s.key, "title": s.title, "about": s.about,
                     "extension": s.key.startswith("extension:") and s.key not in features,
                     "feature": s.key in features, "name": s.key.removeprefix("extension:"),
                     "fields": [field_row(f, current) for f in s.fields]} for s in cfg.ALL_SECTIONS]
        # A feature (Jev) sits with SentrAI's own sections, right after the step it is part of.
        for row in [r for r in sections if r["feature"]]:
            sections.remove(row)
            at = next((i for i, r in enumerate(sections) if r["key"] == "classifier"), len(sections) - 1)
            sections.insert(at + 1, row)
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
            note = "Sentry and the integrations use the new settings now. Restart SentrAI (stop, then run) for the other settings."
        except Exception:  # noqa: BLE001 - saved is saved; a reload that fails must not look like a failed save
            note = "Start SentrAI (run.ps1 or run.sh) so the core picks them up."
        return {"saved": sorted(str(k) for k in sent), "message": f"Saved. {note}"}
