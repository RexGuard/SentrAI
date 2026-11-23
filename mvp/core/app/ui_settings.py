"""The web dashboard's Configuration page: every setting the setup wizard knows, grouped by section, and a save.

Same rules as the Streamlit console (page_config): the saved values over the defaults, the same validation
(sentrai_config.valid), the same file (sentrai_config.save). Secrets and the generated API token are never sent
to the browser: a field shows only whether it is set, and a blank secret on save keeps what is saved.
"""
from __future__ import annotations

from typing import Any, Callable

from fastapi import Body, FastAPI, HTTPException, Request

from . import hosted
from .config import sentrai_config as cfg


def field_row(f: Any, current: dict[str, str]) -> dict[str, Any]:
    value = current.get(f.env, f.default)
    hidden = f.secret or f.generated
    return {"env": f.env, "prompt": f.prompt, "kind": f.kind.__name__, "secret": bool(f.secret),
            "generated": bool(f.generated), "choices": list(f.choices), "preset_field": f.env in cfg.PRESET_FIELDS,
            "advanced": bool(f.advanced),
            "value": "" if hidden else value, "is_set": bool(value), "default": "" if hidden else f.default,
            "hint": cfg.mask(value) if hidden else ""}


def changes(fields: dict[str, Any], before: dict[str, str], after: dict[str, str]) -> list[dict[str, str]]:
    """What a save changed, for the audit record: a secret only as "…a1b2" (cfg.mask), never its value."""
    out = []
    for env in sorted(after):
        old, new = str(before.get(env, "")), str(after.get(env, ""))
        if old == new:
            continue
        f = fields.get(env)
        what = "set" if not old else "cleared" if not new else "changed"
        if f is not None and (f.secret or f.generated):
            out.append({"env": env, "what": what, "now": cfg.mask(new)})
        else:
            out.append({"env": env, "what": what, "from": old, "to": new})
    return out


def install(app: FastAPI, reload_after_save: Callable[[], Any],
            record: Callable[[str, dict[str, Any]], Any] | None = None) -> None:
    """record(type, data): the audit trail (core.scribe), so a settings change says who changed what."""
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
    def post_settings(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """Save changed settings: {"values": {ENV: value}}. A blank secret keeps the saved one; generated fields
        cannot be changed here, and neither can an advanced setting: the panel shows those read-only and the SentrAI
        team changes them in the terminal (sudo sentrai settings set). Everything is checked before anything is
        written."""
        sent = body.get("values")
        if not isinstance(sent, dict):
            raise HTTPException(400, "send {\"values\": {...}}")
        values = {f.env: f.default for f in cfg.FIELDS.values()} | cfg.read()
        before = dict(values)
        bad: list[str] = []
        for env, raw in sent.items():
            f = cfg.FIELDS.get(str(env))
            if f is None or f.generated:
                raise HTTPException(400, f"{env} is not a setting that can be changed here")
            if f.advanced:
                raise HTTPException(403, f"{f.prompt} is an advanced setting. Your SentrAI team changes it in the "
                                         f"terminal: sudo sentrai settings set {f.env}=...")
            text = str(raw).strip()
            if f.secret and not text:
                continue
            if text != values.get(f.env, "") and (why := hosted.setting_refused(f.env, text)) is not None:
                raise HTTPException(403, f"{f.prompt}: {why}")
            if not cfg.valid(f, text):
                bad.append(f.prompt)
            else:
                values[f.env] = text
        if bad:
            raise HTTPException(400, "Please check: " + "; ".join(bad))
        cfg.save(values)
        cfg.mark_setup_done("dashboard")
        changed = changes(cfg.FIELDS, before, values)
        if record is not None and changed:
            account = getattr(request.state, "account", None)
            try:
                record("settings_changed", {"operator": (account or {}).get("email") or "team (API token)",
                                            "changed": changed})
            except Exception:  # noqa: BLE001  saved is saved; a full disk must not turn it into a failed save
                pass
        try:
            reload_after_save()
            note = "Sentry and the integrations use the new settings now. Restart SentrAI (stop, then run) for the other settings."
        except Exception:  # noqa: BLE001 - saved is saved; a reload that fails must not look like a failed save
            note = "Start SentrAI (run.ps1 or run.sh) so the core picks them up."
        return {"saved": sorted(str(k) for k in sent), "message": f"Saved. {note}"}
