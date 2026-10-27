"""The core's half of extensions (mvp/sentrai_extensions.py finds them): it starts each added extension's
core part, plugs it into the pipeline, and takes it out again, all while the core runs.

An extension's core.py has ``setup(ctx)``, which returns an `Extension`. Subclass it and override what
the extension needs; everything else does nothing:

  responders(below)     Responders put after SentrAI's own. Each takes over the action types it lists;
                        below(type) is the responder it wraps (the blocklist or the host firewall), which
                        it applies first, so the local block always holds too.
  classifiers()         Classifier steps, asked after the rules and before the keyword fallback.
  incident_opened(inc)  A new incident was opened (an outside lookup of its address, ...).
  contacts(rows)        Add fields to the routing contacts the dashboard shows (GET /routing).
  addresses(rows)       Add fields to the people an alert is for (each notification's deliver_to).
  agent()               A row for GET /agents (the Classifier page reads the AI classifier's).
  status()              For the Extensions page: configured, detail, last_ok, last_error, testable.
  test()                One harmless call with the saved settings.
  close()               Removed while the core runs: stop its threads and undo what it put outside SentrAI.

core.py may also define ``routes(router, live)`` to add API routes. They are registered when the core
starts, for every installed extension, and answer 404 while it is not added; ``live()`` returns the
running Extension. ``setup`` raises ValueError for settings that cannot work (the Extensions page shows
the message) and must not call outside services: that is what ``test()`` is for.

Everything an extension may use is imported from here (``from app.extensions import ...``).
"""
from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

from .config import sentrai_config  # noqa: F401  (config.py puts mvp/ on sys.path, then these import)
import sentrai_extensions as se  # noqa: E402
import sentrai_paths  # noqa: E402

from .classifier import Classification, Classifier  # noqa: E402,F401
from .firewall import unsafe_reason  # noqa: E402,F401
from .protect import matches as is_protected  # noqa: E402,F401
from .responders import Action, Responder  # noqa: E402,F401
from .risk import CATEGORIES, clip_confidence  # noqa: E402,F401

log = logging.getLogger("sentrai.extensions")



class ExtensionError(Exception):
    """An add or remove the core refuses (the API answers 409)."""


class Extension:
    """One running extension's core part. Override only what the extension needs."""

    def responders(self, below: Callable[[str], Responder | None]) -> list[Responder]:
        """Responders put after SentrAI's own; each takes over the action types it lists. Called again
        whenever an extension is added or removed, so set the wrapped responder each time."""
        return []

    def classifiers(self) -> list[Classifier]:
        """Steps asked after the rules and before the keyword fallback, in this order."""
        return []

    def incident_opened(self, inc: dict[str, Any]) -> None:
        """A new incident (called under the core's lock: hand anything slow to a thread)."""

    def contacts(self, rows: list[dict[str, Any]]) -> None:
        """Add fields to the routing contacts the dashboard shows (GET /routing)."""

    def addresses(self, rows: list[dict[str, Any]]) -> None:
        """Add fields to the people an alert is for (each notification's deliver_to)."""

    def agent(self) -> dict[str, Any] | None:
        """A row for GET /agents, next to SentrAI's own agents."""
        return None

    def status(self) -> dict[str, Any]:
        """For the Extensions page: configured, detail, last_ok, last_error, testable. Never a secret."""
        return {"configured": True}

    def test(self) -> dict[str, Any]:
        """One harmless call with the saved settings: {"ok": True, "detail"} or {"ok": False, "error"}."""
        return {"ok": False, "error": "This extension has no test."}

    def close(self) -> dict[str, Any] | None:
        """Removed while the core runs: stop its threads and undo what it put outside SentrAI.
        What it returns goes into the audit record of the removal."""
        return None


class NotSetUp(Extension):
    """Added, but its key is not saved yet: it does nothing and says what is missing."""

    def __init__(self, why: str) -> None:
        self.why = why

    def status(self) -> dict[str, Any]:
        return {"configured": False, "detail": self.why, "testable": False}

    def test(self) -> dict[str, Any]:
        return {"ok": False, "error": self.why}


def when(ts: float | None) -> str | None:
    """A last-success time as the Extensions page shows it."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else None


class Context:
    """What an extension's core part gets from the core. Use these, not the engine's internals."""

    def __init__(self, manifest: se.Manifest, core: Any, environ: Mapping[str, str]) -> None:
        self.manifest = manifest
        self.name = manifest.name
        self.log = logging.getLogger(f"sentrai.ext.{manifest.name}")
        self._core = core
        self._environ = environ

    @property
    def settings(self) -> Any:
        """The core's own settings (protected_ips, background, ...), read when it started."""
        return self._core.settings

    @property
    def state_dir(self) -> Path:
        """Where the extension may keep files: next to the core's database."""
        return self._core.settings.db_path.parent

    @property
    def lock(self) -> Any:
        """The core's lock: hold it while changing incidents or reading the routing contacts."""
        return self._core.lock

    def setting(self, env: str) -> str:
        """One of its settings: the environment variable, its _FILE, or the manifest's default."""
        value = se.setting(env, self._environ)
        if value:
            return value
        return next((s.default for s in self.manifest.settings if s.env == env), "")

    def number(self, env: str, fallback: float) -> float:
        try:
            return float(self.setting(env) or fallback)
        except ValueError:
            return fallback

    def whole(self, env: str, fallback: int) -> int:
        try:
            return int(float(self.setting(env) or fallback))
        except ValueError:
            return fallback

    def record(self, kind: str, data: dict[str, Any]) -> None:
        """One record in the hash-chained audit trail."""
        self._core.scribe.record(self._core.name, kind, data)

    def note(self, src_ip: str, key: str, value: Any, text: str) -> None:
        """Puts `value` under `key` on every open incident from this address that has none yet, with a
        timeline line `text` (context for the person deciding, never a score)."""
        self._core.note_on_incidents(src_ip, key, value, text)

    def contact(self, ref: str) -> Any:
        """A routing contact by id or name, or None."""
        return self._core.router.contact(ref)

    def contacts(self) -> list[Any]:
        return list(self._core.router.contacts.values())

    def iso(self, ts: float | None = None) -> str:
        clock = self._core.clock
        return clock.iso(clock.now() if ts is None else ts)


@dataclass
class Running:
    manifest: se.Manifest
    ext: Extension
    fingerprint: str  # of its settings when it started, so a reload knows to start it again
    since: str


class Host:
    """The extensions this core has installed, which of them are added, and the running ones."""

    def __init__(self, core: Any, environ: Mapping[str, str] | None = None) -> None:
        self.core = core
        self.environ = os.environ if environ is None else environ
        self.installed, self.problems = se.discover(self.environ)
        words = {w.strip().lower() for w in self.environ.get(se.CHOICE_ENV, "").split(",") if w.strip()}
        unknown = sorted(words - set(self.installed) - {"all", "none"})
        if unknown:
            self.problems.append(f"{se.CHOICE_ENV} names {', '.join(unknown)}, which is not installed")
        for problem in self.problems:  # a skipped folder or a misspelt name: say so where people look
            log.warning("extensions: %s", problem)
        self.choices = se.Choices(sentrai_paths.path("core.extensions", core.settings.db_path.parent))
        self.running: dict[str, Running] = {}
        self.errors: dict[str, str] = {}  # name -> why its core part could not start
        self._modules: dict[str, ModuleType] = {}

    # ------------------------------------------------------------------ state
    @property
    def managed_by(self) -> str | None:
        """SENTRAI_EXTENSIONS when it is set: then the dashboard cannot add or remove."""
        return se.CHOICE_ENV if se.env_choice(list(self.installed), self.environ) is not None else None

    def decided(self) -> dict[str, tuple[bool, str]]:
        return se.decide(self.installed, self.choices.added(), self.environ)

    def added(self, name: str) -> bool:
        return self.decided().get(name, (False, ""))[0]

    def exts(self) -> list[tuple[str, Extension]]:
        """The running extensions, in page order."""
        return [(n, r.ext) for n, r in self.running.items()]

    def module(self, name: str) -> ModuleType | None:
        """Its core.py, imported once. None (and the reason in errors) when it cannot be."""
        if name in self._modules:
            return self._modules[name]
        m = self.installed[name]
        if "core" not in m.parts:
            return None
        try:
            mod = se.load_part(m, "core")
        except Exception as exc:  # a missing package, a syntax error: the rest of SentrAI runs on
            self.errors[name] = f"could not load its core part: {type(exc).__name__}: {exc}"[:300]
            log.warning("extension %s: %s", name, self.errors[name])
            return None
        self._modules[name] = mod
        return mod

    def _start(self, name: str) -> Running | None:
        mod = self.module(name)
        if mod is None:
            return None
        m = self.installed[name]
        try:
            ext = mod.setup(Context(m, self.core, self.environ))
            if not isinstance(ext, Extension):
                raise TypeError("setup() must return an Extension")
        except ValueError as exc:  # settings that cannot work: say why on the Extensions page
            self.errors[name] = str(exc)[:300]
            log.warning("extension %s is off: %s", name, exc)
            return None
        except Exception as exc:
            self.errors[name] = f"{type(exc).__name__}: {exc}"[:300]
            log.exception("extension %s could not start", name)
            return None
        self.errors.pop(name, None)
        run = Running(m, ext, se.fingerprint(m, self.environ), self.core.clock.now_iso())
        self.running[name] = run
        return run

    def _stop(self, name: str) -> dict[str, Any]:
        """Takes its part out of every action in force, closes it, and plugs the rest in again."""
        run = self.running.get(name)
        if run is None:
            return {}
        note = self.core.unplug_extension(name, run.ext)
        del self.running[name]
        self.core.rewire()
        return note

    def start(self) -> None:
        """At start-up, before saved blocks are put back: every added extension's core part."""
        for name, (on, _) in self.decided().items():
            if on:
                self._start(name)
        self.core.rewire()

    # ------------------------------------------------------------------ add / remove / reload
    def _get(self, name: str) -> se.Manifest:
        if name not in self.installed:
            raise KeyError(f"no extension called {name} is installed")
        return self.installed[name]

    def _changeable(self) -> None:
        if self.managed_by:
            raise ExtensionError(f"{se.CHOICE_ENV} is set on the server, so the extensions it lists are the "
                                 "ones on. Change it there.")

    def add(self, name: str, operator: str) -> dict[str, Any]:
        m = self._get(name)
        self._changeable()
        with self.core.lock:
            self.choices.set(name, True, operator, self.core.clock.now_iso())
            started = False
            if name not in self.running and "core" in m.parts and self._start(name) is not None:
                self.core.plug_in_extension(name, self.running[name].ext)
                started = True
            self.core.scribe.record(self.core.name, "extension_added", {
                "extension": name, "title": m.title, "operator": operator, "started": started,
                **({"error": self.errors[name]} if name in self.errors else {})})
            return self.row(name)

    def remove(self, name: str, operator: str) -> dict[str, Any]:
        m = self._get(name)
        self._changeable()
        with self.core.lock:
            self.choices.set(name, False, operator, self.core.clock.now_iso())
            cleanup = self._stop(name)
            self.errors.pop(name, None)
            self.core.scribe.record(self.core.name, "extension_removed", {
                "extension": name, "title": m.title, "operator": operator, **cleanup})
            return {**self.row(name), "cleanup": cleanup}

    def reload(self) -> list[dict[str, Any]]:
        """After the settings file changed: start, stop or restart each extension to match it."""
        sentrai_config.load(refresh=True)
        with self.core.lock:
            changed: dict[str, str] = {}
            for name, (on, _) in self.decided().items():
                m = self.installed[name]
                run = self.running.get(name)
                if run is not None and (not on or run.fingerprint != se.fingerprint(m, self.environ)):
                    self._stop(name)
                    changed[name] = "stopped"
                if on and name not in self.running and "core" in m.parts:
                    before = self.errors.get(name)
                    if self._start(name) is not None:
                        self.core.plug_in_extension(name, self.running[name].ext)
                        changed[name] = "restarted" if changed.get(name) else "started"
                    elif self.errors.get(name) != before or changed.get(name):
                        changed[name] = f"off: {self.errors.get(name)}"
            if changed:
                self.core.scribe.record(self.core.name, "extensions_reloaded", {"changed": changed})
        return self.rows()

    # ------------------------------------------------------------------ what the API shows
    def row(self, name: str) -> dict[str, Any]:
        m = self.installed[name]
        on, by = self.decided()[name]
        run = self.running.get(name)
        choice = self.choices.get(name) or {}
        row: dict[str, Any] = {**m.public(), "built_in": False, "added": on, "added_by": by,
                               "running": run is not None, "configured": False, "detail": "", "last_ok": None,
                               "last_error": None, "testable": False, "error": self.errors.get(name),
                               "changed_by": choice.get("by"), "changed_at": choice.get("at")}
        if run is not None:
            try:
                row.update({k: v for k, v in (run.ext.status() or {}).items() if k in (
                    "configured", "detail", "last_ok", "last_error", "testable")})
            except Exception as exc:  # a broken status must not break the page
                row["last_error"] = f"{type(exc).__name__}: {exc}"[:200]
        elif not on:
            row["detail"] = "Not added. Add it to use it; its settings are kept either way."
        elif "core" not in m.parts:
            row.update(configured=se.set_up(m, self.environ), detail="Runs in the notifier.")
        elif not row["error"]:
            row["detail"] = "Starting."
        if row["error"]:
            row["configured"] = False
        return row

    def rows(self) -> list[dict[str, Any]]:
        return [self.row(n) for n in self.installed]

    def test(self, name: str) -> dict[str, Any]:
        m = self._get(name)
        run = self.running.get(name)
        if run is None:
            why = self.errors.get(name) or (f"{m.title} is not added." if not self.added(name)
                                            else f"{m.title} runs in the notifier; it has no test here.")
            return {"ok": False, "error": why}
        try:
            return run.ext.test()
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200]}

    def live(self, name: str) -> Callable[[], Extension]:
        """For an extension's routes: the running Extension, or 404 while it is not added."""
        from fastapi import HTTPException

        title = self.installed[name].title

        def get() -> Extension:
            run = self.running.get(name)
            if run is None:
                why = self.errors.get(name)
                raise HTTPException(404, f"{title} could not start: {why}" if why else
                                    f"{title} is not added. Add it on the dashboard's Extensions page.")
            return run.ext

        return get

    def summary(self) -> dict[str, str]:
        """For the core_started audit record: what each added extension is doing."""
        out = {}
        for name, (on, _) in self.decided().items():
            if on:
                out[name] = "running" if name in self.running else f"off: {self.errors.get(name) or 'notifier only'}"
        return out

    # ------------------------------------------------------------------ hooks the core calls
    def each(self, hook: str, *args: Any) -> None:
        """Calls one hook on every running extension; a failing extension is logged, never fatal."""
        for name, ext in self.exts():
            try:
                getattr(ext, hook)(*args)
            except Exception:
                log.exception("extension %s failed in %s", name, hook)

    def agents(self) -> list[dict[str, Any]]:
        out = []
        for name, ext in self.exts():
            try:
                row = ext.agent()
            except Exception:
                log.exception("extension %s failed in agent", name)
                continue
            if row:
                out.append({**row, "extension": name})
        return out
