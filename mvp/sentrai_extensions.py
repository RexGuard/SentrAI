"""SentrAI extensions: outside services kept in their own folders, added and removed while SentrAI runs.

An extension is a folder with an ``extension.json`` manifest (what it is, its settings) and one module
for each part of SentrAI it plugs into: ``core.py`` runs inside the core, ``notifier.py`` inside the
notifier. SentrAI runs with none of them. This module finds them and reads their manifests. It is
standard library only, so every part and the setup wizard can use it without the extensions' packages.

Where extensions come from:
  mvp/extensions/<name>/      the ones that ship with SentrAI (Cloudflare, TypeSafe, Telegram, ...)
  SENTRAI_EXTENSIONS_DIR      more folders, separated by os.pathsep (for example /etc/sentrai/extensions).
                              Their code runs inside SentrAI, so a folder that anyone but its owner or
                              root can change is skipped, and a bundled extension is never replaced.
Installing or uninstalling one (adding or deleting its folder) takes effect when SentrAI restarts.

Which ones are on ("added"):
  SENTRAI_EXTENSIONS          when set, the final word: names separated by commas, "all" or "none".
                              The dashboard then shows the choice but cannot change it.
  extensions.json             the Add and Remove choices made on the dashboard's Extensions page, kept by
                              the core next to its database
  otherwise                   an extension counts as added once its main setting (its key or token) is
                              set, so settings saved before extensions existed keep working

An extension's settings are saved in the settings file under "extension:<name>" and read as environment
variables, like every other setting. Removing an extension keeps them, so adding it back restores it.

    python sentrai_extensions.py     list the installed extensions and anything that was skipped
"""
from __future__ import annotations

import hashlib
import importlib
import importlib.machinery
import importlib.util
import json
import os
import re
import stat
import sys
import time
import types
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MVP_DIR = Path(__file__).resolve().parent
BUNDLED_DIR = MVP_DIR / "extensions"
DIRS_ENV = "SENTRAI_EXTENSIONS_DIR"
CHOICE_ENV = "SENTRAI_EXTENSIONS"
MANIFEST = "extension.json"
PARTS = ("core", "notifier")
PACKAGE = "sentrai_ext"  # a part is imported as sentrai_ext.<name>.<part>, never under its own name
BUILT_IN = ("webhook", "email")  # part of SentrAI itself, so never an extension's name
RESERVED = (*BUILT_IN, "all", "none")  # SENTRAI_EXTENSIONS words
KINDS = ("Blocking", "Lookups", "Alerts", "Classifier", "Other")
SECTION_PREFIX = "extension:"  # an extension's section in the settings file
_NAME = re.compile(r"[a-z][a-z0-9_]{1,31}")
_ENV = re.compile(r"[A-Z][A-Z0-9_]{1,63}")
_TYPES = ("str", "int", "float")


@dataclass(frozen=True)
class Setting:
    env: str  # the environment variable the extension reads
    prompt: str
    default: str = ""
    kind: str = "str"  # str, int or float; only used to check what is typed
    secret: bool = False
    choices: tuple[str, ...] = ()
    advanced: bool = False  # on the Configuration page, but never asked by the setup wizard


@dataclass(frozen=True)
class Manifest:
    name: str
    title: str
    kind: str  # Blocking, Lookups, Alerts, Classifier or Other: how the Extensions page groups it
    what: str  # one sentence: what it does for the person running SentrAI
    path: Path
    source: str = "bundled"  # "bundled", or the SENTRAI_EXTENSIONS_DIR folder it came from
    docs: str = ""  # where to get its key or token
    about: str = ""  # one line over its settings
    settings: tuple[Setting, ...] = ()
    on_when: tuple[str, ...] = ()  # settings that make it count as added until someone chooses
    parts: tuple[str, ...] = ()  # which of core.py and notifier.py it has
    order: int = 100  # its place on the Extensions page and in the settings file
    requires: dict[str, list[str]] = field(default_factory=dict)  # part -> pip packages that part needs

    @property
    def section(self) -> str:
        return SECTION_PREFIX + self.name

    def public(self) -> dict[str, Any]:
        """What the API and the dashboard show about it."""
        return {"name": self.name, "title": self.title, "kind": self.kind, "what": self.what, "docs": self.docs,
                "about": self.about, "settings": [s.env for s in self.settings], "on_when": list(self.on_when),
                "parts": list(self.parts), "source": self.source, "requires": self.requires}


def _text(data: dict, key: str, required: bool = False) -> str:
    value = data.get(key, "")
    if not isinstance(value, str):
        raise ValueError(f'"{key}" must be text')
    if required and not value.strip():
        raise ValueError(f'"{key}" is missing')
    return value.strip()


def _setting(row: Any) -> Setting:
    if not isinstance(row, dict):
        raise ValueError("each setting must be an object")
    env = _text(row, "env", True)
    if not _ENV.fullmatch(env):
        raise ValueError(f"{env!r} is not an environment variable name (A-Z, 0-9 and _)")
    kind = _text(row, "kind") or "str"
    if kind not in _TYPES:
        raise ValueError(f"{env}: kind must be one of {', '.join(_TYPES)}")
    choices = row.get("choices") or []
    if not isinstance(choices, list) or not all(isinstance(c, str) for c in choices):
        raise ValueError(f"{env}: choices must be a list of text")
    default = row.get("default", "")
    if not isinstance(default, (str, int, float)) or isinstance(default, bool):
        raise ValueError(f"{env}: default must be text or a number")
    return Setting(env, _text(row, "prompt", True), str(default), kind, bool(row.get("secret")), tuple(choices),
                   bool(row.get("advanced")))


def read_manifest(folder: Path, source: str = "bundled") -> Manifest:
    """The extension in this folder. Raises ValueError (or OSError) with the reason it cannot be used."""
    data = json.loads((folder / MANIFEST).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{MANIFEST} must hold one JSON object")
    name = _text(data, "name") or folder.name
    if name != folder.name:
        raise ValueError(f"its name {name!r} must be the folder's name")
    if not _NAME.fullmatch(name):
        raise ValueError("a name is 2 to 32 lowercase letters, digits or _, starting with a letter")
    if name in RESERVED:
        raise ValueError(f"{name} is built into SentrAI" if name in BUILT_IN else f"{name} cannot be a name")
    kind = _text(data, "kind") or "Other"
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}")
    settings = tuple(_setting(row) for row in data.get("settings") or [])
    envs = [s.env for s in settings]
    if len(set(envs)) != len(envs):
        raise ValueError("a setting is listed twice")
    on_when = data.get("on_when") or []
    if not isinstance(on_when, list) or not set(on_when) <= set(envs):
        raise ValueError('"on_when" must name settings listed under "settings"')
    parts = tuple(p for p in PARTS if (folder / f"{p}.py").is_file())
    if not parts:
        raise ValueError("it has neither core.py nor notifier.py")
    order = data.get("order", 100)
    if not isinstance(order, int) or isinstance(order, bool):
        raise ValueError('"order" must be a whole number')
    requires = data.get("requires") or {}
    if not isinstance(requires, dict) or not all(isinstance(v, list) for v in requires.values()):
        raise ValueError('"requires" must map a part to a list of packages')
    return Manifest(name, _text(data, "title", True), kind, _text(data, "what", True), folder, source,
                    _text(data, "docs"), _text(data, "about"), settings, tuple(on_when), parts, order,
                    {str(k): [str(x) for x in v] for k, v in requires.items()})


def _unsafe(path: Path) -> str | None:
    """Why code here must not run inside SentrAI: someone other than its owner (or root) can change it."""
    if os.name != "posix":
        return None  # Windows permissions are not mode bits; the installer keeps C:\\Program Files safe
    try:
        st = path.stat()
    except OSError as exc:
        return str(exc)
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"{path} can be changed by other users (chmod go-w)"
    if st.st_uid not in (0, os.getuid()):
        return f"{path} belongs to another user"
    return None


def _unsafe_tree(folder: Path) -> str | None:
    for p in [folder, *sorted(folder.rglob("*"))]:
        if "__pycache__" in p.parts or not (p.is_dir() or p.suffix in (".py", ".json")):
            continue
        if (why := _unsafe(p)) is not None:
            return why
    return None


def folders(environ: Mapping[str, str] | None = None) -> list[tuple[Path, str]]:
    """(folder, source) to look in: the bundled one first, then SENTRAI_EXTENSIONS_DIR."""
    env = os.environ if environ is None else environ
    out = [(BUNDLED_DIR, "bundled")]
    for raw in env.get(DIRS_ENV, "").split(os.pathsep):
        if raw.strip():
            out.append((Path(raw.strip()).expanduser(), raw.strip()))
    return out


def discover(environ: Mapping[str, str] | None = None) -> tuple[dict[str, Manifest], list[str]]:
    """The installed extensions by name (in page order), and what was skipped and why."""
    found: dict[str, Manifest] = {}
    problems: list[str] = []
    for base, source in folders(environ):
        if not base.is_dir():
            if source != "bundled":
                problems.append(f"{base}: no such folder")
            continue
        if source != "bundled" and (why := _unsafe(base)):
            problems.append(f"skipped {base}: {why}")
            continue
        for folder in sorted(p for p in base.iterdir() if p.is_dir() and (p / MANIFEST).is_file()):
            if source != "bundled" and (why := _unsafe_tree(folder)):
                problems.append(f"skipped {folder}: {why}")
                continue
            try:
                m = read_manifest(folder, source)
            except (OSError, ValueError) as exc:
                problems.append(f"skipped {folder}: {exc}")
                continue
            if m.name in found:
                problems.append(f"skipped {folder}: {m.name} is already installed from {found[m.name].source}")
                continue
            found[m.name] = m
    return dict(sorted(found.items(), key=lambda kv: (kv[1].order, kv[0]))), problems


_CACHE: dict[str, tuple[dict[str, Manifest], list[str]]] = {}


def installed(environ: Mapping[str, str] | None = None) -> dict[str, Manifest]:
    """discover(), read once per set of folders."""
    env = os.environ if environ is None else environ
    key = env.get(DIRS_ENV, "")
    if key not in _CACHE:
        _CACHE[key] = discover(env)
    return _CACHE[key][0]


def setting(env_name: str, environ: Mapping[str, str] | None = None) -> str:
    """A setting's value: NAME, or the contents of the file NAME_FILE names (as the core reads its secrets)."""
    env = os.environ if environ is None else environ
    path = env.get(f"{env_name}_FILE", "").strip()
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            return ""
    return env.get(env_name, "").strip()


def set_up(m: Manifest, environ: Mapping[str, str] | None = None) -> bool:
    """True when the extension's main setting (its key or token) has a value."""
    return any(setting(e, environ) for e in m.on_when)


def fingerprint(m: Manifest, environ: Mapping[str, str] | None = None) -> str:
    """Changes whenever one of its settings does, so a running extension knows to start again."""
    text = "\n".join(f"{s.env}={setting(s.env, environ)}" for s in m.settings)
    return hashlib.sha256(text.encode()).hexdigest()


def env_choice(names: list[str] | tuple[str, ...], environ: Mapping[str, str] | None = None) -> set[str] | None:
    """The extensions SENTRAI_EXTENSIONS turns on, or None when it is not set (the dashboard decides)."""
    env = os.environ if environ is None else environ
    raw = env.get(CHOICE_ENV, "")
    words = {w.strip().lower() for w in raw.split(",") if w.strip()}
    if not words:
        return None
    if "all" in words:
        return set(names)
    return words & set(names)


def decide(manifests: Mapping[str, Manifest], choices: Mapping[str, bool], environ: Mapping[str, str] | None = None,
           ) -> dict[str, tuple[bool, str]]:
    """name -> (added, by what): "SENTRAI_EXTENSIONS", "dashboard" or "settings"."""
    by_env = env_choice(list(manifests), environ)
    out: dict[str, tuple[bool, str]] = {}
    for name, m in manifests.items():
        if by_env is not None:
            out[name] = (name in by_env, CHOICE_ENV)
        elif name in choices:
            out[name] = (bool(choices[name]), "dashboard")
        else:
            out[name] = (set_up(m, environ), "settings")
    return out


class Choices:
    """The Add and Remove choices made on the dashboard, kept by the core in extensions.json."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.rows: dict[str, dict[str, Any]] = {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):  # none made yet, or unreadable: every extension follows its settings
            return
        rows = data.get("extensions") if isinstance(data, dict) else None
        if isinstance(rows, dict):
            self.rows = {str(k): v for k, v in rows.items() if isinstance(v, dict) and isinstance(v.get("added"), bool)}

    def added(self) -> dict[str, bool]:
        return {k: v["added"] for k, v in self.rows.items()}

    def get(self, name: str) -> dict[str, Any] | None:
        return self.rows.get(name)

    def set(self, name: str, added: bool, by: str, at: str | None = None) -> None:
        self.rows[name] = {"added": added, "by": by, "at": at or time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"extensions": self.rows}, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)


def _package(m: Manifest) -> None:
    """Registers sentrai_ext.<name> as a package whose only folder is the extension's own."""
    if PACKAGE not in sys.modules:
        root = importlib.util.module_from_spec(importlib.machinery.ModuleSpec(PACKAGE, None, is_package=True))
        root.__path__ = []  # nothing is found by name under it: each extension registers its own folder
        sys.modules[PACKAGE] = root
    name = f"{PACKAGE}.{m.name}"
    pkg = sys.modules.get(name)
    if pkg is None or list(getattr(pkg, "__path__", [])) != [str(m.path)]:
        for stale in [k for k in sys.modules if k.startswith(name + ".")]:  # parts loaded from another folder
            del sys.modules[stale]
        spec = importlib.machinery.ModuleSpec(name, None, is_package=True)
        spec.submodule_search_locations = [str(m.path)]
        pkg = importlib.util.module_from_spec(spec)
        sys.modules[name] = pkg
        setattr(sys.modules[PACKAGE], m.name, pkg)


def load_part(m: Manifest, part: str) -> types.ModuleType:
    """The extension's core.py or notifier.py, imported as sentrai_ext.<name>.<part>.

    Its folder is never put on sys.path, so an extension called telegram or cloudflare cannot hide the
    pip package of that name, and two extensions can both have a module called client.py."""
    if part not in m.parts:
        raise ImportError(f"the {m.name} extension has no {part}.py")
    _package(m)
    return importlib.import_module(f"{PACKAGE}.{m.name}.{part}")


def main(argv: list[str]) -> int:
    found, problems = discover()
    print(f"Extensions ({', '.join(str(p) for p, _ in folders())}):")
    for m in found.values():
        print(f"  {m.name:<12} {m.title:<12} {m.kind:<10} parts: {', '.join(m.parts):<15} {m.source}")
    for p in problems:
        print(f"  ! {p}")
    by_env = env_choice(list(found))
    if by_env is not None:
        print(f"{CHOICE_ENV} turns on: {', '.join(sorted(by_env)) or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
