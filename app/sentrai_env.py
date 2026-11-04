"""Old names from before the CactAI -> SentrAI rename, still accepted so existing machines keep working.

* Settings: every component reads ``SENTRAI_*`` variables. ``adopt_old_names()`` (run when this
  module is imported, which sentrai_config and sentrai_llm do) copies each old ``CACTAI_*``
  variable to its ``SENTRAI_*`` name when that one is not set, and says once which old names it saw.
* Settings folder: ``~/.cactai`` moves to ``~/.sentrai`` the first time a SentrAI component looks
  for it (``home_dir()``). If the move fails, the old folder is used where it is.
* Saved settings files and records that still use ``CACTAI_*`` keys are read through ``new_name()``.

Stdlib only, like sentrai_config.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

OLD_PREFIX = "CACTAI_"
NEW_PREFIX = "SENTRAI_"
OLD_HOME = ".cactai"
NEW_HOME = ".sentrai"

_warned: set[str] = set()


def _warn(key: str, text: str) -> None:
    if key not in _warned:
        _warned.add(key)
        print(f"[sentrai] {text}", file=sys.stderr)


def new_name(name: str) -> str:
    """CACTAI_X -> SENTRAI_X; any other name unchanged."""
    return NEW_PREFIX + name[len(OLD_PREFIX):] if name.startswith(OLD_PREFIX) else name


def adopt_old_names(environ: "os._Environ[str] | dict[str, str]" = os.environ) -> list[str]:
    """Copy CACTAI_* variables to their SENTRAI_* names (a set SENTRAI_* one wins). Returns the old names seen."""
    old = sorted(k for k in list(environ) if k.startswith(OLD_PREFIX))
    for name in old:
        environ.setdefault(new_name(name), environ[name])
    if old:
        _warn("env", f"old setting names still work but are deprecated, rename them to SENTRAI_*: {', '.join(old)}")
    return old


def home_dir() -> Path:
    """~/.sentrai, moving an old ~/.cactai there first when only the old one exists."""
    new, old = Path.home() / NEW_HOME, Path.home() / OLD_HOME
    if not new.exists() and old.is_dir():
        try:
            old.rename(new)
            _warn("home", f"moved your settings from {old} to {new}")
        except OSError:
            _warn("home", f"could not move {old} to {new}; using {old} for now")
            return old
    return new


adopt_old_names()
