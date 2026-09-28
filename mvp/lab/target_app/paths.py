"""Shared filesystem locations for the lab target app.

All paths are resolved relative to ``mvp/lab`` so the app, collector and
tests agree on where logs and the SQLite database live. Locations can be
overridden with environment variables or the settings file written by
``mvp/cactai_config.py`` (the pytest suite uses env vars to point at a temp directory).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# mvp/lab/target_app/paths.py -> parents[1] == mvp/lab, parents[2] == mvp
LAB_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(LAB_DIR.parent))
import cactai_config  # noqa: E402

cactai_config.load()  # saved settings become env defaults for everything below


def _dir_from_env(env_name: str, default: Path) -> Path:
    value = os.environ.get(env_name)
    path = Path(value) if value else default
    path.mkdir(parents=True, exist_ok=True)
    return path


def logs_dir() -> Path:
    """Directory holding the JSON-lines log files."""
    return _dir_from_env("CACTAI_LAB_LOGS", LAB_DIR / "logs")


def seed_dir() -> Path:
    return _dir_from_env("CACTAI_LAB_SEED", LAB_DIR / "seed")


def db_path() -> Path:
    value = os.environ.get("CACTAI_LAB_DB")
    if value:
        p = Path(value)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
    logs_dir()  # ensure lab dir exists
    return LAB_DIR / "portal.sqlite3"


# Log file names, shared with the collector.
ACCESS_LOG = os.environ.get("CACTAI_LOG_ACCESS", "access.jsonl")
AUTH_LOG = os.environ.get("CACTAI_LOG_AUTH", "auth.jsonl")
DB_LOG = os.environ.get("CACTAI_LOG_DB", "db.jsonl")
OS_LOG = os.environ.get("CACTAI_LOG_OS", "os.jsonl")

ALL_LOGS = (ACCESS_LOG, AUTH_LOG, DB_LOG, OS_LOG)
