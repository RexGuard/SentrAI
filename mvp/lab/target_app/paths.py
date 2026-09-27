"""Shared filesystem locations for the lab target app.

All paths are resolved relative to ``mvp/lab`` so the app, collector and
tests agree on where logs and the SQLite database live. Locations can be
overridden with environment variables (used by the pytest suite so it can
point at a temp directory).
"""
from __future__ import annotations

import os
from pathlib import Path

# mvp/lab/target_app/paths.py -> parents[1] == mvp/lab
LAB_DIR = Path(__file__).resolve().parents[1]


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
ACCESS_LOG = "access.jsonl"
AUTH_LOG = "auth.jsonl"
DB_LOG = "db.jsonl"
OS_LOG = "os.jsonl"

ALL_LOGS = (ACCESS_LOG, AUTH_LOG, DB_LOG, OS_LOG)
