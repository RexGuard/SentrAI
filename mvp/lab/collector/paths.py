"""Where the collector finds the JSON-lines logs it tails.

The folder is ``logs/`` in SentrAI's data root (``mvp/sentrai_paths.py``) unless ``SENTRAI_LAB_LOGS``,
set in the environment or by the settings file written by ``mvp/sentrai_config.py``, names another
one (the pytest suite uses env vars to point at a temp directory).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# mvp/lab/collector/paths.py -> parents[1] == mvp/lab, parents[2] == mvp
LAB_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(LAB_DIR.parent))
import sentrai_config  # noqa: E402
import sentrai_paths  # noqa: E402

sentrai_config.load()  # saved settings become env defaults for everything below


def logs_dir() -> Path:
    """Directory holding the JSON-lines log files: SENTRAI_LAB_LOGS, else logs/ in the data root."""
    path = sentrai_paths.path("logs")
    path.mkdir(parents=True, exist_ok=True)
    return path


# Log file names, shared with the collector.
ACCESS_LOG = os.environ.get("SENTRAI_LOG_ACCESS", "access.jsonl")
AUTH_LOG = os.environ.get("SENTRAI_LOG_AUTH", "auth.jsonl")
DB_LOG = os.environ.get("SENTRAI_LOG_DB", "db.jsonl")
OS_LOG = os.environ.get("SENTRAI_LOG_OS", "os.jsonl")
DECEPTION_LOG = os.environ.get("SENTRAI_LOG_DECEPTION", "deception.jsonl")  # tripwire touches written by the app being guarded

ALL_LOGS = (ACCESS_LOG, AUTH_LOG, DB_LOG, OS_LOG, DECEPTION_LOG)
