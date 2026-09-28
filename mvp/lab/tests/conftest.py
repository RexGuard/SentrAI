"""Pytest configuration: isolate logs/DB into a temp dir and fix sys.path."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# Make the lab package importable regardless of the working directory.
LAB_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB_DIR))

# Redirect all file output to a throwaway temp directory BEFORE the app or
# collector modules resolve any paths. paths.py reads these env vars lazily.
_TMP = tempfile.mkdtemp(prefix="cactai-lab-test-")
os.environ.setdefault("CACTAI_LAB_LOGS", str(Path(_TMP) / "logs"))
os.environ.setdefault("CACTAI_LAB_DB", str(Path(_TMP) / "portal.sqlite3"))
os.environ["CACTAI_SCOUT_SOURCES"] = str(Path(_TMP) / "scout-sources.json")
os.environ["CACTAI_CONFIG"] = str(Path(_TMP) / "no-config.json")  # ignore this machine's saved settings
# Keep the real seed dir (holds the admin password) — do not override it.
