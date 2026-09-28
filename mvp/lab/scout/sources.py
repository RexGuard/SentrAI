"""The log files the technician approved, read by the collector (``collector.default_sources``)."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

DEFAULT_FILE = Path(__file__).resolve().parent / "sources.json"


def sources_file() -> Path:
    return Path(os.environ.get("CACTAI_SCOUT_SOURCES", str(DEFAULT_FILE)))


def load() -> list[dict]:
    try:
        data = json.loads(sources_file().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [s for s in data if isinstance(s, dict) and s.get("path") and s.get("layer")]


def add(entry: dict, confirmed_by: str) -> None:
    current = [s for s in load() if s["path"] != entry["path"]]
    current.append({**entry, "confirmed_by": confirmed_by, "confirmed_at": time.strftime("%Y-%m-%dT%H:%M:%S")})
    f = sources_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(current, indent=2), encoding="utf-8")
