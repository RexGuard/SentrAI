"""The log files the technician approved, read by the collector (``collector.default_sources``).

Scout's proposals wait in a second file (``pending.json`` next to ``sources.json``, or
``CACTAI_SCOUT_PENDING``) until a person approves or rejects them, from the terminal
(``python -m scout approve``), or on the dashboard's Collector page. Each proposal is saved the
moment Scout makes it, so stopping Scout, or running it with no terminal, loses nothing.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

DEFAULT_FILE = Path(__file__).resolve().parent / "sources.json"


def sources_file() -> Path:
    return Path(os.environ.get("CACTAI_SCOUT_SOURCES", str(DEFAULT_FILE)))


def pending_file() -> Path:
    return Path(os.environ.get("CACTAI_SCOUT_PENDING") or sources_file().with_name("pending.json"))


def proposal_id(path: str) -> str:
    """Stable id for a proposed file, so the dashboard can approve it without sending a path."""
    return "p" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:10]


def _read(f: Path) -> list[dict]:
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [s for s in data if isinstance(s, dict) and s.get("path") and s.get("layer")]


def _write(f: Path, items: list[dict]) -> None:
    """Write through a temp file, so the collector or core never reads half a list."""
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_name(f".{f.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(items, indent=2), encoding="utf-8")
    os.replace(tmp, f)


def load() -> list[dict]:
    return _read(sources_file())


def add(entry: dict, confirmed_by: str) -> None:
    current = [s for s in load() if s["path"] != entry["path"]]
    current.append({**entry, "confirmed_by": confirmed_by, "confirmed_at": time.strftime("%Y-%m-%dT%H:%M:%S")})
    _write(sources_file(), current)


def load_pending() -> list[dict]:
    return _read(pending_file())


def propose(entry: dict, proposed_by: str, goal: str = "") -> dict | None:
    """Save one Scout proposal for a person to confirm later. Files already watched are skipped."""
    if any(s["path"] == entry["path"] for s in load()):
        return None
    item = {**entry, "id": proposal_id(entry["path"]), "proposed_by": proposed_by, "goal": goal,
            "proposed_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    _write(pending_file(), [p for p in load_pending() if p["path"] != entry["path"]] + [item])
    return item


def find_pending(key: str) -> dict | None:
    """A pending proposal by its id or its path."""
    return next((p for p in load_pending() if key in (p.get("id"), p["path"])), None)


def drop_pending(path: str) -> None:
    rest = [p for p in load_pending() if p["path"] != path]
    if rest:
        _write(pending_file(), rest)
    else:
        pending_file().unlink(missing_ok=True)


def approve(key: str, confirmed_by: str, layer: str | None = None) -> dict:
    p = find_pending(key)
    if p is None:
        raise KeyError(f"{key} is not a pending Scout proposal")
    entry = {k: p[k] for k in ("path", "layer", "format", "why") if k in p}
    if layer:
        entry["layer"] = layer
    add({**entry, "found_by": "Scout"}, confirmed_by)
    drop_pending(p["path"])
    return entry


def reject(key: str) -> dict:
    p = find_pending(key)
    if p is None:
        raise KeyError(f"{key} is not a pending Scout proposal")
    drop_pending(p["path"])
    return p
