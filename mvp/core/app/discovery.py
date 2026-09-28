"""System discovery: run the process scanner and turn approved suggestions into collector sources.

The scanner (``procscan``) only suggests. A log file is watched only after an operator approves
it, by its id from the latest scan, so neither the model nor a crafted request can point the
collector at an arbitrary file. Approved files go to the same list Scout writes
(``lab/scout/sources.json``, or ``CACTAI_SCOUT_SOURCES``); the collector re-reads it while running.
Every scan and approval is written to the audit trail.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from . import procscan
from .config import CORE_DIR

MVP_DIR = CORE_DIR.parent
LAB_LOG_NAMES = ("access.jsonl", "auth.jsonl", "db.jsonl", "os.jsonl")
LAYERS = ("web", "db", "os", "network", "cloud")


def sources_file() -> Path:
    return Path(os.environ.get("CACTAI_SCOUT_SOURCES", str(MVP_DIR / "lab" / "scout" / "sources.json")))


def load_sources() -> list[dict[str, Any]]:
    try:
        data = json.loads(sources_file().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [s for s in data if isinstance(s, dict) and s.get("path") and s.get("layer")]


def lab_logs_dir() -> Path:
    return Path(os.environ.get("CACTAI_LAB_LOGS") or MVP_DIR / "lab" / "logs")


class Discovery:
    def __init__(self, core: Any) -> None:
        self.core = core
        self.lock = threading.Lock()
        self.last: dict[str, Any] | None = None
        self._files: dict[str, dict[str, Any]] = {}  # file id -> file + its suggestion, from the last scan

    def watched(self) -> set[str]:
        lab = lab_logs_dir()
        names = [os.environ.get(f"CACTAI_LOG_{k}", n) for k, n in zip(("ACCESS", "AUTH", "DB", "OS"), LAB_LOG_NAMES)]
        return {str(lab / n) for n in names} | {s["path"] for s in load_sources()}

    def scan(self, by: str = "operator") -> dict[str, Any]:
        profile = getattr(self.core, "profile", None) or {}
        result = procscan.scan(profile, self.watched())
        files: dict[str, dict[str, Any]] = {}
        for n, s in enumerate(result["suggestions"], 1):
            s["id"] = f"s{n}"
            for m, f in enumerate(s["files"], 1):
                f["id"] = f"s{n}f{m}"
                files[f["id"]] = {**f, "layer": s["layer"], "format": s["format"], "program": s["program"]}
        result["scanned_at"] = self.core.clock.now_iso()
        with self.lock:
            self.last, self._files = result, files
        self.core.scribe.record(self.core.name, "system_scan", {
            "by": by, "platform": result["platform"], "processes": result.get("scanned", 0),
            "recognised": result.get("recognised", 0), "skipped_protected": result.get("skipped_protected", 0),
            "suggestions": len(result["suggestions"]), "error": result.get("error"),
            "summary": f"{by} scanned {result.get('scanned', 0)} processes, "
                       f"{len(result['suggestions'])} log locations found"})
        return self.public(result)

    def latest(self) -> dict[str, Any] | None:
        with self.lock:
            return self.public(self.last) if self.last else None

    @staticmethod
    def public(result: dict[str, Any], for_model: bool = False) -> dict[str, Any]:
        """Drop real paths (they may contain home folders); the model gets a shorter view."""
        out = {k: v for k, v in result.items() if k not in ("suggestions", "processes")}
        out["processes"] = result.get("processes", [])
        out["suggestions"] = []
        for s in result.get("suggestions", []):
            files = [{k: f[k] for k in ("id", "name", "size", "modified", "watched")} for f in s["files"]]
            s2 = {k: v for k, v in s.items() if k not in ("real_path", "files", "pids")}
            out["suggestions"].append({**s2, "files": files})
        if for_model:
            out["processes"] = [{k: p[k] for k in ("pid", "program", "layer", "account", "service") if p.get(k)}
                                for p in out["processes"][:60]]
        return out

    def file(self, file_id: str) -> dict[str, Any]:
        with self.lock:
            f = self._files.get(file_id)
        if not f:
            raise KeyError(f"{file_id} is not in the latest scan; scan again")
        return f

    def approve(self, file_id: str, operator: str, layer: str | None = None) -> dict[str, Any]:
        f = self.file(file_id)
        layer = layer or f["layer"]
        if layer not in LAYERS:
            raise ValueError(f"layer must be one of {', '.join(LAYERS)}")
        path = f["path"]
        if not Path(path).is_file():
            raise ValueError("that file no longer exists; scan again")
        entry = {"path": path, "layer": layer, "format": f["format"],
                 "why": f"found by process scan ({f['program']})", "found_by": "process scan",
                 "confirmed_by": operator, "confirmed_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
        current = [s for s in load_sources() if s["path"] != path]
        target = sources_file()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps([*current, entry], indent=2), encoding="utf-8")
        with self.lock:
            self._files[file_id]["watched"] = True
            for s in (self.last or {}).get("suggestions", []):
                for x in s["files"]:
                    x["watched"] = x["watched"] or x.get("id") == file_id
                s["already_watched"] = all(x["watched"] for x in s["files"])
        self.core.scribe.record(self.core.name, "log_source_added", {
            "operator": operator, "file": f["name"], "layer": layer, "program": f["program"],
            "summary": f"{operator} added {f['name']} ({f['program']}) to the collector"})
        return {"ok": True, "file": f["name"], "layer": layer, "watching": len(current) + 1,
                "note": "The collector picks this up within a few seconds."}

    def sources(self) -> list[dict[str, Any]]:
        homes = procscan._homes()
        return [{**s, "path": procscan.hide_home(s["path"], homes)} for s in load_sources()]
