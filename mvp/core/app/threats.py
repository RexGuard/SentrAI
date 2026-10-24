"""Threat watch: runs the threat scan, raises each new finding once, and quarantines files an operator approves.

The scan itself (``threatscan``) only reads. This part decides what to do with what it found:

* A ``critical`` or ``high`` finding becomes an ordinary event (source ``threat_scan``) that the rules
  classify as ``malware``, so it opens an incident, is audited and notified like any other.
* Each finding is raised once. A fingerprint (file contents + signature, or program + signature) is
  remembered in ``data/threat_seen.json`` (``CACTAI_THREAT_STATE``), so an hourly scan does not ping
  the operator about the same file every hour. A file that changes is a new finding.
* Nothing is deleted. Quarantine moves one file, chosen by its id from the latest scan, into
  ``data/quarantine`` (``CACTAI_QUARANTINE``) with a note of where it came from, and only if its
  contents still match what was scanned. Restore puts it back. Both are written to the audit trail.

Folders come from ``threat_scan.paths`` in the system profile (or a scan request);
``threat_scan.every_minutes`` repeats the scan in the background.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import threatscan
from .config import CORE_DIR
from . import procscan
from .procscan import hide_home

RAISE = ("critical", "high")
SEEN_LIMIT = 5000


def state_file() -> Path:
    return Path(os.environ.get("CACTAI_THREAT_STATE", str(CORE_DIR / "data" / "threat_seen.json")))


def quarantine_dir() -> Path:
    return Path(os.environ.get("CACTAI_QUARANTINE", str(CORE_DIR / "data" / "quarantine")))


def threat_event(text: str, host: str | None = None) -> dict[str, Any]:
    return {
        "event_id": f"evt-threat-{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": host or socket.gethostname() or "sentrai-core",
        "layer": "os",
        "source": "threat_scan",
        "src_ip": None,
        "user": None,
        "raw": f"threat-scan {text}",
        "asset_criticality": 1.0,
    }


def _fingerprint(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:24]


class ThreatWatch:
    def __init__(self, core: Any) -> None:
        self.core = core
        self.lock = threading.Lock()
        self.scan_lock = threading.Lock()  # one file scan at a time
        self.last: dict[str, Any] | None = None
        self._files: dict[str, dict[str, Any]] = {}  # finding id -> finding (with real path)

    # ------------------------------------------------------------ settings
    def config(self) -> dict[str, Any]:
        """``threat_scan`` from the system profile; CACTAI_THREAT_PATHS (separated by the OS path
        separator) supplies the folders when the profile names none."""
        profile = getattr(self.core, "profile", None) or {}
        cfg = dict(profile.get("threat_scan") or {})
        if not cfg.get("paths") and os.environ.get("CACTAI_THREAT_PATHS"):
            cfg["paths"] = [p for p in os.environ["CACTAI_THREAT_PATHS"].split(os.pathsep) if p.strip()]
        return cfg

    def every_s(self) -> float:
        cfg = self.config()
        if cfg.get("enabled") is False or not cfg.get("paths"):
            return 0.0
        return max(0.0, float(cfg.get("every_minutes", 60))) * 60

    # ---------------------------------------------------------- seen state
    def _seen(self) -> dict[str, str]:
        try:
            data = json.loads(state_file().read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_seen(self, seen: dict[str, str]) -> None:
        f = state_file()
        f.parent.mkdir(parents=True, exist_ok=True)
        if len(seen) > SEEN_LIMIT:  # oldest first out
            seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-SEEN_LIMIT:])
        tmp = f.with_name(f".{f.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(seen, indent=1), encoding="utf-8")
        os.replace(tmp, f)

    def _raise_new(self, items: list[tuple[str, str]]) -> int:
        """items: (fingerprint, event text). Ingests the ones not raised before; returns how many."""
        if not items:
            return 0
        with self.lock:
            seen = self._seen()
            fresh = [(fp, text) for fp, text in items if fp not in seen]
            now = time.strftime("%Y-%m-%dT%H:%M:%S")
            for fp, _ in fresh:
                seen[fp] = now
            if fresh:
                self._save_seen(seen)
        if fresh:
            self.core.ingest([threat_event(text) for _, text in fresh])
        return len(fresh)

    # ---------------------------------------------------------------- scans
    def scan(self, by: str = "operator", paths: list[str] | None = None) -> dict[str, Any]:
        cfg = self.config()
        if cfg.get("enabled") is False:
            return {"enabled": False, "findings": [], "note": "Threat scanning is turned off in the system profile."}
        roots = [p for p in (paths or cfg.get("paths") or []) if isinstance(p, str) and p.strip()]
        if not roots:
            return {"enabled": True, "findings": [], "roots": [],
                    "note": "No folders to scan. Add threat_scan.paths to the system profile, or pass paths."}
        with self.scan_lock:
            result = threatscan.scan(roots, cfg)
        files: dict[str, dict[str, Any]] = {}
        quarantined = {q["sha256"] for q in self.quarantined()}
        raise_items: list[tuple[str, str]] = []
        for n, f in enumerate(result["findings"], 1):
            f["id"] = f"t{n}"
            f["fingerprint"] = _fingerprint(f["sha256"], f["key"], f.get("entry", ""))
            files[f["id"]] = f
            if f["severity"] in RAISE and f["sha256"] not in quarantined:
                where = f["path"] + (f" ({f['entry']})" if f.get("entry") else "")
                line = f" line {f['line']}" if f.get("line") else ""
                raise_items.append((f["fingerprint"], f"{f['severity']} {f['kind']}: {f['label']} in {where}{line}"))
        result["scanned_at"] = self.core.clock.now_iso()
        result["new_alerts"] = self._raise_new(raise_items)
        with self.lock:
            self.last, self._files = result, files
        self.core.scribe.record(self.core.name, "threat_scan", {
            "by": by, "folders": result["roots"], "files_checked": result["files_checked"],
            "counts": result["counts"], "new_alerts": result["new_alerts"],
            "summary": f"{by} checked {result['files_checked']} files for threats: "
                       f"{len(result['findings'])} findings, {result['new_alerts']} new"})
        return self.public(result)

    def report_processes(self, threats: list[dict[str, Any]]) -> int:
        """Hostile-looking programs from the process scan; raised once per program and sign."""
        items = []
        for t in threats:
            if t["severity"] not in RAISE:
                continue
            fp = _fingerprint("proc", t["key"], t.get("exe") or t["name"])
            items.append((fp, f"{t['severity']} process: {t['label']} ({t['name']}, pid {t['pid']}, "
                              f"account {t.get('account') or 'unknown'})"))
        return self._raise_new(items)

    def latest(self) -> dict[str, Any] | None:
        with self.lock:
            return self.public(self.last) if self.last else None

    @staticmethod
    def public(result: dict[str, Any]) -> dict[str, Any]:
        out = {k: v for k, v in result.items() if k != "findings"}
        out["findings"] = [{k: v for k, v in f.items() if k not in ("real_path", "fingerprint")}
                           for f in result.get("findings", [])]
        return out

    # ----------------------------------------------------------- quarantine
    def quarantine(self, finding_id: str, operator: str, reason: str = "") -> dict[str, Any]:
        with self.lock:
            f = self._files.get(finding_id)
        if not f:
            raise KeyError(f"{finding_id} is not in the latest threat scan; scan again")
        src = Path(f["real_path"])
        try:
            data = src.read_bytes()
        except OSError:
            raise ValueError("that file is gone or unreadable; scan again")
        if hashlib.sha256(data).hexdigest() != f["sha256"]:
            raise ValueError("that file changed since the scan; scan again before quarantining it")
        qdir = quarantine_dir()
        qdir.mkdir(parents=True, exist_ok=True)
        qid = f"q-{time.strftime('%Y%m%d%H%M%S')}-{f['sha256'][:8]}"
        meta = {"id": qid, "original": str(src), "name": src.name, "sha256": f["sha256"], "size": len(data),
                "finding": {k: f.get(k) for k in ("key", "kind", "severity", "label", "line", "entry")},
                "operator": operator, "reason": reason or None, "at": time.strftime("%Y-%m-%dT%H:%M:%S")}
        try:
            mode = src.stat().st_mode & 0o7777
        except OSError:
            mode = 0o644
        meta["mode"] = mode
        (qdir / f"{qid}.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        try:
            shutil.move(str(src), str(qdir / f"{qid}.bin"))
        except OSError as e:
            (qdir / f"{qid}.json").unlink(missing_ok=True)
            raise ValueError(f"could not move the file ({type(e).__name__}); SentrAI may lack write access there")
        os.chmod(qdir / f"{qid}.bin", 0o400)  # cannot be run from quarantine
        shown = hide_home(str(src), procscan._homes())
        self.core.scribe.record(self.core.name, "file_quarantined", {
            "operator": operator, "file": shown, "sha256": f["sha256"], "finding": meta["finding"],
            "quarantine_id": qid, "reason": reason or None,
            "summary": f"{operator} quarantined {src.name} ({f['label']})"})
        return {"ok": True, "quarantine_id": qid, "file": shown,
                "note": "Moved out of reach, not deleted. Restore puts it back."}

    def quarantined(self) -> list[dict[str, Any]]:
        qdir = quarantine_dir()
        if not qdir.is_dir():
            return []
        homes = procscan._homes()
        out = []
        for m in sorted(qdir.glob("q-*.json")):
            try:
                meta = json.loads(m.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if (qdir / f"{meta.get('id')}.bin").exists():
                out.append({**meta, "original": hide_home(str(meta.get("original", "")), homes)})
        return out

    def restore(self, qid: str, operator: str) -> dict[str, Any]:
        qdir = quarantine_dir()
        if not qid.startswith("q-") or "/" in qid or "\\" in qid:
            raise KeyError(f"{qid} is not in quarantine")
        meta_f, bin_f = qdir / f"{qid}.json", qdir / f"{qid}.bin"
        if not (meta_f.is_file() and bin_f.is_file()):
            raise KeyError(f"{qid} is not in quarantine")
        meta = json.loads(meta_f.read_text(encoding="utf-8"))
        dst = Path(meta["original"])
        if dst.exists():
            raise ValueError("a file already exists at the original location; move it first")
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(bin_f), str(dst))
        os.chmod(dst, int(meta.get("mode", 0o644)))
        meta_f.unlink()
        shown = hide_home(str(dst), procscan._homes())
        self.core.scribe.record(self.core.name, "file_restored", {
            "operator": operator, "file": shown, "sha256": meta.get("sha256"), "quarantine_id": qid,
            "summary": f"{operator} restored {dst.name} from quarantine"})
        return {"ok": True, "file": shown}
