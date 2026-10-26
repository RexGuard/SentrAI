"""Jobs the panel asks one machine's agent to run: a threat scan or a backup, on that machine.

The panel never reaches into a machine. An operator queues a job here (POST /fleet/jobs); the
machine's agent picks it up on its next call out (GET /fleet/jobs/next), runs it locally and sends
back a short result (POST /fleet/jobs/result). So no port is opened on the machine, and the panel
cannot choose what the agent reads: the agent scans and backs up only the folders set on that
machine itself (CACTAI_THREAT_PATHS / CACTAI_BACKUP_PATHS there). Backups stay on the machine;
only their id, size and checksum come back.

Jobs are kept in jobs.json next to the database, newest MAX_KEEP per machine.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

KINDS = {"threat_scan": "Threat scan", "backup": "Backup"}
QUEUED_TTL_S = 24 * 3600.0      # a job nobody picked up in a day is dropped (machine off or gone)
RUNNING_TTL_S = 3 * 3600.0      # a job that never reports back in 3 h is marked failed
MAX_KEEP = 20                   # finished jobs kept per machine
MAX_FINDINGS = 300


class JobError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


class Jobs:
    def __init__(self, path: Path, clock=time.time) -> None:
        self.path = path
        self.clock = clock
        self.lock = threading.Lock()
        self._jobs: dict[str, dict[str, Any]] = {}
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self._jobs = {j["id"]: j for j in loaded.get("jobs", []) if isinstance(j, dict) and j.get("id")}
        except (OSError, ValueError):
            pass

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"jobs": list(self._jobs.values())}, f, indent=1)
        os.replace(tmp, self.path)

    def _expire(self) -> list[dict[str, Any]]:
        """Time out jobs that were never picked up or never reported back. Returns the ones changed."""
        now = self.clock()
        changed = []
        for j in self._jobs.values():
            if j["status"] == "queued" and now - j["created_ts"] > QUEUED_TTL_S:
                j.update(status="expired", finished_at=_iso(now),
                         error="the machine did not pick this up within a day (agent off or offline?)")
                changed.append(j)
            elif j["status"] == "running" and now - (j.get("started_ts") or now) > RUNNING_TTL_S:
                j.update(status="failed", finished_at=_iso(now),
                         error=f"the machine started this but did not report back in {RUNNING_TTL_S / 3600:g} h")
                changed.append(j)
        return changed

    def _prune(self, host: str) -> None:
        done = sorted((j for j in self._jobs.values() if j["host"] == host and j["status"] not in ("queued", "running")),
                      key=lambda j: j["created_ts"], reverse=True)
        for j in done[MAX_KEEP:]:
            del self._jobs[j["id"]]

    # -------------------------------------------------------------- operator
    def queue(self, host: str, kind: str, by: str) -> dict[str, Any]:
        if kind not in KINDS:
            raise JobError(f"unknown job {kind!r}; use one of: {', '.join(KINDS)}")
        now = self.clock()
        with self.lock:
            self._expire()
            same = next((j for j in self._jobs.values() if j["host"] == host and j["kind"] == kind
                         and j["status"] in ("queued", "running")), None)
            if same is not None:
                raise JobError(f"a {KINDS[kind].lower()} is already {same['status']} on {host} ({same['id']})", 409)
            job = {"id": f"j-{secrets.token_hex(4)}", "host": host, "kind": kind, "status": "queued",
                   "requested_by": by, "created_at": _iso(now), "created_ts": now,
                   "started_at": None, "started_ts": None, "finished_at": None, "result": None, "error": None}
            self._jobs[job["id"]] = job
            self._save()
            return dict(job)

    def cancel(self, job_id: str, by: str) -> dict[str, Any]:
        with self.lock:
            j = self._jobs.get(job_id)
            if j is None:
                raise JobError(f"no job {job_id}", 404)
            if j["status"] != "queued":
                raise JobError(f"job {job_id} is {j['status']}; only a job still waiting can be cancelled", 409)
            j.update(status="cancelled", finished_at=_iso(self.clock()), error=f"cancelled by {by}")
            self._save()
            return dict(j)

    def list(self, host: str | None = None) -> list[dict[str, Any]]:
        with self.lock:
            if self._expire():
                self._save()
            out = [dict(j) for j in self._jobs.values() if host is None or j["host"] == host]
        return sorted(out, key=lambda j: j["created_ts"], reverse=True)

    def drop_host(self, host: str, by: str) -> int:
        """A revoked machine's waiting jobs are cancelled (its agent can no longer pick them up)."""
        n = 0
        with self.lock:
            for j in self._jobs.values():
                if j["host"] == host and j["status"] in ("queued", "running"):
                    j.update(status="cancelled", finished_at=_iso(self.clock()), error=f"machine revoked by {by}")
                    n += 1
            if n:
                self._save()
        return n

    # ----------------------------------------------------------------- agent
    def next_for(self, host: str) -> dict[str, Any] | None:
        """The oldest waiting job for this machine, now marked running; None when there is nothing to do."""
        now = self.clock()
        with self.lock:
            changed = self._expire()
            waiting = sorted((j for j in self._jobs.values() if j["host"] == host and j["status"] == "queued"),
                             key=lambda j: j["created_ts"])
            if not waiting:
                if changed:
                    self._save()
                return None
            j = waiting[0]
            j.update(status="running", started_at=_iso(now), started_ts=now)
            self._save()
            return {"id": j["id"], "kind": j["kind"]}

    def finish(self, host: str, job_id: str, ok: bool, result: dict[str, Any] | None, error: str | None) -> dict[str, Any]:
        with self.lock:
            j = self._jobs.get(job_id)
            if j is None or j["host"] != host:
                raise JobError(f"no job {job_id} for this machine", 404)
            if j["status"] != "running":
                raise JobError(f"job {job_id} is {j['status']}, not running", 409)
            j.update(status="done" if ok else "failed", finished_at=_iso(self.clock()),
                     result=result if ok else None, error=None if ok else (error or "failed")[:400])
            self._prune(host)
            self._save()
            return dict(j)


# ---------------------------------------------------------------- results
def clean_scan(result: dict[str, Any]) -> dict[str, Any]:
    """Keep only what the panel shows from a machine's threat scan (the agent already hides homes
    and masks secrets; this drops anything else it might send)."""
    keep = ("path", "entry", "line", "kind", "severity", "label", "key", "sha256", "snippet", "size")
    findings = [{k: f.get(k) for k in keep if f.get(k) is not None}
                for f in (result.get("findings") or [])[:MAX_FINDINGS] if isinstance(f, dict)]
    return {"roots": [str(r) for r in result.get("roots") or []][:50],
            "missing": [str(r) for r in result.get("missing") or []][:50],
            "files_checked": int(result.get("files_checked") or 0),
            "files_not_checked": int(result.get("files_not_checked") or 0),
            "counts": {str(k): int(v) for k, v in (result.get("counts") or {}).items()},
            "took_s": float(result.get("took_s") or 0), "findings": findings,
            "note": str(result.get("note") or "")[:300] or None}


def clean_backup(result: dict[str, Any]) -> dict[str, Any]:
    keep = ("id", "created", "folders", "missing", "files", "bytes", "archive_bytes", "sha256", "pruned", "note")
    return {k: result.get(k) for k in keep if result.get(k) is not None}


def summary(job: dict[str, Any]) -> str:
    """One line for the Machines page and the audit log."""
    if job["status"] in ("queued", "running"):
        return "waiting for the machine to pick it up" if job["status"] == "queued" else "running on the machine"
    if job["status"] != "done":
        return job.get("error") or job["status"]
    r = job.get("result") or {}
    if job["kind"] == "threat_scan":
        if r.get("note") and not r.get("files_checked"):
            return r["note"]
        c = r.get("counts") or {}
        bad = c.get("critical", 0) + c.get("high", 0)
        return (f"{r.get('files_checked', 0)} files checked, {len(r.get('findings') or [])} findings"
                + (f" ({bad} critical or high)" if bad else ""))
    return f"{r.get('id', 'backup')}: {r.get('files', 0)} files, {(r.get('bytes') or 0) / 1048576:.1f} MB"
