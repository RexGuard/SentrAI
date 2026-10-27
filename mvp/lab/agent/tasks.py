"""Jobs the panel asks this machine to run (the panel's jobs.py): a threat scan or a backup.

The agent asks the panel for work on its own outgoing calls, runs it here, and sends back a short
result. What gets read is decided on this machine, never by the panel:

  SENTRAI_THREAT_PATHS   folders to scan for web shells, miners, reverse shells (OS path separator)
  SENTRAI_BACKUP_PATHS   folders to back up; SENTRAI_BACKUP_KEEP (default 7), SENTRAI_BACKUP_COPY_TO,
                        SENTRAI_BACKUP_DIR (default: "backups" next to the agent file)

Backups stay on this machine (restoring one is done here, by a person). The panel only gets the
backup's id, size and checksum, and the scan's findings with home folders hidden and secrets masked.
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

import requests

from app import procscan, threatscan  # noqa: E402  (the core's scanner; agent.py puts core/ on the path)
from app.backups import BackupWatch  # noqa: E402

JOBS_EVERY_S = 15.0


def _paths(name: str) -> list[str]:
    return [p for p in os.environ.get(name, "").split(os.pathsep) if p.strip()]


def run_threat_scan() -> dict[str, Any]:
    roots = _paths("SENTRAI_THREAT_PATHS")
    if not roots:
        return {"roots": [], "files_checked": 0, "findings": [], "counts": {},
                "note": "No folders to scan on this machine: set SENTRAI_THREAT_PATHS for its agent."}
    result = threatscan.scan(roots)
    for f in result["findings"]:
        f.pop("real_path", None)  # the panel sees the shown path only
    return result


class _Clock:
    @staticmethod
    def iso(ts: float) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts))

    def now(self) -> float:
        return time.time()

    def now_iso(self) -> str:
        return self.iso(time.time())


class _Scribe:
    """The agent has no audit log of its own: the panel records the job and its result."""
    def record(self, *_: Any, **__: Any) -> None:
        pass


class _Settings:
    def __init__(self, data_dir: Path) -> None:
        self.db_path = data_dir / "agent.db"   # only its folder is used: backups/ goes next to it
        self.on_duty = "on-duty"


class LocalCore:
    """Just enough of the core for BackupWatch to back up this machine's folders."""
    name = "agent"

    def __init__(self, data_dir: Path) -> None:
        self.profile: dict[str, Any] = {}
        self.settings = _Settings(data_dir)
        self.clock = _Clock()
        self.scribe = _Scribe()
        self.lock = threading.Lock()

    def _notify(self, *_: Any, **__: Any) -> None:
        pass  # a failed backup comes back to the panel as a failed job, and the panel alerts


def run_backup(data_dir: Path) -> dict[str, Any]:
    watch = BackupWatch(LocalCore(data_dir))
    if not watch._roots(watch.config()):
        return {"ok": False, "error": "No folders to back up on this machine: set SENTRAI_BACKUP_PATHS for its agent."}
    out = watch.make("panel", "manual", include_sentrai=False)
    if out.get("ok"):
        out["folders"] = [procscan.hide_home(f, procscan._homes()) for f in out.get("folders") or []]
    return out


def run_job(job: dict[str, Any], data_dir: Path) -> tuple[bool, dict[str, Any] | None, str | None]:
    """Run one job here. Returns (ok, result, error); never raises."""
    try:
        if job["kind"] == "threat_scan":
            return True, run_threat_scan(), None
        if job["kind"] == "backup":
            out = run_backup(data_dir)
            return (True, out, None) if out.get("ok") else (False, None, out.get("error") or out.get("note"))
        return False, None, f"this agent does not know the job {job['kind']!r}; update it"
    except Exception as exc:  # report it to the panel rather than kill the agent
        return False, None, f"{type(exc).__name__}: {exc}"[:400]


def next_job(data: dict[str, Any], session: requests.Session, verify: Any) -> dict[str, Any] | None:
    try:
        r = session.get(f"{data['panel']}/fleet/jobs/next", headers={"Authorization": f"Bearer {data['key']}"},
                        timeout=5, verify=verify)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None  # an older panel without jobs answers 404/403: nothing to do
    job = r.json().get("job")
    return job if isinstance(job, dict) and job.get("id") else None


def send_result(data: dict[str, Any], session: requests.Session, verify: Any, job_id: str, ok: bool,
                result: dict[str, Any] | None, error: str | None, tries: int = 3, wait_s: float = 5.0) -> bool:
    body = {"id": job_id, "ok": ok, "result": result, "error": error}
    for n in range(tries):
        try:
            r = session.post(f"{data['panel']}/fleet/jobs/result", json=body, timeout=15, verify=verify,
                             headers={"Authorization": f"Bearer {data['key']}"})
            if r.status_code == 200:
                return True
            if 400 <= r.status_code < 500:
                return False  # the panel refused it (job cancelled or timed out): do not retry
        except requests.RequestException:
            pass
        if n < tries - 1:
            time.sleep(wait_s)
    return False


def job_loop(data: dict[str, Any], verify: Any, data_dir: Path, stop: threading.Event,
             every_s: float = JOBS_EVERY_S, log: Callable[[str], None] = lambda s: print(f"[agent] {s}", flush=True),
             session: requests.Session | None = None) -> None:
    """Runs beside the block list loop, so a long scan or backup never holds up blocking. ``session`` is
    the agent's panel session (pinned to the panel's certificate when joined with --pin)."""
    session = session or requests.Session()
    while not stop.is_set():
        job = next_job(data, session, verify)
        if job:
            log(f"panel asked for a {job['kind'].replace('_', ' ')} ({job['id']})")
            ok, result, error = run_job(job, data_dir)
            sent = send_result(data, session, verify, job["id"], ok, result, error)
            log(f"{job['id']} {'done' if ok else 'failed: ' + str(error)}{'' if sent else ' (could not tell the panel)'}")
            continue  # another job may be waiting
        stop.wait(every_s)
