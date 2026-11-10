"""Jobs the panel asks this machine to run (the panel's jobs.py): a threat scan, a backup, a
dependency scan, and the package updates a person pressed on the panel (and their undo).

The agent asks the panel for work on its own outgoing calls, runs it here, and sends back a short
result. What gets read is decided on this machine, never by the panel:

  SENTRAI_THREAT_PATHS   folders to scan for web shells, miners, reverse shells (OS path separator);
                        the file watch (watch.py) also keeps an eye on them between scans
  SENTRAI_CLAMAV         auto | off | path: also run ClamAV on them when it is installed (clamav.py)
  SENTRAI_BACKUP_PATHS   folders to back up; SENTRAI_BACKUP_KEEP (default 7), SENTRAI_BACKUP_COPY_TO,
                        SENTRAI_BACKUP_DIR (default: "backups" next to the agent file)
  SENTRAI_DEP_PATHS      folders with virtualenvs, npm projects or requirements files to check for
                        vulnerable packages (the agent's own environment and dpkg are always checked;
                        SENTRAI_DEP_OS=off skips dpkg)

A package update names only a finding id from this machine's own last dependency scan, kept in
deps/ next to the agent file; the package, place and version come from that file, never from the
panel. Only "safe" findings (a virtualenv package or an npm project's direct dependency, fixed in
the same major version) are updated, and each one can be undone.

Backups are made and restored on this machine, by a person. So that losing the machine does not lose
them, the newest one is also sealed with this machine's own key (backup.key next to the agent file)
and sent to the panel, which has other machines keep a copy (sync_copies, the panel's
backup_copies.py). In turn this machine keeps sealed copies of other machines' backups in
backups/copies/, which it cannot open. The panel keeps this machine's key so it can unlock the copy
when this machine is gone. SENTRAI_BACKUP_COPIES=off turns all of that off for this machine.
The scan's findings reach the panel with home folders hidden and secrets masked.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import threading
import time
from pathlib import Path
from typing import Any, Callable

import requests

from app import clamav, depscan, procscan, signatures, threatscan  # noqa: E402  (the core's scanner; agent.py puts core/ on the path)
from app import sealed  # noqa: E402
from app.backups import BackupWatch  # noqa: E402
import sentrai_paths  # noqa: E402  (mvp/, put on the path by app/__init__.py)
from agent import quarantine  # noqa: E402

JOBS_EVERY_S = 15.0
COPIES_EVERY_S = 600.0     # how often backup copies are sent and fetched
COPY_HOLD = 2              # copies of each other machine kept here (newer ones push older ones out)


def _paths(name: str) -> list[str]:
    return [p for p in os.environ.get(name, "").split(os.pathsep) if p.strip()]


def run_threat_scan(data_dir: Path | None = None) -> dict[str, Any]:
    """The full scan: SentrAI's signatures and checks, the panel's shared fingerprint list (the copy
    the file watch keeps here) and ClamAV when it is installed. Each finding gets an id a person can
    name to lock the file away (quarantine.py); the real path stays on this machine."""
    roots = _paths("SENTRAI_THREAT_PATHS")
    if not roots:
        return {"roots": [], "files_checked": 0, "findings": [], "counts": {},
                "note": "No folders to scan on this machine: set SENTRAI_THREAT_PATHS for its agent."}
    cfg: dict[str, Any] = {}
    if data_dir is not None:
        copy = signatures.load_copy(quarantine.threats_dir(data_dir) / "signatures.json")
        cfg = {"known_bad_sha256": copy.get("sha256") or [], "known_bad_md5": copy.get("md5") or []}
    result = threatscan.scan(roots, cfg)
    clam = clamav.scan(roots, skip=threatscan._own_dirs())
    if clam.get("engine"):
        homes = procscan._homes()
        have = {(f.get("real_path"), f.get("sha256")) for f in result["findings"]}
        extra = [{**f, "path": procscan.hide_home(f["real_path"], homes)} for f in clam["findings"]
                 if (f["real_path"], f["sha256"]) not in have]
        result["findings"] = extra + result["findings"]
        result["counts"]["critical"] = result["counts"].get("critical", 0) + len(extra)
        result["engines"] = ["sentrai", clam["engine"]]
        if clam.get("error"):
            result["note"] = clam["error"]
    if data_dir is not None:
        result["findings"] = quarantine.remember(data_dir, result["findings"])
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


class AgentBackups(BackupWatch):
    """Backups in agent/backups next to the agent file (SENTRAI_BACKUP_DIR moves them). An older
    version kept them next to the settings file; they move here the first time."""

    def _dir(self) -> Path:
        return sentrai_paths.path("agent.backups", self._data_dir())


def run_backup(data_dir: Path) -> dict[str, Any]:
    watch = AgentBackups(LocalCore(data_dir))
    if not watch._roots(watch.config()):
        return {"ok": False, "error": "No folders to back up on this machine: set SENTRAI_BACKUP_PATHS for its agent."}
    out = watch.make("panel", "manual", include_sentrai=False)
    if out.get("ok"):
        out["folders"] = [procscan.hide_home(f, procscan._homes()) for f in out.get("folders") or []]
    return out


# ------------------------------------------------------------ backup copies on other machines
def copies_on() -> bool:
    return os.environ.get("SENTRAI_BACKUP_COPIES", "on").strip().lower() not in ("0", "off", "false", "no")


def backup_key(data_dir: Path) -> bytes:
    """This machine's own backup key, made the first time (mode 0600, next to the agent file)."""
    f = data_dir / "backup.key"
    try:
        key = base64.b64decode(f.read_text(encoding="ascii").strip(), validate=True)
        if len(key) == 32:
            return key
    except (OSError, ValueError):
        pass
    key = sealed.new_key()
    data_dir.mkdir(parents=True, exist_ok=True)
    tmp = f.with_name(".backup.key.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(base64.b64encode(key).decode())
    os.replace(tmp, f)
    return key


class CopySync:
    """Sends this machine's newest backup to the panel, sealed, and keeps the copies of other machines'
    backups the panel picked it for. Never raises: a failed step is tried again next round."""

    def __init__(self, data: dict[str, Any], session: requests.Session, verify: Any, data_dir: Path,
                 log: Callable[[str], None]) -> None:
        self.data, self.session, self.verify, self.data_dir, self.log = data, session, verify, data_dir, log
        self.backups = AgentBackups(LocalCore(data_dir))
        self.held_dir = self.backups._dir() / "copies"
        self.state_file = self.held_dir / "state.json"

    def _h(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.data['key']}"}

    def _url(self, path: str) -> str:
        return f"{self.data['panel']}{path}"

    def run(self) -> dict[str, Any]:
        out: dict[str, Any] = {"sent": None, "fetched": [], "dropped": [], "held": 0}
        state = _load(self.state_file, {})
        key = backup_key(self.data_dir)
        kid = sealed.key_id(key)
        try:
            if state.get("key_sent") != kid:
                r = self.session.post(self._url("/fleet/backup-key"), json={"key": base64.b64encode(key).decode()},
                                      headers=self._h(), timeout=10, verify=self.verify)
                if r.status_code != 200:
                    return {**out, "error": f"panel did not take the backup key ({r.status_code})"}
                state["key_sent"] = kid
                _store(self.state_file, state)
            out["sent"] = self._send_newest(key, state)
            r = self.session.get(self._url("/fleet/backup-copies/wanted"), headers=self._h(), timeout=10,
                                 verify=self.verify)
            if r.status_code != 200:
                return {**out, "error": f"panel answered {r.status_code} for the copies to keep"}
            for c in r.json().get("copies") or []:
                got = self._fetch(c)
                if got:
                    out["fetched"].append(f"{c['owner']}/{c['id']}")
            out["dropped"] = self._drop_old()
            held = self.held()
            out["held"] = len(held)
            free = shutil.disk_usage(self.held_dir).free / 1048576 if self.held_dir.is_dir() else None
            self.session.post(self._url("/fleet/backup-copies/held"), json={"held": held, "free_mb": free},
                              headers=self._h(), timeout=10, verify=self.verify)
        except requests.RequestException as exc:
            out["error"] = f"panel not reachable ({exc.__class__.__name__})"
        except (OSError, ValueError, KeyError, sealed.SealError) as exc:
            out["error"] = f"{type(exc).__name__}: {exc}"[:200]
        return out

    def _send_newest(self, key: bytes, state: dict[str, Any]) -> str | None:
        """Seal this machine's newest backup and send it, once."""
        metas = [m for m in self.backups._metas() if m.get("reason") != "before_restore"]
        if not metas or metas[0]["id"] == state.get("sent"):
            return None
        meta = metas[0]
        archive = self.backups._dir() / f"{meta['id']}.tar.gz"
        part = self.held_dir / ".outgoing.sbk"
        self.held_dir.mkdir(parents=True, exist_ok=True)
        try:
            sealed_sha = sealed.seal(archive, part, key)
            params = {"id": meta["id"], "sealed_sha256": sealed_sha, "sha256": meta.get("sha256"),
                      "created": meta.get("created"), "created_ts": meta.get("created_ts"), "files": meta.get("files")}
            with open(part, "rb") as fh:
                r = self.session.post(self._url("/fleet/backup-copies"), params=params, data=fh, timeout=600,
                                      headers={**self._h(), "Content-Type": "application/octet-stream"},
                                      verify=self.verify)
        finally:
            part.unlink(missing_ok=True)
        if r.status_code != 200:
            raise ValueError(f"the panel did not keep the copy of {meta['id']} ({r.status_code}: {r.text[:120]})")
        state["sent"] = meta["id"]
        _store(self.state_file, state)
        self.log(f"sent a sealed copy of backup {meta['id']} to the panel")
        return meta["id"]

    def _fetch(self, c: dict[str, Any]) -> bool:
        from app import backup_copies

        owner, bid = backup_copies.check_owner(str(c.get("owner"))), backup_copies.check_id(str(c.get("id")))
        dest = self.held_dir / owner / f"{bid}.sbk"
        if dest.is_file():
            return False
        size = int(c.get("bytes") or 0)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if shutil.disk_usage(dest.parent).free < size * 1.1 + 500 * 1024 * 1024:
            self.log(f"not keeping a copy of {owner}/{bid}: not enough free disk space here")
            return False
        part = dest.with_name(f".{dest.name}.part")
        try:
            with self.session.get(self._url("/fleet/backup-copies/file"), params={"owner": owner, "id": bid},
                                  headers=self._h(), timeout=600, verify=self.verify, stream=True) as r:
                if r.status_code != 200:
                    return False
                with open(part, "wb") as fh:
                    for chunk in r.iter_content(1024 * 1024):
                        fh.write(chunk)
            if sealed.sha256_file(part) != c.get("sealed_sha256"):
                raise ValueError(f"the copy of {owner}/{bid} arrived damaged")
            os.replace(part, dest)
        finally:
            part.unlink(missing_ok=True)
        meta = {k: c.get(k) for k in ("owner", "id", "created", "created_ts", "sealed_sha256", "bytes")}
        _store(dest.with_suffix(".json"), meta)
        self.log(f"keeping a sealed copy of {owner}'s backup {bid}")
        return True

    def held(self) -> list[dict[str, Any]]:
        out = []
        for d in sorted(p for p in self.held_dir.iterdir() if p.is_dir()) if self.held_dir.is_dir() else []:
            for f in sorted(d.glob("b-*.sbk")):
                meta = _load(f.with_suffix(".json"), {})
                if meta.get("sealed_sha256"):
                    out.append({"owner": d.name, "id": f.stem, "sealed_sha256": meta["sealed_sha256"]})
        return out

    def _drop_old(self) -> list[str]:
        """Only this machine decides what it deletes: per machine, the oldest beyond the newest COPY_HOLD."""
        gone = []
        for d in (p for p in self.held_dir.iterdir() if p.is_dir()) if self.held_dir.is_dir() else []:
            copies = sorted(d.glob("b-*.sbk"), key=lambda f: (_load(f.with_suffix(".json"), {}).get("created_ts") or 0,
                                                              f.name), reverse=True)
            for f in copies[COPY_HOLD:]:
                f.unlink(missing_ok=True)
                f.with_suffix(".json").unlink(missing_ok=True)
                gone.append(f"{d.name}/{f.stem}")
        return gone


def _deps_dir(data_dir: Path) -> Path:
    return sentrai_paths.path("agent.deps", data_dir)


def _load(f: Path, default: Any) -> Any:
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _store(f: Path, data: Any) -> None:
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_name(f".{f.name}.tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    os.replace(tmp, f)


def run_dep_scan(data_dir: Path) -> dict[str, Any]:
    result = depscan.scan(_paths("SENTRAI_DEP_PATHS"))
    if not result.get("note"):  # an offline scan keeps the last good list for updates
        _store(_deps_dir(data_dir) / "last_scan.json", result)
    return depscan.shown(result)


def run_dep_update(data_dir: Path, params: dict[str, Any]) -> dict[str, Any]:
    d = _deps_dir(data_dir)
    fid = str(params.get("finding") or "")
    f = next((f for f in _load(d / "last_scan.json", {}).get("findings") or [] if f.get("id") == fid), None)
    if f is None:
        raise depscan.UpdateError(f"{fid or 'that finding'} is not in this machine's last dependency scan; scan again")
    rec = depscan.apply_update(f, d / "undo")
    updates = _load(d / "updates.json", [])
    _store(d / "updates.json", (updates + [rec])[-100:])
    return {k: v for k, v in rec.items() if k not in ("real_path", "python", "backup")}


def run_dep_rollback(data_dir: Path, params: dict[str, Any]) -> dict[str, Any]:
    d = _deps_dir(data_dir)
    uid = str(params.get("update") or "")
    updates = _load(d / "updates.json", [])
    n = next((i for i, u in enumerate(updates) if u.get("id") == uid), None)
    if n is None:
        raise depscan.UpdateError(f"no update {uid or '(none)'} was made on this machine")
    updates[n] = depscan.rollback(updates[n])
    _store(d / "updates.json", updates)
    return {k: v for k, v in updates[n].items() if k not in ("real_path", "python", "backup")}


def run_job(job: dict[str, Any], data_dir: Path) -> tuple[bool, dict[str, Any] | None, str | None]:
    """Run one job here. Returns (ok, result, error); never raises."""
    try:
        if job["kind"] == "threat_scan":
            return True, run_threat_scan(data_dir), None
        if job["kind"] in ("quarantine", "restore"):
            params = job.get("params") or {}
            try:
                if job["kind"] == "quarantine":
                    return True, quarantine.quarantine(data_dir, str(params.get("finding") or ""), "panel"), None
                return True, quarantine.restore(data_dir, str(params.get("item") or ""), "panel"), None
            except quarantine.QuarantineError as exc:
                return False, None, str(exc)[:400]
        if job["kind"] == "backup":
            out = run_backup(data_dir)
            return (True, out, None) if out.get("ok") else (False, None, out.get("error") or out.get("note"))
        if job["kind"] == "dep_scan":
            return True, run_dep_scan(data_dir), None
        if job["kind"] in ("dep_update", "dep_rollback"):
            run = run_dep_update if job["kind"] == "dep_update" else run_dep_rollback
            try:
                return True, run(data_dir, job.get("params") or {}), None
            except depscan.UpdateError as exc:
                return False, None, str(exc)[:400]
        return False, None, f"this agent does not know the job {job['kind']!r}; update it"
    except Exception as exc:  # report it to the panel rather than kill the agent
        return False, None, f"{type(exc).__name__}: {exc}"[:400]


BLOCKING_JOBS = ("blocking_on", "blocking_off")


def switch_blocking(job: dict[str, Any], data: dict[str, Any]) -> tuple[bool, dict[str, Any] | None, str | None]:
    """The panel asked this machine to really block (blocking_on) or go back to a dry run (blocking_off).

    Kept next to the machine's key; the block loop picks it up within a few seconds (agent.enforce_setting).
    A later --enforce or --dry-run given to the installer on this machine wins again."""
    from agent import agent as core_agent  # here, not at the top: agent.py starts this loop

    try:
        on = job["kind"] == "blocking_on"
        core_agent.choose_enforce(data, on)
        core_agent.save(data)
        return True, {"enforce": on}, None
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
    next_copies = time.monotonic() + 30.0  # first round shortly after start
    while not stop.is_set():
        if copies_on() and time.monotonic() >= next_copies:
            out = CopySync(data, session, verify, data_dir, log).run()
            if out.get("error"):
                log(f"backup copies: {out['error']}")
            next_copies = time.monotonic() + COPIES_EVERY_S
        job = next_job(data, session, verify)
        if job:
            log(f"panel asked for a {job['kind'].replace('_', ' ')} ({job['id']})")
            ok, result, error = switch_blocking(job, data) if job["kind"] in BLOCKING_JOBS else run_job(job, data_dir)
            sent = send_result(data, session, verify, job["id"], ok, result, error)
            log(f"{job['id']} {'done' if ok else 'failed: ' + str(error)}{'' if sent else ' (could not tell the panel)'}")
            if ok and job["kind"] == "backup":
                next_copies = 0.0  # send the new backup's copy right away
            continue  # another job may be waiting
        stop.wait(every_s)
