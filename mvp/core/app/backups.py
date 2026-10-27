"""Backups: copy chosen folders (and SentrAI's own data) on a schedule, so a damaged system can be put back.

What is copied:
* The folders named in ``backup.paths`` in the system profile (or ``SENTRAI_BACKUP_PATHS``, separated
  by the OS path separator): a website, a game server, an upload folder.
* SentrAI's own data, always (``backup.include_sentrai`` false turns it off): the settings file, the
  data folder (protection switch, signing key, threat state) and a consistent snapshot of the audit
  database taken with SQLite's own backup call, so it is never copied half-written.

Each backup is one ``.tar.gz`` in ``backups`` beside the database (``SENTRAI_BACKUP_DIR``) with a ``manifest.json``
inside listing every file and its SHA-256, plus a ``.json`` note beside it. The archive's SHA-256 is
written to the audit trail, so a backup that was swapped or edited later fails ``verify``. Archives
and notes are readable by this account only (they hold the settings file and the signing key).

Schedule: every ``backup.every_hours`` (24), keeping the newest ``backup.keep`` (7). ``backup.copy_to``
puts a second copy on another drive or network share. A failed backup alerts the on-duty contact.

Restore always needs a person (an operator's request through the API or the dashboard; the chat can
only suggest it). By default it unpacks into a new folder beside the backups and changes nothing live.
Putting files back where they came from needs ``in_place`` with the backup's id typed as confirmation,
and first takes a fresh backup of those folders, so the restore itself can be undone. SentrAI's own data
is never written back in place while the core runs; it is unpacked to a folder with a note on how to
swap it in. Every step, and whether it worked, goes to the audit trail. Standard library only.
"""

from __future__ import annotations

import fnmatch
import hashlib
import io
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
import threading
import time
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from .config import CORE_DIR
import sentrai_config
from . import procscan
from .procscan import hide_home

DEFAULT_EVERY_HOURS = 24.0
DEFAULT_KEEP = 7
DEFAULT_MAX_TOTAL_MB = 5120     # refuse a backup bigger than this (it would fill the disk)
IN_MEMORY_BYTES = 64 * 1024 * 1024
CHUNK = 1024 * 1024
# Rebuilt on their own or not worth restoring.
SKIP_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache"}
SKIP_FILES = ("*.pyc", "*.db-wal", "*.db-shm", "*.tmp")
REASONS = ("schedule", "manual", "before_restore")


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


class _Hashing(io.RawIOBase):
    """Reads a file for tarfile while hashing it, so big files are read once."""

    def __init__(self, fh: Any) -> None:
        self.fh, self.h = fh, hashlib.sha256()

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        data = self.fh.read(n)
        self.h.update(data)
        return data


def _safe_member(name: str) -> PurePosixPath | None:
    """The member's path if it stays inside the archive's own folders, else None."""
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts or not p.parts or ":" in p.parts[0]:
        return None
    return p


class BackupWatch:
    def __init__(self, core: Any) -> None:
        self.core = core
        self.lock = threading.Lock()       # one backup or restore at a time
        self.last_error: dict[str, Any] | None = None
        self._retry_at = 0.0                # after a failed scheduled backup: wait, do not alert every minute

    # ------------------------------------------------------------ settings
    def config(self) -> dict[str, Any]:
        """``backup`` from the system profile; SENTRAI_BACKUP_* fill in what the profile leaves out."""
        profile = getattr(self.core, "profile", None) or {}
        cfg = dict(profile.get("backup") or {})
        env = os.environ
        if not cfg.get("paths") and env.get("SENTRAI_BACKUP_PATHS"):
            cfg["paths"] = [p for p in env["SENTRAI_BACKUP_PATHS"].split(os.pathsep) if p.strip()]
        for key, name in (("every_hours", "SENTRAI_BACKUP_EVERY_HOURS"), ("keep", "SENTRAI_BACKUP_KEEP"),
                          ("copy_to", "SENTRAI_BACKUP_COPY_TO")):
            if cfg.get(key) in (None, "") and env.get(name, "").strip():
                cfg[key] = env[name].strip()
        return cfg

    def every_s(self) -> float:
        cfg = self.config()
        if cfg.get("enabled") is False:
            return 0.0
        try:
            return max(0.0, float(cfg.get("every_hours", DEFAULT_EVERY_HOURS))) * 3600
        except (TypeError, ValueError):
            return DEFAULT_EVERY_HOURS * 3600

    def _keep(self, cfg: dict[str, Any]) -> int:
        try:
            return max(1, int(cfg.get("keep", DEFAULT_KEEP)))
        except (TypeError, ValueError):
            return DEFAULT_KEEP

    def _roots(self, cfg: dict[str, Any]) -> list[str]:
        return [os.path.abspath(os.path.expanduser(p)) for p in (cfg.get("paths") or [])
                if isinstance(p, str) and p.strip()]

    def _data_dir(self) -> Path:
        return Path(self.core.settings.db_path).parent

    def _dir(self) -> Path:
        """Next to the database by default: the one place a hardened install lets the core write."""
        return Path(os.environ.get("SENTRAI_BACKUP_DIR") or self._data_dir() / "backups")

    # ------------------------------------------------------------- listing
    def _metas(self) -> list[dict[str, Any]]:
        d = self._dir()
        out = []
        for m in d.glob("b-*.json") if d.is_dir() else []:
            try:
                meta = json.loads(m.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(meta, dict) and (d / f"{meta.get('id')}.tar.gz").is_file():
                out.append(meta)
        return sorted(out, key=lambda x: (x.get("created_ts", 0), x.get("id", "")), reverse=True)

    def _meta(self, bid: str) -> dict[str, Any]:
        if not bid.startswith("b-") or "/" in bid or "\\" in bid or ".." in bid:
            raise KeyError(f"{bid} is not a backup")
        d = self._dir()
        try:
            meta = json.loads((d / f"{bid}.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise KeyError(f"{bid} is not a backup")
        if not (d / f"{bid}.tar.gz").is_file():
            raise KeyError(f"{bid} has lost its archive")
        return meta

    def status(self) -> dict[str, Any]:
        cfg = self.config()
        every = self.every_s()
        backups = self._metas()
        homes = procscan._homes()
        last_ok = next((b for b in backups if b.get("reason") != "before_restore"), None)
        next_due = None
        overdue = False
        if every:
            base = last_ok["created_ts"] if last_ok else time.time()
            next_due = self.core.clock.iso(base + every) if last_ok else "now"
            overdue = bool(last_ok) and time.time() > last_ok["created_ts"] + every * 2
        return {
            "enabled": cfg.get("enabled") is not False,
            "every_hours": round(every / 3600, 2) if every else None,
            "keep": self._keep(cfg),
            "folders": [hide_home(r, homes) for r in self._roots(cfg)],
            "include_sentrai": cfg.get("include_sentrai") is not False,
            "copy_to": hide_home(str(cfg["copy_to"]), homes) if cfg.get("copy_to") else None,
            "stored_in": hide_home(str(self._dir()), homes),
            "next_due": next_due,
            "overdue": overdue,
            "last_error": self.last_error,
            "backups": [self.public(b) for b in backups],
        }

    @staticmethod
    def public(meta: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in meta.items() if k != "real_roots"}

    def due(self) -> bool:
        every = self.every_s()
        if not every or time.time() < self._retry_at:
            return False
        last = next((b for b in self._metas() if b.get("reason") != "before_restore"), None)
        return last is None or time.time() >= last["created_ts"] + every

    # --------------------------------------------------------------- backup
    def _walk(self, root: Path, skip: list[Path], exclude: list[str]) -> Iterator[Path]:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            here = Path(dirpath)
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS
                                 and not any((here / d) == s for s in skip))
            for name in sorted(filenames):
                p = here / name
                rel = p.relative_to(root).as_posix()
                if any(fnmatch.fnmatch(name, pat) for pat in SKIP_FILES) or \
                        any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(name, pat) for pat in exclude):
                    continue
                if p.is_symlink() or not p.is_file():
                    continue
                yield p

    def make(self, by: str = "operator", reason: str = "manual", roots: list[str] | None = None,
             include_sentrai: bool | None = None) -> dict[str, Any]:
        """Take one backup now. Returns its note; ``ok`` false (and an alert) when it failed."""
        if reason not in REASONS:
            reason = "manual"
        with self.lock:
            return self._make(by, reason, roots, include_sentrai)

    def _make(self, by: str, reason: str, roots: list[str] | None, include_sentrai: bool | None) -> dict[str, Any]:
        cfg = self.config()
        if cfg.get("enabled") is False and reason != "before_restore":
            return {"ok": False, "note": "Backups are turned off in the system profile."}
        roots = [os.path.abspath(r) for r in roots] if roots is not None else self._roots(cfg)
        with_sentrai = (cfg.get("include_sentrai") is not False) if include_sentrai is None else include_sentrai
        exclude = [str(x) for x in (cfg.get("exclude") or []) if isinstance(x, str)]
        dest = self._dir()
        homes = procscan._homes()
        shown_roots = [hide_home(r, homes) for r in roots]
        bid = f"b-{time.strftime('%Y%m%d-%H%M%S')}"
        n = 1
        while (dest / f"{bid}.json").exists() or (dest / f"{bid}.tar.gz").exists():
            n += 1
            bid = f"b-{time.strftime('%Y%m%d-%H%M%S')}-{n}"
        tmp = dest / f".{bid}.tar.gz.part"
        snap_dir = None
        try:
            _private_dir(dest)
            skip = [dest.resolve(), self._quarantine_dir().resolve()]
            plan: list[tuple[Path, str]] = []   # (file on disk, name in the archive)
            missing = []
            for i, r in enumerate(roots):
                rp = Path(r)
                if not rp.is_dir():
                    missing.append(shown_roots[i])
                    continue
                for p in self._walk(rp, skip, exclude):
                    plan.append((p, f"files/{i}/{p.relative_to(rp).as_posix()}"))
            if with_sentrai:
                data = self._data_dir()
                db = Path(self.core.settings.db_path)
                if data.is_dir():
                    for p in self._walk(data, skip + [(data / "restores").resolve()], exclude):
                        if p.name != db.name:
                            plan.append((p, f"sentrai/data/{p.relative_to(data).as_posix()}"))
                snap_dir = Path(tempfile.mkdtemp(prefix="sentrai-backup-"))
                snap = snap_dir / db.name
                self._snapshot_db(snap)
                plan.append((snap, f"sentrai/data/{db.name}"))
                conf = sentrai_config.config_path()
                if conf.is_file():
                    plan.append((conf, "sentrai/config.json"))
            if not plan:
                raise ValueError("nothing to back up: no folders are set (backup.paths) and SentrAI's own data "
                                 "is left out" + (f"; folders not found: {', '.join(missing)}" if missing else ""))
            total = 0
            for p, _ in plan:
                try:
                    total += p.stat().st_size
                except OSError:
                    pass
            limit = float(cfg.get("max_total_mb", DEFAULT_MAX_TOTAL_MB)) * 1024 * 1024
            if total > limit:
                raise ValueError(f"the folders hold {total / 1048576:.0f} MB, over the {limit / 1048576:.0f} MB "
                                 f"limit (backup.max_total_mb); back up fewer folders or raise the limit")
            free = shutil.disk_usage(dest).free
            if free < total * 1.1 + 50 * 1024 * 1024:
                raise ValueError(f"not enough free disk space in {hide_home(str(dest), homes)} "
                                 f"({free / 1048576:.0f} MB free, about {total / 1048576:.0f} MB needed)")
            manifest = {"id": bid, "created": self.core.clock.now_iso(),
                        "roots": [{"index": i, "path": r} for i, r in enumerate(roots)], "sentrai": with_sentrai}
            files, skipped, manifest_bytes = self._write_archive(tmp, plan, manifest)
            archive_sha = _sha256_file(tmp)
            os.replace(tmp, dest / f"{bid}.tar.gz")
            try:
                os.chmod(dest / f"{bid}.tar.gz", 0o600)
            except OSError:
                pass
            now = time.time()
            meta = {
                "id": bid, "created": self.core.clock.iso(now), "created_ts": now, "by": by, "reason": reason,
                "folders": shown_roots, "real_roots": roots, "missing": missing, "sentrai": with_sentrai,
                "files": len(files), "bytes": sum(f["size"] for f in files),
                "archive_bytes": (dest / f"{bid}.tar.gz").stat().st_size,
                "sha256": archive_sha, "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "skipped": skipped[:50], "copy": None, "verified": None,
            }
            meta["copy"] = self._copy(cfg, bid, meta)
            self._write_meta(meta)
            self.last_error, self._retry_at = None, 0.0
            self.core.scribe.record(self.core.name, "backup_made", {
                "backup": bid, "by": by, "reason": reason, "folders": shown_roots, "sentrai": with_sentrai,
                "files": meta["files"], "bytes": meta["bytes"], "sha256": archive_sha,
                "manifest_sha256": meta["manifest_sha256"], "skipped": len(skipped),
                "copy": (meta["copy"] or {}).get("ok"),
                "summary": f"{by} backed up {meta['files']} files ({meta['bytes'] / 1048576:.1f} MB) as {bid}"})
            if meta["copy"] and not meta["copy"]["ok"]:
                self._alert("backup_failed", f"Backup {bid}: second copy failed",
                            f"Backup {bid} was made, but copying it to {meta['copy']['to']} failed: "
                            f"{meta['copy']['error']}. Check that drive or share.")
            pruned = self._prune(self._keep(cfg), keep_id=bid)
            return {"ok": True, **self.public(meta), "pruned": pruned}
        except Exception as e:  # any failure is reported and alerted, never raised into the scheduler
            tmp.unlink(missing_ok=True)
            why = str(e) if isinstance(e, ValueError) else f"{type(e).__name__}: {e}"
            self.last_error = {"at": self.core.clock.now_iso(), "reason": reason, "error": why[:400]}
            if reason == "schedule":
                self._retry_at = time.time() + min(3600.0, self.every_s() or 3600.0)
            self.core.scribe.record(self.core.name, "backup_failed", {
                "by": by, "reason": reason, "folders": shown_roots, "error": why[:400],
                "summary": f"Backup by {by} failed: {why[:120]}"})
            self._alert("backup_failed", "Backup failed",
                        f"The {reason.replace('_', ' ')} backup failed: {why[:300]}. "
                        f"Until one works, there is no fresh copy to restore from.")
            return {"ok": False, "error": why[:400], "note": "The backup failed; nothing was kept."}
        finally:
            if snap_dir is not None:
                shutil.rmtree(snap_dir, ignore_errors=True)

    def _quarantine_dir(self) -> Path:
        return Path(os.environ.get("SENTRAI_QUARANTINE", str(CORE_DIR / "data" / "quarantine")))

    def _snapshot_db(self, target: Path) -> None:
        """A consistent copy of the audit database while it stays in use (SQLite's online backup)."""
        audit = self.core.audit
        dst = sqlite3.connect(str(target))
        try:
            with audit.lock:
                audit.conn.backup(dst)
        finally:
            dst.close()

    def _write_archive(self, tmp: Path, plan: list[tuple[Path, str]],
                       manifest: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str], bytes]:
        """Writes the files, then manifest.json (every file's size and SHA-256) as the last entry."""
        files: list[dict[str, Any]] = []
        skipped: list[str] = []
        homes = procscan._homes()
        with tarfile.open(tmp, "w:gz", compresslevel=6) as tar:
            for path, arc in plan:
                try:
                    st = path.stat()
                    info = tarfile.TarInfo(arc)
                    info.mtime, info.mode = int(st.st_mtime), st.st_mode & 0o777
                    if st.st_size <= IN_MEMORY_BYTES:
                        data = path.read_bytes()
                        info.size = len(data)
                        sha = hashlib.sha256(data).hexdigest()
                        tar.addfile(info, io.BytesIO(data))
                    else:  # a big file is streamed; one that changes size mid-copy fails the backup
                        info.size = st.st_size
                        with open(path, "rb") as fh:
                            wrap = _Hashing(fh)
                            tar.addfile(info, wrap)
                            sha = wrap.h.hexdigest()
                except (PermissionError, FileNotFoundError):
                    skipped.append(hide_home(str(path), homes))
                    continue
                files.append({"name": arc, "size": info.size, "sha256": sha})
            manifest_bytes = json.dumps({**manifest, "files": files}, indent=1).encode("utf-8")
            info = tarfile.TarInfo("manifest.json")
            info.size, info.mtime, info.mode = len(manifest_bytes), int(time.time()), 0o600
            tar.addfile(info, io.BytesIO(manifest_bytes))
        return files, skipped, manifest_bytes

    def _write_meta(self, meta: dict[str, Any]) -> None:
        f = self._dir() / f"{meta['id']}.json"
        tmp = f.with_name(f".{f.name}.tmp")
        tmp.write_text(json.dumps(meta, indent=1), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, f)

    def _copy(self, cfg: dict[str, Any], bid: str, meta: dict[str, Any]) -> dict[str, Any] | None:
        to = cfg.get("copy_to")
        if not to:
            return None
        target = Path(os.path.expanduser(str(to)))
        shown = hide_home(str(target), procscan._homes())
        try:
            _private_dir(target)
            src = self._dir() / f"{bid}.tar.gz"
            shutil.copyfile(src, target / f".{bid}.tar.gz.part")
            if _sha256_file(target / f".{bid}.tar.gz.part") != meta["sha256"]:
                raise OSError("the copy does not match the original")
            os.replace(target / f".{bid}.tar.gz.part", target / f"{bid}.tar.gz")
            (target / f"{bid}.json").write_text(json.dumps(self.public(meta), indent=1), encoding="utf-8")
            keep = self._keep(cfg)
            for old in sorted(target.glob("b-*.tar.gz"), reverse=True)[keep:]:
                old.unlink(missing_ok=True)
                old.with_name(old.name.replace(".tar.gz", ".json")).unlink(missing_ok=True)
            return {"ok": True, "to": shown}
        except OSError as e:
            if target.is_dir():
                (target / f".{bid}.tar.gz.part").unlink(missing_ok=True)
            return {"ok": False, "to": shown, "error": f"{type(e).__name__}: {e}"[:200]}

    def _prune(self, keep: int, keep_id: str) -> list[str]:
        """Delete the oldest backups beyond ``keep`` (safety copies taken before a restore count too)."""
        gone = []
        d = self._dir()
        for meta in self._metas()[keep:]:
            if meta["id"] == keep_id:
                continue
            (d / f"{meta['id']}.tar.gz").unlink(missing_ok=True)
            (d / f"{meta['id']}.json").unlink(missing_ok=True)
            gone.append(meta["id"])
        if gone:
            self.core.scribe.record(self.core.name, "backup_pruned", {
                "removed": gone, "keep": keep, "summary": f"Removed {len(gone)} old backup(s), keeping the newest {keep}"})
        return gone

    def _alert(self, kind: str, title: str, text: str) -> None:
        core = self.core
        with core.lock:
            core._notify(core.clock.now(), kind, None, [core.settings.on_duty], title, text, [])

    # --------------------------------------------------------------- verify
    def verify(self, bid: str, by: str = "operator") -> dict[str, Any]:
        with self.lock:
            return self._verify(bid, by)

    def _verify(self, bid: str, by: str, record: bool = True) -> dict[str, Any]:
        meta = self._meta(bid)
        problems: list[str] = []
        archive = self._dir() / f"{bid}.tar.gz"
        sha = _sha256_file(archive)
        if sha != meta.get("sha256"):
            problems.append("the archive changed since it was made (its fingerprint does not match the note)")
        audited = [r["data"] for r in self.core.audit.records()
                   if r["type"] == "backup_made" and r["data"].get("backup") == bid]
        if not audited:
            problems.append("the audit trail has no record of this backup being made")
        elif audited[-1].get("sha256") != sha:
            problems.append("the archive does not match the fingerprint in the audit trail")
        checked = 0
        if not problems:
            try:
                manifest_sha, checked, bad = self._check_members(archive)
                if manifest_sha != meta.get("manifest_sha256"):
                    problems.append("the file list inside the archive was changed")
                problems += bad
            except (tarfile.TarError, OSError, ValueError, KeyError, EOFError) as e:
                problems.append(f"the archive cannot be read ({type(e).__name__})")
        ok = not problems
        meta["verified"] = {"ok": ok, "at": self.core.clock.now_iso(), "problems": problems[:10]}
        self._write_meta(meta)
        if record:
            self.core.scribe.record(self.core.name, "backup_verified", {
                "backup": bid, "by": by, "ok": ok, "files_checked": checked, "problems": problems[:10],
                "summary": f"{by} checked backup {bid}: " + ("intact" if ok else "PROBLEM: " + problems[0])})
        return {"ok": ok, "backup": bid, "files_checked": checked, "problems": problems}

    def _check_members(self, archive: Path) -> tuple[str, int, list[str]]:
        """(SHA-256 of manifest.json, files checked, problems): every entry against its fingerprint."""
        with tarfile.open(archive, "r:gz") as tar:
            mf = tar.extractfile("manifest.json")
            if mf is None:
                raise KeyError("manifest.json")
            raw = mf.read()
            manifest = json.loads(raw.decode("utf-8"))
            want = {f["name"]: f["sha256"] for f in manifest["files"]}
            bad, checked = [], 0
            for m in tar:
                if m.name == "manifest.json":
                    continue
                if m.name not in want or not m.isfile() or _safe_member(m.name) is None:
                    bad.append(f"unexpected entry in the archive: {m.name[:120]}")
                    continue
                h = hashlib.sha256()
                fh = tar.extractfile(m)
                for chunk in iter(lambda: fh.read(CHUNK), b""):
                    h.update(chunk)
                if h.hexdigest() != want.pop(m.name):
                    bad.append(f"{m.name[:120]} does not match its fingerprint")
                checked += 1
            bad += [f"{name[:120]} is missing from the archive" for name in list(want)[:10]]
        return hashlib.sha256(raw).hexdigest(), checked, bad

    # -------------------------------------------------------------- restore
    def restore(self, bid: str, operator: str, in_place: bool = False, confirm: str = "",
                target: str | None = None) -> dict[str, Any]:
        """Unpack a backup. A person asks for it; it is checked first and the outcome is audited."""
        if not operator or not operator.strip():
            raise ValueError("a restore needs the name of the person asking for it")
        if in_place and confirm != bid:
            raise ValueError(f"putting files back in place overwrites live files: type the backup id ({bid}) "
                             f"as confirmation")
        with self.lock:
            meta = self._meta(bid)
            check = self._verify(bid, operator)
            if not check["ok"]:
                raise ValueError("this backup failed its check, so it will not be restored: " + check["problems"][0])
            homes = procscan._homes()
            roots = list(meta.get("real_roots") or [])
            safety = None
            if in_place:
                live = [r for r in roots if Path(r).exists()]
                if live:
                    safety = self._make(operator, "before_restore", live, include_sentrai=False)
                    if not safety.get("ok"):
                        raise ValueError("could not take a safety backup of the current files first, so nothing "
                                         "was restored: " + str(safety.get("error")))
                dest_root = None
            else:
                stamp = time.strftime("%Y%m%d-%H%M%S")
                dest_root = Path(os.path.expanduser(target)) if target else self._data_dir() / "restores" / f"{bid}-{stamp}"
                if dest_root.exists() and any(dest_root.iterdir()):
                    raise ValueError("the restore folder is not empty; pick a new one")
                _private_dir(dest_root)
            written, failed, sentrai_files = 0, [], 0
            archive = self._dir() / f"{bid}.tar.gz"
            try:
                with tarfile.open(archive, "r:gz") as tar:
                    mf = tar.extractfile("manifest.json")
                    want = {f["name"]: f["sha256"] for f in json.loads(mf.read())["files"]} if mf else {}
                    for m in tar.getmembers():
                        p = _safe_member(m.name)
                        if m.name == "manifest.json" or p is None or not m.isfile():
                            continue
                        out = self._where(p, roots, dest_root, bid)
                        if out is None:
                            continue
                        if p.parts[0] == "sentrai":
                            sentrai_files += 1
                        try:
                            self._extract(tar, m, out, want.get(m.name))
                            written += 1
                        except (OSError, ValueError) as e:
                            failed.append(f"{hide_home(str(out), homes)}: {e}"[:200])
            except (tarfile.TarError, OSError) as e:
                failed.append(f"archive: {type(e).__name__}: {e}"[:200])
            ok = not failed and written > 0
            where = "in place" if in_place else hide_home(str(dest_root), homes)
            result = {
                "ok": ok, "backup": bid, "in_place": in_place, "restored_to": where, "files_restored": written,
                "failed": failed[:20], "safety_backup": (safety or {}).get("id"),
                "note": self._restore_note(in_place, sentrai_files, safety, meta),
            }
            self.core.scribe.record(self.core.name, "backup_restored", {
                "backup": bid, "operator": operator, "in_place": in_place, "restored_to": where, "ok": ok,
                "files_restored": written, "failed": len(failed), "safety_backup": result["safety_backup"],
                "summary": f"{operator} restored {written} files from {bid} {'in place' if in_place else 'to ' + where}"
                           + ("" if ok else f" ({len(failed)} failed)")})
            self._alert("backup_restored", f"Backup {bid} restored" + ("" if ok else " with problems"),
                        f"{operator} restored {written} files from backup {bid} "
                        f"{'over the live folders' if in_place else 'into ' + where}."
                        + (f" {len(failed)} files could not be written." if failed else "")
                        + (f" Safety backup of the files it replaced: {result['safety_backup']}." if safety else ""))
            return result

    @staticmethod
    def _restore_note(in_place: bool, sentrai_files: int, safety: dict[str, Any] | None, meta: dict[str, Any]) -> str:
        parts = []
        if in_place:
            parts.append("Files were put back where they came from. Files made after the backup were left alone.")
            if safety:
                parts.append(f"The files that were replaced are in safety backup {safety.get('id')}; "
                             f"restoring that one in place undoes this.")
        else:
            parts.append("Nothing live was changed. Compare the restored files, then copy back what you need, or "
                         "restore again with 'in place'.")
        if meta.get("sentrai"):
            parts.append("SentrAI's own data is never written over while it runs. "
                         + ("It was skipped. " if in_place else "It is in the sentrai folder. ")
                         + "To use it: stop SentrAI, copy sentrai/data into the core's data folder and "
                           "sentrai/config.json to the settings file, then start SentrAI.")
        return " ".join(parts)

    @staticmethod
    def _where(p: PurePosixPath, roots: list[str], dest_root: Path | None, bid: str) -> Path | None:
        """Where one archive entry goes: under its original folder (in place) or the restore folder."""
        if p.parts[0] == "files" and len(p.parts) > 2 and p.parts[1].isdigit():
            i, rest = int(p.parts[1]), p.parts[2:]
            if i >= len(roots):
                return None
            if dest_root is None:
                return Path(roots[i]).joinpath(*rest)
            label = f"{i}-{Path(roots[i]).name or 'root'}"
            return dest_root.joinpath("files", label, *rest)
        if p.parts[0] == "sentrai" and len(p.parts) > 1:
            return None if dest_root is None else dest_root.joinpath(*p.parts)
        return None

    @staticmethod
    def _extract(tar: tarfile.TarFile, m: tarfile.TarInfo, out: Path, want_sha: str | None) -> None:
        out.parent.mkdir(parents=True, exist_ok=True)
        part = out.with_name(f".{out.name}.restore-part")
        h = hashlib.sha256()
        src = tar.extractfile(m)
        with open(part, "wb") as fh:
            for chunk in iter(lambda: src.read(CHUNK), b""):
                h.update(chunk)
                fh.write(chunk)
        if want_sha and h.hexdigest() != want_sha:
            part.unlink(missing_ok=True)
            raise ValueError("did not match its fingerprint")
        os.chmod(part, m.mode & 0o777 or 0o644)
        os.replace(part, out)
        os.utime(out, (m.mtime, m.mtime))

