"""Backup copies on other machines: losing one machine no longer loses its backups.

Every backup is sealed (sealed.py) and copies go to other machines through the panel. Agents only ever
make outgoing calls, so the panel is the meeting point:

* A machine's own backup: its agent seals it with that machine's key and sends the copy to the panel
  (POST /fleet/backup-copies). The panel keeps it in ``backups/copies/<machine>/``.
* The panel's own backup: the panel seals it with its own key into ``backups/copies/_panel/``.
* Each copy is also kept on ``SENTRAI_BACKUP_REPLICAS`` (default 2) other joined machines. The panel tells
  each agent which copies it should hold (GET /fleet/backup-copies/wanted, newest
  ``SENTRAI_BACKUP_HOLD`` (2) per machine); the agent downloads them, checks their fingerprint and says
  what it holds (POST /fleet/backup-copies/held). Machines are picked by a stable hash, so the same
  machines keep the same copies and a new machine only takes over a share.

Keys: every machine has its own. An agent sends its key to the panel once (POST /fleet/backup-key), so
the panel can unlock that machine's copy when the machine itself is lost. The panel's own key is shown to
the owner once as a recovery code (``python -m app.backup_copies key``): with it, any machine's copy of
the panel's backup can be unlocked after the panel is lost. The panel's backup holds the machines' keys,
so that one code brings everything back. A machine that keeps a copy never has the key for it.

What a machine holds is its own decision: it never deletes a copy because the panel says so, only when
it has newer ones of the same machine, so a panel taken over cannot wipe the copies elsewhere.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from . import sealed

PANEL = "_panel"            # the owner name of the panel's own copies (no machine name starts with "_")
OWNER_RE = re.compile(r"^(_panel|[A-Za-z0-9][A-Za-z0-9._-]{0,62})$")
ID_RE = re.compile(r"^b-[0-9]{8}-[0-9]{6}(-[0-9]{1,3})?$")
DEFAULT_REPLICAS = 2
DEFAULT_KEEP = 3            # copies per machine kept on the panel
DEFAULT_HOLD = 2            # copies per machine each holding machine is asked to keep
DEFAULT_MAX_MB = 5120


def _int_env(name: str, default: int, low: int = 0) -> int:
    try:
        return max(low, int(os.environ.get(name, "").strip() or default))
    except ValueError:
        return default


def replicas() -> int:
    return _int_env("SENTRAI_BACKUP_REPLICAS", DEFAULT_REPLICAS)


def check_owner(owner: str) -> str:
    if not OWNER_RE.match(owner or ""):
        raise KeyError(f"{owner!r} is not a machine")
    return owner


def check_id(bid: str) -> str:
    if not ID_RE.match(bid or ""):
        raise KeyError(f"{bid!r} is not a backup")
    return bid


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1)
    _same_owner(tmp, path if path.exists() else path.parent)
    os.replace(tmp, path)


def _same_owner(f: Path, like: Path) -> None:
    """Run with sudo (python -m app.backup_copies key), keep the file owned by the service's account."""
    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            st = like.stat()
            os.chown(f, st.st_uid, st.st_gid)
        except OSError:
            pass


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def rank(owner: str, hosts: Iterable[str]) -> list[str]:
    """Machines in the order they should keep ``owner``'s copies (rendezvous hashing: stable, spread out)."""
    return sorted((h for h in hosts if h != owner),
                  key=lambda h: hashlib.sha256(f"{owner}|{h}".encode()).hexdigest())


class CopyStore:
    """The panel's side: sealed copies, the machines' keys, and which machine holds what."""

    def __init__(self, backups_dir: Callable[[], Path], keys_path: Path, hosts: Callable[[], list[str]],
                 iso: Callable[[float], str]) -> None:
        self._backups_dir = backups_dir
        self.keys_path = keys_path
        self.hosts = hosts          # the joined machines that may keep copies (not revoked or removed)
        self.iso = iso
        self.lock = threading.Lock()

    # ------------------------------------------------------------------ places
    def root(self) -> Path:
        return self._backups_dir() / "copies"

    def _owner_dir(self, owner: str) -> Path:
        return self.root() / check_owner(owner)

    def path(self, owner: str, bid: str) -> Path:
        return self._owner_dir(owner) / f"{check_id(bid)}.sbk"

    # -------------------------------------------------------------------- keys
    def _keys(self) -> dict[str, Any]:
        return _read_json(self.keys_path, {})

    def panel_key(self) -> bytes:
        """The panel's own backup key, made the first time it is needed."""
        with self.lock:
            keys = self._keys()
            mine = keys.get(PANEL) or {}
            if mine.get("current") and mine.get("keys", {}).get(mine["current"]):
                return base64.b64decode(mine["keys"][mine["current"]])
            key = sealed.new_key()
            kid = sealed.key_id(key)
            keys[PANEL] = {"current": kid, "keys": {kid: base64.b64encode(key).decode()}, "made": self.iso(time.time()),
                           "shown": False}
            _write_json(self.keys_path, keys)
            return key

    def recovery_code(self, mark_shown: bool = True) -> str:
        key = self.panel_key()
        if mark_shown:
            with self.lock:
                keys = self._keys()
                keys[PANEL]["shown"] = True
                _write_json(self.keys_path, keys)
        return sealed.to_code(key)

    def escrow(self, owner: str, key_b64: str) -> str:
        """Keep a machine's backup key, so its copy can be unlocked when the machine is lost."""
        check_owner(owner)
        if owner == PANEL:
            raise KeyError("that name is the panel's own")
        try:
            key = base64.b64decode(key_b64, validate=True)
        except ValueError as exc:
            raise ValueError("the key is not base64") from exc
        if len(key) != 32:
            raise ValueError("a backup key is 32 bytes")
        kid = sealed.key_id(key)
        with self.lock:
            keys = self._keys()
            entry = keys.setdefault(owner, {"keys": {}})
            entry.setdefault("keys", {})[kid] = base64.b64encode(key).decode()
            entry["current"] = kid
            _write_json(self.keys_path, keys)
        return kid

    def key_for(self, owner: str, kid: str) -> bytes | None:
        raw = ((self._keys().get(owner) or {}).get("keys") or {}).get(kid)
        return base64.b64decode(raw) if raw else None

    def has_key(self, owner: str) -> bool:
        return bool((self._keys().get(owner) or {}).get("current"))

    # ------------------------------------------------------------------ copies
    def metas(self, owner: str | None = None) -> list[dict[str, Any]]:
        root = self.root()
        out = []
        dirs = [self._owner_dir(owner)] if owner else ([d for d in root.iterdir() if d.is_dir()] if root.is_dir() else [])
        for d in dirs:
            for m in d.glob("b-*.json") if d.is_dir() else []:
                meta = _read_json(m, None)
                if isinstance(meta, dict) and (d / f"{meta.get('id')}.sbk").is_file():
                    out.append(meta)
        return sorted(out, key=lambda x: (x.get("created_ts", 0), x.get("id", "")), reverse=True)

    def _store_meta(self, meta: dict[str, Any]) -> None:
        _write_json(self._owner_dir(meta["owner"]) / f"{meta['id']}.json", meta)

    def _prune(self, owner: str) -> list[str]:
        keep = _int_env("SENTRAI_BACKUP_COPIES_KEEP", DEFAULT_KEEP, 1)
        gone = []
        for meta in self.metas(owner)[keep:]:
            self.path(owner, meta["id"]).unlink(missing_ok=True)
            (self._owner_dir(owner) / f"{meta['id']}.json").unlink(missing_ok=True)
            gone.append(meta["id"])
        return gone

    def add_panel_copy(self, meta: dict[str, Any], archive: Path) -> dict[str, Any]:
        """Seal one of the panel's own backups, so other machines can keep a copy."""
        key = self.panel_key()
        dest = self.path(PANEL, meta["id"])
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(dest.parent, 0o700)
        except OSError:
            pass
        sealed_sha = sealed.seal(archive, dest, key)
        copy = {"owner": PANEL, "id": meta["id"], "created": meta.get("created"), "created_ts": meta.get("created_ts"),
                "sha256": meta.get("sha256"), "sealed_sha256": sealed_sha, "bytes": dest.stat().st_size,
                "files": meta.get("files"), "key_id": sealed.key_id(key), "received": self.iso(time.time())}
        self._store_meta(copy)
        self._prune(PANEL)
        return copy

    def start(self, owner: str, bid: str, info: dict[str, Any]) -> "Upload":
        """Begin keeping a sealed copy a machine sends; feed it with ``write`` and end with ``finish``."""
        return Upload(self, check_owner(owner), check_id(bid), info)

    def receive(self, owner: str, bid: str, chunks: Iterable[bytes], info: dict[str, Any]) -> dict[str, Any]:
        up = self.start(owner, bid, info)
        try:
            for chunk in chunks:
                up.write(chunk)
            return up.finish()
        finally:
            up.abort()

    # --------------------------------------------------------- who holds what
    def _held(self) -> dict[str, Any]:
        return _read_json(self.root() / "held.json", {})

    def holders(self, owner: str) -> list[str]:
        return rank(owner, self.hosts())[:replicas()]

    def wanted(self, host: str) -> list[dict[str, Any]]:
        """The copies ``host`` should keep: the newest few of every machine it was picked for."""
        hold = _int_env("SENTRAI_BACKUP_HOLD", DEFAULT_HOLD, 1)
        by_owner: dict[str, list[dict[str, Any]]] = {}
        for m in self.metas():
            by_owner.setdefault(m["owner"], []).append(m)
        out = []
        for owner, copies in by_owner.items():
            if owner == host or host not in self.holders(owner):
                continue
            for m in copies[:hold]:
                out.append({k: m.get(k) for k in ("owner", "id", "created", "created_ts", "sealed_sha256", "bytes")})
        return out

    def report(self, host: str, held: list[dict[str, Any]], free_mb: float | None) -> dict[str, Any]:
        clean = []
        for x in held[:500]:
            try:
                clean.append({"owner": check_owner(str(x.get("owner"))), "id": check_id(str(x.get("id"))),
                              "sealed_sha256": str(x.get("sealed_sha256") or "")[:64]})
            except KeyError:
                continue
        with self.lock:
            data = self._held()
            data[host] = {"at": self.iso(time.time()), "at_ts": time.time(), "held": clean,
                          "free_mb": None if free_mb is None else round(float(free_mb))}
            _write_json(self.root() / "held.json", data)
        return {"held": len(clean)}

    def where(self, owner: str, bid: str, sealed_sha: str | None = None) -> list[str]:
        """The machines that said they hold this copy (with the same fingerprint)."""
        out = []
        for host, rec in self._held().items():
            if host == owner or host not in self.hosts():
                continue
            if any(x["owner"] == owner and x["id"] == bid and (not sealed_sha or x["sealed_sha256"] == sealed_sha)
                   for x in rec.get("held") or []):
                out.append(host)
        return sorted(out)

    def summary(self, names: dict[str, str] | None = None) -> dict[str, Any]:
        names = names or {}
        keys = self._keys()
        machines: dict[str, Any] = {}
        for m in self.metas():
            owner = m["owner"]
            entry = machines.setdefault(owner, {
                "owner": owner, "name": "this panel" if owner == PANEL else names.get(owner, owner),
                "key_kept": bool((keys.get(owner) or {}).get("current")), "should_hold": self.holders(owner),
                "copies": []})
            held_on = self.where(owner, m["id"], m.get("sealed_sha256"))
            entry["copies"].append({**{k: m.get(k) for k in ("id", "created", "bytes", "files", "received")},
                                    "on_panel": owner != PANEL, "held_on": [names.get(h, h) for h in held_on]})
        panel_key = keys.get(PANEL) or {}
        return {
            "replicas": replicas(), "machines_available": len(self.hosts()),
            "recovery_code_shown": bool(panel_key.get("shown")), "recovery_key_id": panel_key.get("current"),
            "machines": sorted(machines.values(), key=lambda e: (e["owner"] != PANEL, e["name"])),
        }

    # ---------------------------------------------------------------- unlocking
    def unlock(self, owner: str, bid: str, out_dir: Path) -> Path:
        """Unlock a copy with the key the panel keeps for that machine, into ``out_dir``. For a machine
        that was lost: its backup comes back as the .tar.gz it was."""
        src = self.path(owner, bid)
        if not src.is_file():
            raise KeyError(f"no copy {bid} of {owner}")
        key = self.key_for(owner, sealed.needs(src))
        if key is None:
            raise ValueError("the panel has no key for this copy")
        out_dir.mkdir(parents=True, exist_ok=True)
        dest = out_dir / f"{owner.lstrip('_')}-{bid}.tar.gz"
        sealed.unseal(src, dest, key)
        return dest


class Upload:
    """One sealed copy arriving from a machine: checked for size while it comes in, and for its
    fingerprint and key before it replaces anything."""

    def __init__(self, store: CopyStore, owner: str, bid: str, info: dict[str, Any]) -> None:
        self.store, self.owner, self.bid, self.info = store, owner, bid, info
        self.want = str(info.get("sealed_sha256") or "").lower()
        if not re.match(r"^[0-9a-f]{64}$", self.want):
            raise ValueError("the copy's fingerprint (sealed_sha256) is missing")
        self.limit = _int_env("SENTRAI_BACKUP_COPY_MAX_MB", DEFAULT_MAX_MB, 1) * 1024 * 1024
        self.dir = store._owner_dir(owner)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.free = shutil.disk_usage(self.dir).free
        self.part = self.dir / f".{bid}.sbk.part"
        self.h, self.size = hashlib.sha256(), 0
        fd = os.open(str(self.part), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        self.fh = os.fdopen(fd, "wb")

    def write(self, chunk: bytes) -> None:
        self.size += len(chunk)
        if self.size > self.limit:
            raise ValueError(f"the copy is over {self.limit // 1048576} MB (SENTRAI_BACKUP_COPY_MAX_MB)")
        if self.size > self.free - 200 * 1024 * 1024:
            raise ValueError("the panel is running out of disk space for backup copies")
        self.h.update(chunk)
        self.fh.write(chunk)

    def finish(self) -> dict[str, Any]:
        self.fh.close()
        if self.h.hexdigest() != self.want:
            raise ValueError("the copy arrived damaged (its fingerprint does not match); it will be sent again")
        kid = sealed.needs(self.part)
        if self.store.key_for(self.owner, kid) is None:
            raise ValueError("the panel has no key for this copy yet; the machine sends it first")
        os.replace(self.part, self.dir / f"{self.bid}.sbk")
        now = time.time()
        try:
            created_ts = float(self.info.get("created_ts") or now)
        except (TypeError, ValueError):
            created_ts = now
        try:
            files = int(self.info.get("files") or 0)
        except (TypeError, ValueError):
            files = 0
        meta = {"owner": self.owner, "id": self.bid, "created": str(self.info.get("created") or "")[:40]
                or self.store.iso(created_ts), "created_ts": created_ts,
                "sha256": str(self.info.get("sha256") or "")[:64], "sealed_sha256": self.want, "bytes": self.size,
                "files": files, "key_id": kid, "received": self.store.iso(now)}
        self.store._store_meta(meta)
        meta["pruned"] = self.store._prune(self.owner)
        return meta

    def abort(self) -> None:
        if not self.fh.closed:
            self.fh.close()
        self.part.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    """python -m app.backup_copies key   show the panel's recovery code (write it down, keep it off the panel)."""
    import argparse

    from .config import Settings
    import sentrai_paths

    ap = argparse.ArgumentParser(prog="python -m app.backup_copies")
    ap.add_argument("cmd", choices=["key"])
    ap.parse_args(argv)
    data_dir = Settings().db_path.parent
    store = CopyStore(lambda: sentrai_paths.path("core.backups", data_dir),
                      sentrai_paths.path("core.backup_keys", data_dir, migrate=False), lambda: [],
                      lambda ts: time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts)))
    code = store.recovery_code()
    print("Recovery code for the panel's backups (keep it somewhere other than this server):\n")
    print(f"    {code}\n")
    print("With it, any machine's copy of the panel's backup can be unlocked after this server is lost:")
    print("    python -m app.sealed open <copy>.sbk backup.tar.gz --code <recovery code>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
