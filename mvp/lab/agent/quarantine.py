"""Findings and quarantine on this machine: what the threat scan and the file watch found here, and
the files a person chose to lock away.

Every finding this machine reports gets an id (16 hex characters). The panel shows the id; to lock a
file away, a person queues a ``quarantine`` job that names only that id (and to undo it, a
``restore`` job naming the quarantine id). The agent looks the real file up in its own list
(threats/findings.json next to the agent file), so the panel can never make a machine move a file
this machine did not itself flag.

Quarantine, as in any antivirus, is a move, not a delete:

* the file must still be exactly what was flagged (same SHA-256), or it is left alone;
* its bytes are scrambled (XOR with a fixed key) into threats/quarantine/q-*.bin, mode 0600, so it
  cannot run from there, nor be picked up again by this or another scanner;
* a note keeps where it was, its permissions and fingerprint, so ``restore`` puts it back exactly,
  and refuses when something else now sits in its place.

Nothing here runs on its own: both steps come from a person on the panel or the CLI.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Iterable

import sentrai_paths  # noqa: E402  (mvp/, put on the path by agent.py)
from app import procscan, threatscan  # noqa: E402

MAX_KEEP = 1000
XOR_KEY = b"SentrAI-quarantine"  # not secret: it only keeps the file from running or matching a scanner


class QuarantineError(Exception):
    pass


def threats_dir(data_dir: Path) -> Path:
    return sentrai_paths.path("agent.threats", data_dir)


def _load(f: Path, default: Any) -> Any:
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _store(f: Path, data: Any) -> None:
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_name(f".{f.name}.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1)
    os.replace(tmp, f)


def finding_id(real_path: str, sha256: str) -> str:
    return hashlib.sha256(f"{os.path.normcase(real_path)}|{sha256}".encode()).hexdigest()[:16]


def remember(data_dir: Path, findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Gives each finding its id, keeps the real path here, and returns the findings without it (for
    the panel)."""
    f = threats_dir(data_dir) / "findings.json"
    known: dict[str, Any] = _load(f, {})
    out = []
    now = time.time()
    for x in findings:
        real = x.get("real_path")
        if real and x.get("sha256"):
            fid = finding_id(real, x["sha256"])
            known[fid] = {"real_path": real, "sha256": x["sha256"], "path": x.get("path"), "label": x.get("label"),
                          "severity": x.get("severity"), "kind": x.get("kind"), "ts": now}
            x = {**x, "id": fid}
        out.append({k: v for k, v in x.items() if k != "real_path"})
    if len(known) > MAX_KEEP:
        known = dict(sorted(known.items(), key=lambda kv: kv[1].get("ts", 0))[-MAX_KEEP:])
    _store(f, known)
    return out


def _scramble(data: bytes) -> bytes:
    k = XOR_KEY * (len(data) // len(XOR_KEY) + 1)
    return bytes(a ^ b for a, b in zip(data, k))


def quarantine(data_dir: Path, fid: str, by: str = "panel") -> dict[str, Any]:
    known: dict[str, Any] = _load(threats_dir(data_dir) / "findings.json", {})
    f = known.get(fid)
    if not f:
        raise QuarantineError(f"{fid or 'that finding'} is not in this machine's findings; scan again")
    src = Path(f["real_path"])
    own = [os.path.normcase(str(d)) for d in threatscan._own_dirs()]
    if any(os.path.normcase(str(src)).startswith(o + os.sep) for o in own):
        raise QuarantineError("that file is in SentrAI's own folders; it is not moved")
    try:
        data = src.read_bytes()
        mode = src.stat().st_mode & 0o7777
    except OSError:
        raise QuarantineError("that file is gone or unreadable now; scan again") from None
    sha = hashlib.sha256(data).hexdigest()
    if sha != f["sha256"]:
        raise QuarantineError("that file changed since it was flagged; scan again before locking it away")
    qdir = threats_dir(data_dir) / "quarantine"
    qdir.mkdir(parents=True, exist_ok=True)
    qid = f"q-{secrets.token_hex(4)}"
    shown = f.get("path") or procscan.hide_home(str(src), procscan._homes())
    meta = {"id": qid, "original": str(src), "path": shown, "name": src.name, "sha256": sha, "size": len(data),
            "mode": mode, "label": f.get("label"), "severity": f.get("severity"), "kind": f.get("kind"),
            "finding": fid, "by": by, "at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    binf = qdir / f"{qid}.bin"
    fd = os.open(str(binf), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(_scramble(data))
        fh.flush()
        os.fsync(fh.fileno())
    _store(qdir / f"{qid}.json", meta)
    try:
        src.unlink()
    except OSError as e:
        binf.unlink(missing_ok=True)
        (qdir / f"{qid}.json").unlink(missing_ok=True)
        raise QuarantineError(f"could not move the file ({e.strerror or type(e).__name__}): the agent may not change "
                              f"files in that folder. On Linux its service writes only to its own folder unless "
                              f"the folder is added to ReadWritePaths (docs/antivirus.md)")
    return {k: v for k, v in meta.items() if k != "original"}


def listed(data_dir: Path) -> list[dict[str, Any]]:
    qdir = threats_dir(data_dir) / "quarantine"
    out = []
    for m in sorted(qdir.glob("q-*.json")) if qdir.is_dir() else []:
        meta = _load(m, None)
        if isinstance(meta, dict) and (qdir / f"{meta.get('id')}.bin").exists():
            out.append({k: v for k, v in meta.items() if k != "original"})
    return out


def restore(data_dir: Path, qid: str, by: str = "panel") -> dict[str, Any]:
    qdir = threats_dir(data_dir) / "quarantine"
    if not qid.startswith("q-") or any(c in qid for c in "/\\."):
        raise QuarantineError(f"{qid or 'that'} is not in this machine's quarantine")
    meta_f, bin_f = qdir / f"{qid}.json", qdir / f"{qid}.bin"
    meta = _load(meta_f, None)
    if not isinstance(meta, dict) or not bin_f.is_file():
        raise QuarantineError(f"{qid} is not in this machine's quarantine")
    dst = Path(meta["original"])
    if dst.exists():
        raise QuarantineError("something else is at the file's old place now; move it first")
    data = _scramble(bin_f.read_bytes())
    if hashlib.sha256(data).hexdigest() != meta.get("sha256"):
        raise QuarantineError("the quarantined copy is damaged; it was left where it is")
    dst.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(dst), os.O_WRONLY | os.O_CREAT | os.O_EXCL, int(meta.get("mode", 0o644)) & 0o777)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    try:
        os.chmod(dst, int(meta.get("mode", 0o644)))
    except OSError:
        pass
    bin_f.unlink()
    meta_f.unlink()
    return {"id": qid, "path": meta.get("path"), "sha256": meta.get("sha256"), "restored_by": by,
            "at": time.strftime("%Y-%m-%dT%H:%M:%S")}
