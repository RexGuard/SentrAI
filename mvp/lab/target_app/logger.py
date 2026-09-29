"""JSON-lines event logging for the target app.

Each system layer writes to its own ``*.jsonl`` file under the logs
directory. Every line is a self-contained JSON object. The collector tails
these files and normalizes them into the shared Event schema, so the field
names here are deliberately stable.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone, timedelta
from typing import Any

from . import paths

# Singapore time (+08:00) to match the contract's example timestamps.
SGT = timezone(timedelta(hours=8))

_write_lock = threading.Lock()


def now_iso() -> str:
    return datetime.now(SGT).isoformat(timespec="seconds")


def _write(filename: str, record: dict[str, Any]) -> None:
    line = json.dumps(record, ensure_ascii=False)
    path = paths.logs_dir() / filename
    # A single process-wide lock keeps concurrent request threads from
    # interleaving partial lines.
    with _write_lock:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def log_access(src_ip: str, method: str, path_: str, status: int,
               user: str | None = None, pii: bool = False, blocked: bool = False) -> None:
    raw = f"{method} {path_} {status}"
    if user:
        raw += f" user={user}"
    if blocked:  # refused by containment: core rules treat it as benign, not as a new attack
        raw += " blocked by SentrAI"
    _write(paths.ACCESS_LOG, {
        "ts": now_iso(),
        "src_ip": src_ip,
        "user": user,
        "method": method,
        "path": path_,
        "status": status,
        "pii": pii,
        "raw": raw,
    })


def log_auth(src_ip: str, user: str | None, result: str) -> None:
    raw = f"login {result} user={user}"
    _write(paths.AUTH_LOG, {
        "ts": now_iso(),
        "src_ip": src_ip,
        "user": user,
        "result": result,
        "raw": raw,
    })


def log_db(src_ip: str, user: str | None, query: str, rows: int,
           pii: bool = True) -> None:
    raw = f"SELECT rows={rows} q={query!r}"
    _write(paths.DB_LOG, {
        "ts": now_iso(),
        "src_ip": src_ip,
        "user": user,
        "query": query,
        "rows": rows,
        "pii": pii,
        "raw": raw,
    })


def log_os(src_ip: str, user: str | None, message: str) -> None:
    """Record a SIMULATED OS-layer event. Nothing is ever executed."""
    _write(paths.OS_LOG, {
        "ts": now_iso(),
        "src_ip": src_ip,
        "user": user,
        "simulated": True,
        "raw": message,
    })


def log_spine(kind: str, layer: str, src_ip: str, user: str | None, detail: str,
              pii: bool = False) -> None:
    """A tripwire was touched (spines.py). Always an attack signal, never routine."""
    _write(paths.DECEPTION_LOG, {
        "ts": now_iso(),
        "src_ip": src_ip,
        "user": user,
        "kind": kind,
        "layer": layer,
        "pii": pii,
        "raw": f"tripwire {kind}: {detail}",
    })
