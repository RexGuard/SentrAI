"""Append-only, hash-chained audit log stored in SQLite.

hash = sha256(prev_hash + canonical_json({"seq", "ts", "type", "data"}))
UPDATE and DELETE are blocked by triggers; any out-of-band edit breaks verification.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def compute_hash(prev_hash: str, seq: int, ts: str, rtype: str, data: Any) -> str:
    body = canonical({"seq": seq, "ts": ts, "type": rtype, "data": data})
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._open()

    def _open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.path), check_same_thread=False)
        # WAL: readers never block the writer, and a crash mid-write cannot corrupt the file.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, ts TEXT NOT NULL, type TEXT NOT NULL,"
            " data TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL)"
        )
        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit"
            " BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END"
        )
        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit"
            " BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END"
        )
        conn.commit()
        self._conn = conn

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    @property
    def conn(self) -> sqlite3.Connection:
        """The open connection, shared with the state store (see state.py)."""
        assert self._conn is not None
        return self._conn

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def append(self, rtype: str, data: dict[str, Any], ts: str) -> dict[str, Any]:
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (row[0] + 1, row[1]) if row else (1, GENESIS_HASH)
            # Round-trip through JSON so the stored form and the hashed form are identical.
            data = json.loads(canonical(data))
            h = compute_hash(prev, seq, ts, rtype, data)
            self._conn.execute(
                "INSERT INTO audit (seq, ts, type, data, prev_hash, hash) VALUES (?,?,?,?,?,?)",
                (seq, ts, rtype, canonical(data), prev, h),
            )
            self._conn.commit()
            return {"seq": seq, "ts": ts, "type": rtype, "data": data, "prev_hash": prev, "hash": h}

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute("SELECT seq, ts, type, data, prev_hash, hash FROM audit ORDER BY seq").fetchall()
        out = []
        for seq, ts, rtype, data, prev, h in rows:
            try:
                parsed = json.loads(data)
            except json.JSONDecodeError:
                parsed = {"_unparseable": data}
            out.append({"seq": seq, "ts": ts, "type": rtype, "data": parsed, "prev_hash": prev, "hash": h})
        return out

    def verify(self) -> tuple[bool, int | None]:
        """Returns (chain_valid, first_bad_seq)."""
        prev = GENESIS_HASH
        expected_seq = 1
        for rec in self.records():
            if rec["seq"] != expected_seq or rec["prev_hash"] != prev:
                return False, rec["seq"]
            if compute_hash(prev, rec["seq"], rec["ts"], rec["type"], rec["data"]) != rec["hash"]:
                return False, rec["seq"]
            prev = rec["hash"]
            expected_seq += 1
        return True, None

    def head_hash(self) -> str:
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS_HASH

    def head(self) -> tuple[int, str]:
        """(seq, hash) of the newest record; (0, GENESIS_HASH) for an empty chain."""
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return (int(row[0]), row[1]) if row else (0, GENESIS_HASH)

    def archive_and_reset(self) -> Path | None:
        """Moves the current DB to data/archive/ (never destroyed) and starts a fresh chain."""
        with self._lock:
            self.close()
            archived = None
            try:
                if self.path.exists():
                    archive_dir = self.path.parent / "archive"
                    archive_dir.mkdir(parents=True, exist_ok=True)
                    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
                    archived = archive_dir / f"{self.path.stem}-{stamp}{self.path.suffix}"
                    self.path.replace(archived)
            finally:
                # Always reopen, even if the rename failed (e.g. file locked on Windows),
                # so later audit writes keep working on the existing chain.
                self._open()
            return archived
