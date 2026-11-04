"""Append-only, hash-chained audit log stored in SQLite.

hash = sha256(prev_hash + canonical_json({"seq", "ts", "type", "data"}))
UPDATE and DELETE are blocked by triggers; any out-of-band edit breaks verification.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

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
        self.listeners: list[Callable[[], None]] = []  # called after each append (the off-box copy wakes up)
        self._snap: list[dict[str, Any]] = []  # snapshot(): the records read so far, grown instead of re-read
        self._seen: dict[str, Any] = {}  # verify_recent(): when the whole chain was last checked, and how far
        self._checking = False  # verify_recent(wait=False): a full re-check is running in the background
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
        for listener in self.listeners:
            listener()
        return {"seq": seq, "ts": ts, "type": rtype, "data": data, "prev_hash": prev, "hash": h}

    def records_after(self, seq: int, limit: int = 500) -> list[dict[str, Any]]:
        """Up to ``limit`` records after ``seq``, oldest first, as stored (not re-checked)."""
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute("SELECT seq, ts, type, data, prev_hash, hash FROM audit WHERE seq > ? ORDER BY seq"
                                      " LIMIT ?", (seq, limit)).fetchall()
        return [{"seq": q, "ts": ts, "type": t, "data": json.loads(d), "prev_hash": p, "hash": h}
                for q, ts, t, d, p, h in rows]

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

    def snapshot(self) -> list[dict[str, Any]]:
        """Every record, like records(), but only the new ones are read each time. For pages that load often.
        Do not change the list; copy it first."""
        with self._lock:
            while True:
                last = self._snap[-1]["seq"] if self._snap else 0
                more = self.records_after(last, 5000)
                if not more:
                    return self._snap
                self._snap.extend(more)

    def verify_recent(self, max_age: float = 60.0, wait: bool = True) -> tuple[bool, int | None]:
        """verify() for pages that load often: the whole chain is re-hashed at most every ``max_age`` seconds;
        in between, only the records added since are checked, from where the last check ended. A broken
        result is never reused, so a page keeps showing it until the chain is checked and found whole.

        ``wait=False`` (the pages): when the full re-check is due, it runs in the background, a chunk at a time,
        and this answer uses the last one. A long chain then never holds up a page load or new records."""
        with self._lock:
            seen = self._seen
            due = not seen or not seen.get("ok") or time.monotonic() - seen["at"] >= max_age
            if due and (wait or not seen or not seen.get("ok")):
                valid, bad = self.verify()
                head = self.head()
                self._seen = {"ok": valid, "bad": bad, "at": time.monotonic(), "seq": head[0], "hash": head[1]}
                return valid, bad
            if due and not self._checking:
                self._checking = True
                threading.Thread(target=self._full_check, name="audit-full-check", daemon=True).start()
            prev, expected = seen["hash"], seen["seq"] + 1
            for rec in self.records_after(seen["seq"], 100000):
                if rec["seq"] != expected or rec["prev_hash"] != prev or \
                        compute_hash(prev, rec["seq"], rec["ts"], rec["type"], rec["data"]) != rec["hash"]:
                    self._seen = {"ok": False, "bad": rec["seq"], "at": 0.0, "seq": 0, "hash": GENESIS_HASH}
                    return False, rec["seq"]
                prev, expected = rec["hash"], expected + 1
            seen.update(seq=expected - 1, hash=prev)
            return True, None

    def _full_check(self, chunk: int = 5000) -> None:
        """The background full re-check: reads the chain a chunk at a time (the lock is held per chunk only)."""
        try:
            prev, expected, ok, bad = GENESIS_HASH, 1, True, None
            while ok:
                recs = self.records_after(expected - 1, chunk)
                for rec in recs:
                    if rec["seq"] != expected or rec["prev_hash"] != prev or \
                            compute_hash(prev, rec["seq"], rec["ts"], rec["type"], rec["data"]) != rec["hash"]:
                        ok, bad = False, rec["seq"]
                        break
                    prev, expected = rec["hash"], expected + 1
                if len(recs) < chunk:
                    break
            with self._lock:
                if not ok:
                    self._seen = {"ok": False, "bad": bad, "at": 0.0, "seq": 0, "hash": GENESIS_HASH}
                elif self._seen.get("ok"):
                    self._seen["at"] = time.monotonic()  # the records after where it ended are checked as they come
        finally:
            self._checking = False

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
            self._snap, self._seen = [], {}
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
