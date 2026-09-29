"""Saves the orchestrator's working state (incidents, actions, notifications) in SQLite.

The state lives in the same database file as the audit chain, in its own tables, so
POST /demo/reset (which archives that file) clears both at once. Each row is one object
stored as JSON; only rows that changed since the last save are written.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .audit import AuditLog

TABLES = ("incidents", "actions", "notifications", "events", "meta")


class StateStore:
    def __init__(self, audit: AuditLog) -> None:
        self.audit = audit
        self._saved: dict[tuple[str, str], str] = {}  # (table, key) -> JSON last written
        self._ready_conn: sqlite3.Connection | None = None

    def _conn(self) -> sqlite3.Connection:
        conn = self.audit.conn
        if conn is not self._ready_conn:  # first use, or the file was archived and reopened
            for t in TABLES:
                conn.execute(f"CREATE TABLE IF NOT EXISTS state_{t} (key TEXT PRIMARY KEY, data TEXT NOT NULL)")
            conn.commit()
            self._ready_conn = conn
            self._saved.clear()
        return conn

    def save(self, rows: dict[str, dict[str, Any]]) -> int:
        """Writes {table: {key: object}}. Returns how many rows changed."""
        with self.audit.lock:
            conn = self._conn()
            changed = []
            for table, objs in rows.items():
                for key, obj in objs.items():
                    data = json.dumps(obj, sort_keys=True, default=str)
                    if self._saved.get((table, key)) != data:
                        changed.append((table, key, data))
            if not changed:
                return 0
            with conn:  # one transaction
                for table, key, data in changed:
                    conn.execute(f"INSERT OR REPLACE INTO state_{table} (key, data) VALUES (?, ?)", (key, data))
            for table, key, data in changed:
                self._saved[(table, key)] = data
            return len(changed)

    def load(self) -> dict[str, dict[str, Any]]:
        with self.audit.lock:
            conn = self._conn()
            out: dict[str, dict[str, Any]] = {}
            for t in TABLES:
                out[t] = {}
                for key, data in conn.execute(f"SELECT key, data FROM state_{t}"):
                    try:
                        out[t][key] = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    self._saved[(t, key)] = data
            return out

    def forget(self) -> None:
        """After a reset: nothing has been written to the new file yet."""
        self._saved.clear()
        self._ready_conn = None
