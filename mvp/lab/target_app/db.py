"""SQLite store with a synthetic ``members`` table.

The data is obviously fake (``Member 0001`` .. ``Member NNNN`` with
``@example.com`` emails) per the contract. The ``/search`` endpoint is
intentionally naive so the lab can demonstrate SQL-injection-looking
queries in the logs; the actual SQL here is still parameter-safe so the
demo box cannot be genuinely damaged.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from . import paths


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path: Path | None = None, count: int = 40) -> None:
    """Create and seed the members table if it does not yet exist."""
    path = path or paths.db_path()
    conn = _connect(path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS members (
                id       INTEGER PRIMARY KEY,
                member_no TEXT NOT NULL,
                name     TEXT NOT NULL,
                email    TEXT NOT NULL,
                program  TEXT NOT NULL
            )
            """
        )
        existing = conn.execute("SELECT COUNT(*) AS c FROM members").fetchone()["c"]
        if existing == 0:
            programs = [
                "Diploma in Cybersecurity",
                "BSc Computing",
                "Diploma in Business",
                "MSc Data Science",
            ]
            rows = []
            for i in range(1, count + 1):
                member_no = f"Member {i:04d}"
                rows.append((
                    i,
                    member_no,
                    member_no,
                    f"member{i:04d}@example.com",
                    programs[i % len(programs)],
                ))
            conn.executemany(
                "INSERT INTO members (id, member_no, name, email, program) "
                "VALUES (?, ?, ?, ?, ?)",
                rows,
            )
        conn.commit()
    finally:
        conn.close()


def set_honeytokens(on: bool, path: Path | None = None) -> None:
    """Add the tripwire bait rows (spines.py) when on, remove them when off."""
    from .spines import HONEYTOKEN_IDS, HONEYTOKEN_ROWS

    path = path or paths.db_path()
    conn = _connect(path)
    try:
        if on:
            conn.executemany(
                "INSERT OR IGNORE INTO members (id, member_no, name, email, program) "
                "VALUES (?, ?, ?, ?, ?)",
                [(i, r["member_no"], r["name"], r["email"], r["program"])
                 for i, r in zip(HONEYTOKEN_IDS, HONEYTOKEN_ROWS)],
            )
        else:
            conn.executemany("DELETE FROM members WHERE id = ?", [(i,) for i in HONEYTOKEN_IDS])
        conn.commit()
    finally:
        conn.close()


def search_members(term: str, path: Path | None = None) -> list[dict]:
    """Search members by name/email substring.

    Parameterized on purpose: the endpoint LOOKS injectable and logs the raw
    query string, but the DB itself is safe (this is a demo lab, not a real
    vulnerable target).
    """
    path = path or paths.db_path()
    conn = _connect(path)
    try:
        like = f"%{term}%"
        cur = conn.execute(
            "SELECT member_no, name, email, program FROM members "
            "WHERE name LIKE ? OR email LIKE ? ORDER BY id LIMIT 50",
            (like, like),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def all_members(path: Path | None = None) -> list[dict]:
    path = path or paths.db_path()
    conn = _connect(path)
    try:
        cur = conn.execute(
            "SELECT member_no, name, email, program FROM members ORDER BY id"
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
