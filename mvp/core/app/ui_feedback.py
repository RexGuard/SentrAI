"""Contact Us: the panel's feedback form, sent to the SentrAI team.

A business owner writes their name, an email or company, and a question, feedback or bug report
(POST /ui/feedback). It is kept on the panel in feedback.json (sentrai_paths "core.feedback"), newest last, and
written to the audit record (who, not what: the message itself stays in the file). The SentrAI team reads it with
`sudo sentrai feedback` (GET /ui/feedback) and marks it done. Nothing leaves the machine from here.
"""
from __future__ import annotations

import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request

from .config import sentrai_config  # noqa: F401  (config.py puts mvp/ on sys.path)
import sentrai_accounts as acc  # noqa: E402

LIMITS = {"name": 120, "contact": 200, "message": 5000}
KEEP = 2000  # the oldest done messages go first past this many
PER_HOUR = 20  # from one signed-in person (or the API token)


class Inbox:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._recent: dict[str, list[float]] = {}

    def all(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def _write(self, rows: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.path)

    def add(self, name: str, contact: str, message: str, by: str) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            hits = [t for t in self._recent.get(by, []) if now - t < 3600]
            if len(hits) >= PER_HOUR:
                raise OverflowError("Too many messages in an hour. Please try again later.")
            self._recent[by] = hits + [now]
            row = {"id": "FB-" + secrets.token_hex(4), "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                   "name": name, "contact": contact, "message": message, "by": by, "done": False}
            rows = self.all() + [row]
            while len(rows) > KEEP:
                old = next((i for i, r in enumerate(rows) if r.get("done")), 0)
                rows.pop(old)
            self._write(rows)
            return row

    def mark(self, ids: list[str], done: bool) -> int:
        with self._lock:
            rows, n = self.all(), 0
            for r in rows:
                if r.get("id") in ids:
                    r["done"], n = done, n + 1
            self._write(rows)
            return n


def clean(body: dict) -> tuple[str, str, str]:
    out = []
    for key, label in (("name", "your name"), ("contact", "an email or company"), ("message", "your message")):
        text = str(body.get(key) or "").strip()
        if not text:
            raise HTTPException(400, f"Please fill in {label}.")
        if len(text) > LIMITS[key]:
            raise HTTPException(400, f"Please keep {label} under {LIMITS[key]} characters.")
        out.append(text)
    return out[0], out[1], out[2]


def install(app: FastAPI, core: Any, inbox: Inbox) -> None:
    @app.post("/ui/feedback")
    def post_feedback(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """Contact Us: {"name", "contact", "message"}. Anyone signed in to the panel may send one."""
        name, contact, message = clean(body)
        account = getattr(request.state, "account", None)
        by = (account or {}).get("email") or "api"
        try:
            row = inbox.add(name, contact, message, by)
        except OverflowError as e:
            raise HTTPException(429, str(e)) from e
        core.scribe.record(core.name, "feedback_sent", {"id": row["id"], "operator": by})
        return {"id": row["id"], "message": "Thank you. Your message is with the SentrAI team, and we will get back to you."}

    @app.get("/ui/feedback")
    def get_feedback(request: Request, all: bool = False) -> dict[str, Any]:  # noqa: A002 - the query name
        """For the SentrAI team (sentrai feedback): open messages, or all of them with ?all=true."""
        account = getattr(request.state, "account", None)
        if account and not acc.can(account.get("role"), "configure"):
            raise HTTPException(403, "Only an Owner or Admin can read the messages.")
        rows = inbox.all()
        return {"feedback": rows if all else [r for r in rows if not r.get("done")], "total": len(rows)}

    @app.post("/ui/feedback/done")
    def post_feedback_done(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """Mark messages handled (or not): {"ids": [...], "done": true}."""
        account = getattr(request.state, "account", None)
        if account and not acc.can(account.get("role"), "configure"):
            raise HTTPException(403, "Only an Owner or Admin can change the messages.")
        ids = [str(i) for i in body.get("ids") or []]
        if not ids:
            raise HTTPException(400, "send {\"ids\": [...]}")
        n = inbox.mark(ids, bool(body.get("done", True)))
        return {"changed": n, "message": f"{n} message{'s' if n != 1 else ''} marked {'done' if body.get('done', True) else 'open'}."}
