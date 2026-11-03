"""Feature ideas: what people asked Sentry for that SentrAI cannot do yet, for the SentrAI team.

When someone asks the chat for something no tool or button covers ("Clean up the overdue risks for the shop
laptop", "email me a report every Monday"), Sentry says plainly that SentrAI cannot do that yet and notes it here
as a feature idea. With an AI model, the model decides (its `suggest_feature` tool); without one, a request that
none of the fixed answers understood is noted (chat.py `_fallback`).

The same idea asked again is grouped: the count goes up, the newest wording is kept as an example, and the
people who asked are counted. Only the person's own words are kept, never attached files or log lines, and they
are cleaned first: addresses, emails, file paths and anything that looks like a key or password are taken out.

Kept in feature-ideas.json (sentrai_paths "core.feature_ideas"). The SentrAI team reads them with
`sudo sentrai ideas` (GET /ui/feature-ideas) and marks each one planned, done or dismissed.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request

from .config import sentrai_config  # noqa: F401  (config.py puts mvp/ on sys.path)
import sentrai_accounts as acc  # noqa: E402

MAX_IDEAS = 500
MAX_EXAMPLES = 3
MAX_TITLE = 100
MAX_TEXT = 240
STATUSES = ("new", "planned", "done", "dismissed")
SAME = 0.6  # share of meaningful words two ideas must have in common to count as the same one

_SECRETISH = re.compile(r"(?i)\b(password|passwd|pwd|token|secret|api[ _-]?key|key)\s*[:=]?\s*\S+")
_SCRUB = (
    (re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"), "[email]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?::\d+)?\b"), "[address]"),
    (re.compile(r"\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b", re.I), "[address]"),
    (re.compile(r"https?://\S+"), "[link]"),
    (re.compile(r"(?:[A-Za-z]:\\|~?/)[^\s]*[\\/][^\s]*"), "[path]"),
    (re.compile(r"\b(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])[A-Za-z0-9_\-]{20,}\b"), "[hidden]"),
)
_STOP = set("""a an the and or of for to in on at by with from my our me us we i you your it its this that these
those please can could would will should do does did is are be been am want wanted like need help make sure just also
some any all every each so then than them they there here sentry sentrai have has had let get how what when which who
""".split())


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def clean(text: Any, limit: int = MAX_TEXT) -> str:
    """The person's words without addresses, emails, paths, links or anything that looks like a secret."""
    s = " ".join(str(text or "").split())
    s = _SECRETISH.sub(lambda m: f"{m.group(1)} [hidden]", s)
    for pattern, repl in _SCRUB:
        s = pattern.sub(repl, s)
    if len(s) > limit:
        s = s[:limit - 1].rstrip() + "…"
    return s


def _words(text: str) -> set[str]:
    out = set()
    for w in re.findall(r"[a-z]+", text.lower()):
        if len(w) < 3 or w in _STOP:
            continue
        for end in ("ing", "ed", "es", "s"):
            if w.endswith(end) and len(w) - len(end) >= 3:
                w = w[:-len(end)]
                break
        out.add(w)
    return out


def similar(a: str, b: str) -> bool:
    wa, wb = _words(a), _words(b)
    if not wa or not wb:
        return a.strip().lower() == b.strip().lower()
    return len(wa & wb) / min(len(wa), len(wb)) >= SAME and len(wa & wb) / len(wa | wb) >= SAME / 2


class Ideas:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.lock = threading.Lock()

    def all(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            rows = data.get("ideas") if isinstance(data, dict) else None
            return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
        except (OSError, ValueError):
            return []

    def _write(self, rows: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"ideas": rows}, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.path)

    def note(self, title: str, request: str, by: str, why: str = "", source: str = "chat") -> dict[str, Any]:
        """Add an idea, or count one more ask of the same idea. Returns the idea with `"new": True` when it is new."""
        title = clean(title, MAX_TITLE)
        request = clean(request)
        if not title:
            title = clean(request, MAX_TITLE)
        if not title:
            raise ValueError("say what the feature would do")
        why = clean(why)
        now = _now()
        with self.lock:
            rows = self.all()
            same = next((r for r in rows if r.get("status") != "done" and (
                similar(title, r.get("title", "")) or any(similar(request, x) for x in r.get("examples", []))
                or similar(request, r.get("title", "")))), None)
            if same is not None:
                same["count"] = int(same.get("count") or 1) + 1
                same["last_at"] = now
                people = list(same.get("people") or [])
                if by and by not in people:
                    people = (people + [by])[-50:]
                same["people"] = people
                if request and request not in same.get("examples", []):
                    same["examples"] = ([request] + list(same.get("examples") or []))[:MAX_EXAMPLES]
                if same.get("status") == "dismissed":
                    same["status"] = "new"  # asked again after it was put aside: worth another look
                self._write(rows)
                return dict(same, new=False)
            idea = {"id": "FI-" + secrets.token_hex(3), "title": title, "why": why, "status": "new", "count": 1,
                    "people": [by] if by else [], "examples": [request] if request else [], "source": source,
                    "first_at": now, "last_at": now}
            rows.append(idea)
            if len(rows) > MAX_IDEAS:  # drop the oldest finished ones first, then the oldest asked-once ones
                for keep_out in (lambda r: r.get("status") in ("done", "dismissed"), lambda r: r.get("count", 1) <= 1):
                    while len(rows) > MAX_IDEAS and (i := next((k for k, r in enumerate(rows) if keep_out(r)), None)) is not None:
                        rows.pop(i)
                del rows[:-MAX_IDEAS]
            self._write(rows)
            return dict(idea, new=True)

    def listing(self, include_closed: bool = False) -> list[dict[str, Any]]:
        rows = [r for r in self.all() if include_closed or r.get("status") in ("new", "planned")]
        rows.sort(key=lambda r: (int(r.get("count") or 1), str(r.get("last_at") or "")), reverse=True)  # most asked first
        return [dict(r, asked_by=len(r.get("people") or [])) for r in rows]

    def set_status(self, ids: list[str], status: str, by: str, note: str = "") -> int:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        want = set(ids)
        changed = 0
        with self.lock:
            rows = self.all()
            for r in rows:
                if r.get("id") in want:
                    r.update(status=status, status_by=by, status_at=_now())
                    if note:
                        r["note"] = clean(note, 300)
                    changed += 1
            if changed:
                self._write(rows)
        return changed


def _who(request: Request) -> tuple[str, str | None]:
    a = getattr(request.state, "account", None)
    return ((a or {}).get("email") or "cli"), (a or {}).get("role")


def install(app: FastAPI, core: Any, chat: Any, ideas: Ideas) -> None:
    chat.ideas = ideas

    @app.get("/ui/feature-ideas")
    def get_ideas(all: bool = False) -> dict[str, Any]:  # noqa: A002 - matches ?all=true elsewhere
        rows = ideas.listing(all)
        return {"ideas": rows, "count": len(rows)}

    @app.post("/ui/feature-ideas/status")
    def post_status(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        me, role = _who(request)
        if role is not None and not acc.can(role, "configure"):
            raise HTTPException(403, "Only an Owner or an Admin can change feature ideas.")
        ids = [str(i) for i in (body.get("ids") or []) if str(i).strip()][:100]
        status = str(body.get("status") or "")
        if not ids:
            raise HTTPException(400, "which ideas? (ids)")
        try:
            n = ideas.set_status(ids, status, str(body.get("operator") or me), str(body.get("note") or ""))
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        core.scribe.record(core.name, "feature_idea_status", {"operator": str(body.get("operator") or me), "ids": ids,
                                                              "status": status,
                                                              "summary": f"{len(ids)} feature idea(s) marked {status}"})
        return {"changed": n, "message": f"{n} idea{'s' if n != 1 else ''} marked {status}."}
