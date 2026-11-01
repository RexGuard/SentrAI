"""Cyanide's memory and shared chats.

Memory: standing instructions for every chat ("answer in plain words, our managers are not IT people") and facts the
team taught it ("rexguard is our game server"). Cyanide reads both before every answer; the model can save a fact
with its `remember` tool when someone says "remember that ...", and without a model the chat does the same for a
question that starts with "remember". Instructions need the configure permission (Owner, Admin); facts need act.
Every change goes on the audit record. Kept in chat-memory.json (sentrai_paths "core.chat_memory").

Shared chats: a copy of a conversation, sent to teammates or to everyone on the team, read-only. A copy, because
the live chat log is a rolling window in memory. Kept in chat-shares.json ("core.chat_shares").
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

MAX_FACTS = 100
MAX_FACT_CHARS = 300
MAX_INSTRUCTIONS = 2000
MAX_SHARES = 200
MAX_SHARE_MESSAGES = 100


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class _JsonFile:
    def __init__(self, path: Path, empty: dict[str, Any]):
        self.path, self.empty = Path(path), empty
        self.lock = threading.Lock()

    def read(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else json.loads(json.dumps(self.empty))
        except (OSError, ValueError):
            return json.loads(json.dumps(self.empty))

    def write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)


class Memory(_JsonFile):
    def __init__(self, path: Path):
        super().__init__(path, {"instructions": "", "facts": []})

    def load(self) -> dict[str, Any]:
        d = self.read()
        return {"instructions": str(d.get("instructions") or ""), "facts": list(d.get("facts") or []),
                "updated_at": d.get("updated_at"), "updated_by": d.get("updated_by")}

    def set_instructions(self, text: str, by: str) -> dict[str, Any]:
        with self.lock:
            d = self.load()
            d.update(instructions=str(text or "").strip()[:MAX_INSTRUCTIONS], updated_at=_now(), updated_by=by)
            self.write(d)
        return d

    def add(self, text: str, by: str) -> dict[str, Any]:
        text = " ".join(str(text or "").split())[:MAX_FACT_CHARS]
        if not text:
            raise ValueError("say what Cyanide should remember")
        with self.lock:
            d = self.load()
            same = next((f for f in d["facts"] if f["text"].lower() == text.lower()), None)
            if same:
                return same
            if len(d["facts"]) >= MAX_FACTS:
                raise ValueError(f"Cyanide remembers at most {MAX_FACTS} things; forget one first")
            fact = {"id": "m" + secrets.token_hex(4), "text": text, "by": by, "at": _now()}
            d["facts"].append(fact)
            self.write(d)
        return fact

    def forget(self, fid: str) -> dict[str, Any]:
        with self.lock:
            d = self.load()
            fact = next((f for f in d["facts"] if f["id"] == fid), None)
            if fact is None:
                raise KeyError(f"nothing remembered as {fid}")
            d["facts"] = [f for f in d["facts"] if f["id"] != fid]
            self.write(d)
        return fact

    def prompt(self) -> str:
        """What the model reads before every answer. The team wrote it, but it can quote log text, so it is data."""
        d = self.load()
        parts = []
        if d["instructions"].strip():
            parts.append(f"Standing instructions from the team:\n{d['instructions'].strip()}")
        if d["facts"]:
            parts.append("Things the team asked you to remember:\n" + "\n".join(f"- {f['text']}" for f in d["facts"]))
        return "\n\n".join(parts)

    def about(self, words: str) -> list[str]:
        """Remembered facts that mention any of these words (for answers without a model)."""
        low = [w.lower() for w in words.split() if len(w) > 3]
        return [f["text"] for f in self.load()["facts"] if any(w in f["text"].lower() for w in low)]


class Shares(_JsonFile):
    def __init__(self, path: Path):
        super().__init__(path, {"shares": []})

    def all(self) -> list[dict[str, Any]]:
        return list(self.read().get("shares") or [])

    def create(self, by: str, title: str, to: list[str], messages: list[dict[str, Any]], note: str = "") -> dict[str, Any]:
        if not messages:
            raise ValueError("there is nothing in this chat to share")
        keep = ("id", "role", "text", "ts", "operator", "incident", "source", "blocks", "followups", "attachments",
                "stopped", "suggestions")
        share = {"id": "s" + secrets.token_hex(5), "title": str(title or "Conversation").strip()[:80] or "Conversation",
                 "by": by, "at": _now(), "to": to, "note": str(note or "").strip()[:300],
                 "messages": [{k: m[k] for k in keep if k in m} for m in messages[-MAX_SHARE_MESSAGES:]]}
        with self.lock:
            d = self.read()
            d["shares"] = ([share] + list(d.get("shares") or []))[:MAX_SHARES]
            self.write(d)
        return share

    def remove(self, sid: str, by: str, may_manage: bool) -> dict[str, Any]:
        with self.lock:
            d = self.read()
            share = next((s for s in d.get("shares") or [] if s["id"] == sid), None)
            if share is None:
                raise KeyError(sid)
            if share["by"] != by and not may_manage:
                raise PermissionError("Only the person who shared it, an Owner or an Admin can remove it.")
            d["shares"] = [s for s in d["shares"] if s["id"] != sid]
            self.write(d)
        return share


def _who(request: Request) -> tuple[str, str | None]:
    a = getattr(request.state, "account", None)
    return ((a or {}).get("email") or "dashboard"), (a or {}).get("role")


def _may(role: str | None, permission: str) -> bool:
    return role is None or acc.can(role, permission)  # no account = the shared API token, which may do everything


def _sees(share: dict[str, Any], me: str, role: str | None) -> bool:
    return role is None or share["by"] == me or "everyone" in share["to"] or me in share["to"]


def install(app: FastAPI, core: Any, chat: Any, memory: Memory, shares: Shares) -> None:
    chat.memory = memory

    @app.get("/chat/memory")
    def get_memory() -> dict[str, Any]:
        return memory.load()

    @app.post("/chat/memory")
    def post_memory(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        me, role = _who(request)
        if not _may(role, "configure"):
            raise HTTPException(403, "Only an Owner or an Admin can change Cyanide's standing instructions.")
        d = memory.set_instructions(str(body.get("instructions") or ""), me)
        core.scribe.record(core.name, "chat_memory_changed", {"operator": me, "instructions": d["instructions"][:500],
                                                              "summary": f"{me} changed Cyanide's instructions"})
        return d

    @app.post("/chat/memory/facts")
    def post_fact(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        me, role = _who(request)
        if not _may(role, "act"):
            raise HTTPException(403, "Your role can read Cyanide's memory but not add to it.")
        try:
            fact = memory.add(str(body.get("text") or ""), me)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        core.scribe.record(core.name, "chat_memory_added", {"operator": me, "fact": fact,
                                                            "summary": f"{me} taught Cyanide: {fact['text'][:60]}"})
        return fact

    @app.delete("/chat/memory/facts/{fid}")
    def delete_fact(fid: str, request: Request) -> dict[str, Any]:
        me, role = _who(request)
        if not _may(role, "act"):
            raise HTTPException(403, "Your role can read Cyanide's memory but not change it.")
        try:
            fact = memory.forget(fid)
        except KeyError as e:
            raise HTTPException(404, str(e).strip("'")) from e
        core.scribe.record(core.name, "chat_memory_forgot", {"operator": me, "fact": fact,
                                                             "summary": f"{me} made Cyanide forget: {fact['text'][:60]}"})
        return {"ok": True, "forgot": fact}

    @app.get("/chat/shares")
    def get_shares(request: Request) -> dict[str, Any]:
        me, role = _who(request)
        mine = [s for s in shares.all() if _sees(s, me, role)]
        return {"me": me, "shares": [{k: v for k, v in s.items() if k != "messages"} | {"count": len(s["messages"])}
                                     for s in mine]}

    @app.get("/chat/shares/{sid}")
    def get_share(sid: str, request: Request) -> dict[str, Any]:
        me, role = _who(request)
        share = next((s for s in shares.all() if s["id"] == sid), None)
        if share is None or not _sees(share, me, role):
            raise HTTPException(404, "No shared chat with that link, or it was not shared with you.")
        return share

    @app.post("/chat/shares")
    def post_share(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        me, _ = _who(request)
        to = [str(t).strip().lower() for t in (body.get("to") or []) if str(t).strip()][:20] or ["everyone"]
        known = {p["email"] for p in acc.people()}
        unknown = [t for t in to if t != "everyone" and t not in known]
        if unknown and known:
            raise HTTPException(400, f"No dashboard account for {', '.join(unknown)}.")
        want = {str(i) for i in (body.get("message_ids") or [])}
        with chat.lock:
            picked = [dict(m) for m in chat.history if str(m["id"]) in want]
        try:
            share = shares.create(me, str(body.get("title") or ""), to, picked, str(body.get("note") or ""))
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        core.scribe.record(core.name, "chat_shared", {"operator": me, "share": share["id"], "to": to,
                                                      "messages": len(share["messages"]), "title": share["title"],
                                                      "summary": f"{me} shared a chat with {', '.join(to)}"})
        return {k: v for k, v in share.items() if k != "messages"} | {"count": len(share["messages"])}

    @app.delete("/chat/shares/{sid}")
    def delete_share(sid: str, request: Request) -> dict[str, Any]:
        me, role = _who(request)
        try:
            share = shares.remove(sid, me, _may(role, "people"))
        except KeyError as e:
            raise HTTPException(404, "No shared chat with that link.") from e
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        core.scribe.record(core.name, "chat_unshared", {"operator": me, "share": sid,
                                                        "summary": f"{me} removed a shared chat"})
        return {"ok": True}
