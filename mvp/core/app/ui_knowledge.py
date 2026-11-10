"""The Company Rules page (/ui/knowledge/*) and what the phone app asks (/mobile/company, /mobile/ask).

knowledge.py has the logic. Every signed-in role can read the rules and try a question; adding or removing guides
and changing quick facts needs `configure` (Owner or Admin). Changes go on the audit record with the guide's
title and size, never its text. Staff in the phone app see only guides marked "for staff".
"""
from __future__ import annotations

from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request

from .config import sentrai_config  # noqa: F401  (config.py puts mvp/ on sys.path)
from . import knowledge as kn
import sentrai_accounts as acc  # noqa: E402


def _who(request: Request, body: dict[str, Any] | None = None) -> str:
    account = getattr(request.state, "account", None)
    return (account or {}).get("email") or str((body or {}).get("operator") or "dashboard")


def _need(request: Request, what: str) -> None:
    account = getattr(request.state, "account", None)
    if account and not acc.can(account.get("role"), "configure"):
        raise HTTPException(403, f"Only an Owner or Admin can {what}.")


def _phone(request: Request) -> dict[str, Any]:
    p = getattr(request.state, "phone", None)
    if not p:
        raise HTTPException(401, "Sign in on the SentrAI app first.")
    return p


def install(app: FastAPI, core: Any, kb: kn.Knowledge) -> None:
    @app.get("/ui/knowledge")
    def overview() -> dict[str, Any]:
        return kb.overview()

    @app.post("/ui/knowledge/guides")
    def add_guide(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        _need(request, "teach SentrAI the company's rules")
        who = _who(request, body)
        try:
            g = kb.add(body, who)
        except kn.KnowledgeError as e:
            raise HTTPException(400, str(e)) from e
        core.scribe.record(core.name, "knowledge_added", {
            "operator": who, "guide": g["id"], "title": g["title"], "kind": g["kind"], "chars": g["chars"],
            "replaced": g["replaced"], "summary": f"{who} taught SentrAI the guide \"{g['title'][:60]}\""})
        return g

    @app.get("/ui/knowledge/guides/{gid}")
    def get_guide(gid: str) -> dict[str, Any]:
        g = kb.guide(gid)
        if g is None:
            raise HTTPException(404, "No guide with that id.")
        return g

    @app.delete("/ui/knowledge/guides/{gid}")
    def remove_guide(gid: str, request: Request) -> dict[str, Any]:
        _need(request, "remove the company's guides")
        who = _who(request)
        try:
            g = kb.remove(gid)
        except KeyError as e:
            raise HTTPException(404, "No guide with that id.") from e
        core.scribe.record(core.name, "knowledge_removed", {
            "operator": who, "guide": g["id"], "title": g["title"],
            "summary": f"{who} removed the guide \"{g['title'][:60]}\""})
        return {"ok": True, "removed": g}

    @app.post("/ui/knowledge/facts")
    def save_facts(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        _need(request, "change the company's quick facts")
        who = _who(request, body)
        try:
            f = kb.save_facts(body, who)
        except kn.KnowledgeError as e:
            raise HTTPException(400, str(e)) from e
        core.scribe.record(core.name, "knowledge_facts_changed", {
            "operator": who, "fields": sorted(k for k in body if k != "operator"),
            "allowed_apps": len(f["allowed_apps"]), "blocked_apps": len(f["blocked_apps"]),
            "systems": len(f["systems"]), "summary": f"{who} changed the company's quick facts"})
        return kb.overview()

    @app.get("/ui/knowledge/ask")
    def try_question(q: str = "", staff: bool = False) -> dict[str, Any]:
        """Try what Sentry and the phone app would find for a question."""
        return kb.answer(q[:500], staff=staff)

    # ------------------------------------------------------------------ the phone app
    @app.get("/mobile/company")
    def company(request: Request) -> dict[str, Any]:
        _phone(request)
        return kb.for_staff()

    @app.post("/mobile/ask")
    def ask(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """A staff question about the company's rules ("Can I use WhatsApp for work?"), answered from its guides."""
        p = _phone(request)
        q = " ".join(str(body.get("question") or "").split())[:500]
        if not q:
            raise HTTPException(400, "Type a question.")
        out = kb.answer(q, staff=p["kind"] == "staff")
        core.scribe.record(core.name, "knowledge_asked", {"via": "app", "found": out["found"],
                                                          "passages": len(out["passages"])})
        return out
