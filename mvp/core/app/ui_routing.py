"""What the web dashboard's "Who gets what" editor needs: the routing as the map editor draws it, and its Save.

GET /ui/routing is the console's routing_editor_data() (canvas_model, the Streamlit console's own function); the
save turns the editor's file back with routing_from_editor() and gives it to the core's own validation, which
refuses a bad file with the reason a person can act on.
"""
from __future__ import annotations

from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request

import sentrai_accounts as acc  # noqa: E402
from . import canvas_model as cm


def install(app: FastAPI, core: Any) -> None:
    @app.get("/ui/routing")
    def get_routing_page(request: Request) -> dict[str, Any]:
        account = getattr(request.state, "account", None)
        off = bool(account) and not acc.can(account.get("role"), "configure")
        routing = core.routing_public()
        return {"source": routing.get("source"),
                "escalate_after": (routing.get("follow_up") or {}).get("escalate_after_reminders"),
                "editor": cm.routing_editor_data(routing, read_only=off,
                                                 lock_reason="Your role can read everything but change nothing." if off else "")}

    @app.post("/ui/routing")
    def post_routing_page(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """The editor's Save: {"routing": {...}, "summary": "..."}; the whole routing file is replaced."""
        account = getattr(request.state, "account", None)
        if account and not acc.can(account.get("role"), "configure"):
            raise HTTPException(403, "Your role can read everything but change nothing.")
        operator = (account or {}).get("email") or str(body.get("operator") or "dashboard")
        summary = str(body.get("summary") or "")[:300]
        try:
            core.routing_update(cm.routing_from_editor(body.get("routing")), operator, summary)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"message": f"Saved. {summary}".strip()}
