"""The web dashboard's Team page: who may sign in, with which role. Owners and Admins only, and always a signed-in
person: the shared API token has no account to act as, so it is refused here (sentrai_accounts checks the rest)."""
from __future__ import annotations

from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request

from .config import sentrai_config  # noqa: F401  (config.py puts mvp/ on sys.path)
import sentrai_accounts as acc  # noqa: E402


def install(app: FastAPI) -> None:
    def manager(request: Request) -> dict:
        me = getattr(request.state, "account", None)
        if not me:
            raise HTTPException(403, "Sign in as a person to manage the team.")
        if not acc.can(me["role"], "people"):
            raise HTTPException(403, "Only an Owner or an Admin can manage people.")
        return me

    def ok(fn, *args) -> Any:
        try:
            return fn(*args)
        except acc.AccountError as e:
            raise HTTPException(400, str(e)) from e

    @app.get("/ui/team")
    def get_team(request: Request) -> dict[str, Any]:
        me = manager(request)
        return {"me": me["email"], "my_role": me["role"], "roles": {r: acc.ROLE_LABEL[r] for r in acc.ROLES},
                "invite_hours": acc.INVITE_HOURS,
                "people": [{**p, "role_label": acc.ROLE_LABEL[p["role"]]} for p in acc.people()],
                "invites": acc.pending_invites()}

    @app.post("/ui/team/invite")
    def post_invite(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        me = manager(request)
        email, role = str(body.get("email") or ""), str(body.get("role") or "admin")
        code = ok(acc.invite, me["email"], email, role)
        return {"code": code, "path": f"/?invite={code}",
                "message": f"Invite for {email.strip().lower()} as {acc.ROLE_LABEL[role]}"}

    @app.post("/ui/team/role")
    def post_role(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        me = manager(request)
        email, role = str(body.get("email") or ""), str(body.get("role") or "")
        ok(acc.set_role, me["email"], email, role)
        return {"message": f"{email} is now {acc.ROLE_LABEL[role]}"}

    @app.post("/ui/team/reset")
    def post_reset(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        me = manager(request)
        email = str(body.get("email") or "")
        code = ok(acc.reset, me["email"], email)
        return {"code": code, "path": f"/?invite={code}", "message": f"Reset link for {email}"}

    @app.post("/ui/team/remove")
    def post_remove(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        me = manager(request)
        email = str(body.get("email") or "")
        ok(acc.remove, me["email"], email)
        return {"message": f"{email} can no longer sign in"}

    @app.post("/ui/team/withdraw")
    def post_withdraw(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        me = manager(request)
        ok(acc.withdraw_invite, me["email"], str(body.get("email") or ""))
        return {"message": "Invite withdrawn"}
