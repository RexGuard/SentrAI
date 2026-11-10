"""Website check endpoints (/ui/websites/*). websites.py has the logic.

Every signed-in role can read the list and the latest results. Running a check needs `act` (the sign-in
middleware already refuses writes to read-only roles). Adding, proving and removing a website needs `configure`
(Owner or Admin); in practice SentrAI's team does it with `sentrai websites`. Nothing here is open without
sign-in or the API token.
"""
from __future__ import annotations

from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request

from .config import sentrai_config  # noqa: F401  (config.py puts mvp/ on sys.path)
from . import websites as ws
import sentrai_accounts as acc  # noqa: E402


def _who(request: Request, body: dict[str, Any] | None = None) -> str:
    account = getattr(request.state, "account", None)
    return (account or {}).get("email") or str((body or {}).get("operator") or "dashboard")


def _need(request: Request, what: str) -> None:
    account = getattr(request.state, "account", None)
    if account and not acc.can(account.get("role"), "configure"):
        raise HTTPException(403, f"Only an Owner or Admin can {what}.")


def install(app: FastAPI, sites: ws.Websites) -> None:
    @app.get("/ui/websites")
    def overview() -> dict[str, Any]:
        return sites.overview()

    @app.post("/ui/websites")
    def add(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        _need(request, "add a website")
        try:
            return sites.add(body.get("domain"), _who(request, body))
        except ws.WebsiteError as e:
            raise HTTPException(400, str(e)) from e

    @app.get("/ui/websites/{domain}")
    def latest(domain: str) -> dict[str, Any]:
        try:
            found = sites.latest(domain)
        except ws.WebsiteError as e:
            raise HTTPException(404, str(e)) from e
        if not found:
            raise HTTPException(404, f"{domain} has not been checked yet.")
        return found[0]

    @app.post("/ui/websites/{domain}/verify")
    def verify(domain: str, request: Request, body: dict = Body(default={})) -> dict[str, Any]:
        _need(request, "prove a website")
        try:
            return sites.verify(domain, _who(request, body))
        except ws.WebsiteError as e:
            raise HTTPException(400, str(e)) from e

    @app.post("/ui/websites/{domain}/check")
    def check(domain: str, request: Request, body: dict = Body(default={})) -> dict[str, Any]:
        try:
            return sites.check(domain, _who(request, body))
        except ws.WebsiteError as e:
            raise HTTPException(400, str(e)) from e

    @app.delete("/ui/websites/{domain}")
    def remove(domain: str, request: Request) -> dict[str, Any]:
        _need(request, "remove a website")
        try:
            return sites.remove(domain, _who(request))
        except (ws.WebsiteError, KeyError) as e:
            raise HTTPException(404, f"{domain} is not on the list.") from e
