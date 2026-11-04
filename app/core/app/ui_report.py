"""The web dashboard's "Report something suspicious" page, for registered users only.

Whoever is signed in can send a staff report from it: it is sorted and tracked like any staff report (POST
/staff-reports, channel "dashboard") and the person gets the reporter-safe answer: its number, what it sounds
like and what to do now. Like every other endpoint it needs a sign-in (or the API token): nothing here is open.
SENTRAI_REPORT_PAGE=off turns the page off. The core caps how often one sender may send (staff_reports.py);
the sender is the signed-in account.
"""
from __future__ import annotations

import os
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request

from .staff_reports import RateLimited, ReportError


def page_on() -> bool:
    return os.environ.get("SENTRAI_REPORT_PAGE", "on").strip().lower() not in ("off", "0", "no", "false")


def install(app: FastAPI, core: Any, staff: Any) -> None:
    @app.get("/ui/report")
    def get_report_page(request: Request) -> dict[str, Any]:
        """Whether the page is on, who is reporting, and the machines a report can be about."""
        account = getattr(request.state, "account", None) or {}
        on = page_on()
        names = [str(m["host"]) for m in core.machines() if isinstance(m, dict) and m.get("host")] if on else []
        return {"on": on, "reporter": account.get("name") or account.get("email") or "", "machines": names}

    @app.post("/ui/report")
    def post_report(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        if not page_on():
            raise HTTPException(404, "Reporting from this page is turned off. Please tell your IT contact directly.")
        account = getattr(request.state, "account", None) or {}
        who = account.get("email") or "dashboard"
        try:
            return staff.submit(body.get("text"), body.get("reporter") or account.get("name") or who,
                                body.get("contact"), body.get("where"), "dashboard", who, body.get("host"))
        except RateLimited as e:
            raise HTTPException(429, str(e)) from e
        except ReportError as e:
            raise HTTPException(400, str(e)) from e
