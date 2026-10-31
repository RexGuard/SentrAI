"""The staff report page, open to everyone at the business (no sign-in): <dashboard address>/report.

It shows nothing from SentrAI. It only sends the report and tells the reporter what to do now (the same
reporter-safe answer as the Streamlit page's). The core caps how often one sender may send (staff_reports.py).
SENTRAI_REPORT_CODE asks for a shared code first (put it on the staff noticeboard); SENTRAI_REPORT_PAGE=off
turns the page off.
"""
from __future__ import annotations

import hmac
import os
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request

from .staff_reports import RateLimited, ReportError


def page_on() -> bool:
    return os.environ.get("SENTRAI_REPORT_PAGE", "on").strip().lower() not in ("off", "0", "no", "false")


def sender_of(request: Request) -> str:
    """Who is sending, for the per-sender cap: the address behind a proxy if it says so, else the connection."""
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return forwarded or (request.client.host if request.client else "")


def install(app: FastAPI, core: Any, staff: Any) -> None:
    @app.get("/public/report")
    def get_report_page() -> dict[str, Any]:
        """Whether the page is on, whether it asks for a code, and the machines a report can be about."""
        on = page_on()
        names = [str(m["host"]) for m in core.machines() if isinstance(m, dict) and m.get("host")] if on else []
        return {"on": on, "code_needed": bool(os.environ.get("SENTRAI_REPORT_CODE", "").strip()) if on else False,
                "machines": names}

    @app.post("/public/report")
    def post_report(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        if not page_on():
            raise HTTPException(404, "Reporting from this page is turned off. Please tell your IT contact directly.")
        needed = os.environ.get("SENTRAI_REPORT_CODE", "").strip()
        if needed and not hmac.compare_digest(str(body.get("code") or "").strip().encode(), needed.encode()):
            raise HTTPException(400, "That report code is not right. Ask your manager for it.")
        try:
            return staff.submit(body.get("text"), body.get("reporter"), body.get("contact"), body.get("where"),
                                "dashboard", sender_of(request), body.get("host"))
        except RateLimited as e:
            raise HTTPException(429, str(e)) from e
        except ReportError as e:
            raise HTTPException(400, str(e)) from e
