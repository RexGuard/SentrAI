"""Endpoints for the SentrAI phone app (/mobile/*) and the panel's view of phones (/ui/mobile/*).

The app signs in with POST /mobile/login (or POST /mobile/invite/accept the first time for staff) and then sends
its key as ``Authorization: Bearer sm_...``. main.py's token check lets such a key reach /mobile/* only, and puts
the sign-in on ``request.state.phone``. mobile.py has the rules.
"""
from __future__ import annotations

from typing import Any, Callable

from fastapi import Body, FastAPI, HTTPException, Request

from .config import sentrai_config  # noqa: F401  (config.py puts mvp/ on sys.path)
from . import coach as cm
from . import mobile as mb
from . import ui_risks
import sentrai_accounts as acc  # noqa: E402

# Reached without a key: signing in, and what the sign-in screen needs.
OPEN_ROUTES = frozenset({("GET", "/mobile/hello"), ("POST", "/mobile/login"), ("POST", "/mobile/invite/accept")})


def _address(request: Request) -> str:
    ip = request.client.host if request.client else None
    fwd = request.headers.get("x-forwarded-for", "")
    if ip in (None, "127.0.0.1", "::1") and fwd.strip():
        ip = fwd.split(",")[-1].strip()
    return ip or "local"


def _phone(request: Request) -> dict[str, Any]:
    p = getattr(request.state, "phone", None)
    if not p:
        raise HTTPException(401, "Sign in on the SentrAI app first.")
    return p


def _need(request: Request, what: str) -> str:
    account = getattr(request.state, "account", None)
    if account and not acc.can(account.get("role"), "configure"):
        raise HTTPException(403, f"Only an Owner or Admin can {what}.")
    return (account or {}).get("email") or "dashboard"


def install(app: FastAPI, core: Any, coach: cm.Coach, phones: mb.Mobile, staff: Any,
            org: Callable[[], tuple[str, str]], notice: Callable[[], str]) -> None:
    def err(e: Exception) -> HTTPException:
        return HTTPException(getattr(e, "status", 400), str(e))

    def me_for(p: dict[str, Any]) -> dict[str, Any]:
        name, _ = org()
        account = acc.get(p["email"]) if p["kind"] == "panel" else None
        view = coach.for_phone(p["email"])
        return {"email": p["email"], "kind": p["kind"], "device": p["device"], "organisation": name,
                "role": acc.ROLE_LABEL.get((account or {}).get("role", ""), "Staff"),
                "name": (account or {}).get("name") or view.get("name") or p["email"].split("@")[0],
                "sees_alerts": bool(account and acc.can(account["role"], "view")), "coach": view}

    def signed_in(request: Request, email: str, kind: str, device: Any) -> dict[str, Any]:
        stamp = acc.session_stamp(email) or "" if kind == "panel" else ""
        out = phones.start(email, kind, mb.device_name(device), stamp)
        core.scribe.record(core.name, "phone_signed_in", {"email": email, "kind": kind, "phone": out["id"],
                                                          "address": _address(request)})
        p = {"id": out["id"], "email": email, "kind": kind, "device": mb.device_name(device)}
        return {"key": out["key"], "expires_days": out["expires_days"], "me": me_for(p)}

    # ------------------------------------------------------------------ signing in
    @app.get("/mobile/hello")
    def hello() -> dict[str, Any]:
        """Lets the app check it found a SentrAI panel before anyone signs in. Says nothing about the business."""
        return {"app": "sentrai", "min_password": mb.MIN_PASSWORD}

    @app.post("/mobile/login")
    def login(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """Email and password. Panel accounts also send `code` (authenticator); without it the answer is
        {"need_code": true} and nothing else."""
        ip = _address(request)
        try:
            phones.guard(ip)
        except mb.MobileError as e:
            raise err(e) from e
        email, password = str(body.get("email") or "").strip().lower(), str(body.get("password") or "")
        account = acc.check_password(email, password)
        if account:
            if not account["authenticator"]:
                raise HTTPException(403, "Add an authenticator on the website first, then sign in here.")
            code = str(body.get("code") or "").strip()
            if not code:
                return {"need_code": True}
            if not acc.check_second_factor(email, code):
                phones.failed(ip)
                raise HTTPException(401, "That code is wrong or already used.")
            phones.cleared(ip)
            acc.record_sign_in(email, ip)
            return signed_in(request, account["email"], "panel", body.get("device"))
        if phones.check_staff(email, password) and coach.person(email):
            phones.cleared(ip)
            return signed_in(request, email, "staff", body.get("device"))
        phones.failed(ip)
        raise HTTPException(401, "Wrong email or password.")

    @app.post("/mobile/invite/accept")
    def accept(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """Staff, the first time: the invite code from their admin and a new password."""
        ip = _address(request)
        try:
            phones.guard(ip)
            email = phones.accept(str(body.get("code") or ""), str(body.get("password") or ""))
        except mb.MobileError as e:
            if e.status == 403:
                phones.failed(ip)
            raise err(e) from e
        if not coach.person(email):
            phones.forget(email)
            raise HTTPException(403, "You're no longer on your company's SentrAI list. Ask your admin.")
        phones.cleared(ip)
        return signed_in(request, email, "staff", body.get("device"))

    @app.post("/mobile/logout")
    def logout(request: Request) -> dict[str, Any]:
        p = _phone(request)
        phones.end(p["id"])
        return {"signed_out": True}

    # ------------------------------------------------------------------ the person's own things
    @app.get("/mobile/me")
    def me(request: Request) -> dict[str, Any]:
        return me_for(_phone(request))

    @app.get("/mobile/notice")
    def get_notice(request: Request) -> dict[str, Any]:
        _phone(request)
        return {"text": notice()}

    @app.post("/mobile/notice")
    def confirm_notice(request: Request) -> dict[str, Any]:
        """The person has read the staff notice. Their held coaching notes are then shown."""
        p = _phone(request)
        if not coach.person(p["email"]):
            raise HTTPException(404, "You're not on your company's coaching list.")
        coach.upsert_person({"email": p["email"], "notice_confirmed": True})
        core.scribe.record(core.name, "coach_notice_confirmed", {"email": p["email"], "via": "app"})
        return me_for(p)

    @app.get("/mobile/lessons")
    def lessons(request: Request) -> dict[str, Any]:
        _phone(request)
        return {"lessons": coach.lessons()}

    @app.post("/mobile/moments/{moment_id}")
    def answer_moment(moment_id: str, request: Request, body: dict = Body(...)) -> dict[str, Any]:
        p = _phone(request)
        if coach.moment_person(moment_id) != p["email"]:
            raise HTTPException(404, "No such note.")
        try:
            m = coach.respond(moment_id, str(body.get("answer") or ""), p["email"])
        except cm.CoachError as e:
            raise HTTPException(400, str(e)) from e
        if m["status"] == "needs help":
            core.scribe.record(core.name, "coach_urgent", {"moment": m["id"], "kind": m["kind"],
                                                           "by": "person said it wasn't them (app)"})
        return {"moment": {k: m[k] for k in ("id", "status", "level")}, "me": me_for(p)}

    @app.post("/mobile/lessons/{lesson_id}/answer")
    def answer_lesson(lesson_id: str, request: Request, body: dict = Body(...)) -> dict[str, Any]:
        p = _phone(request)
        try:
            return coach.answer_lesson(p["email"], lesson_id, body.get("answers"))
        except cm.CoachError as e:
            raise HTTPException(400, str(e)) from e

    @app.get("/mobile/my-data")
    def my_data(request: Request) -> dict[str, Any]:
        """Everything SentrAI holds about this person, for them to read."""
        p = _phone(request)
        try:
            held = coach.my_data(p["email"])
        except cm.CoachError:
            held = {}
        return {"coach": held, "phones": [r for r in phones.phones() if r["email"] == p["email"]]}

    @app.post("/mobile/check")
    def check(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """The phone check's yes/no answers. New problems become coaching notes when the coach is switched on
        for the phone app; otherwise only the result is kept."""
        p = _phone(request)
        result, new = phones.record_check(p["id"], body)
        coached = 0
        if new and coach.person(p["email"]):
            events = [{"person": p["email"], "app": "phone", "kind": k, "device": "phone"} for k in new]
            try:
                out = coach.ingest(events)
                coached = out["moments"]
                for u in out["urgent"]:
                    core.scribe.record(core.name, "coach_urgent", {"moment": u["id"], "kind": u["kind"],
                                                                   "by": "phone check"})
            except cm.CoachError:
                pass  # the coach is not switched on yet: the person still sees the result on the phone
        return {"result": result, "problems": mb.problems(result), "new": new, "coached": coached}

    @app.post("/mobile/report")
    def report(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """"Something looks wrong": a staff report from the app, with the person's email as the reporter."""
        p = _phone(request)
        try:
            return staff.submit(body.get("text"), p["email"], p["email"], body.get("where") or "", "app",
                                p["email"])
        except Exception as e:  # noqa: BLE001 - ReportError / RateLimited carry plain words
            raise HTTPException(429 if type(e).__name__ == "RateLimited" else 400, str(e)) from e

    @app.get("/mobile/alerts")
    def alerts(request: Request) -> dict[str, Any]:
        """Owners, Admins and Auditors: the risk, open alerts in plain words, and team totals."""
        p = _phone(request)
        account = acc.get(p["email"]) if p["kind"] == "panel" else None
        if not account or not acc.can(account["role"], "view"):
            raise HTTPException(403, "Alerts are for the business's owners and admins.")
        r = core.risk(history=0)
        incs = [i for i in core.list_incidents() if i.get("status") in ("open", "acknowledged")]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        incs.sort(key=lambda i: (order.get(i.get("severity"), 4), i.get("opened_at") or ""))
        names = getattr(core, "machine_name", lambda h: h)
        rows = [{"id": i["id"], "title": ui_risks.title_case(str(i.get("category") or "alert").replace("_", " ")),
                 "what": ui_risks.plain_happened({**i, "host": names(i["host"]) if i.get("host") else None}),
                 "fix": ui_risks.plain_fix(i), "severity": i.get("severity"), "status": i.get("status"),
                 "needs_review": bool(i.get("needs_review")), "opened_at": i.get("opened_at")} for i in incs[:20]]
        ov = coach.overview()
        return {"risk_index": r.get("risk_index"), "band": r.get("band"), "open": len(incs), "alerts": rows,
                "staff_reports_new": staff.counts().get("new", 0),
                "coach": {"urgent_open": ov["team"]["urgent_open"], "moments_30d": ov["team"]["moments_30d"]},
                "phones": phones.team_checks()}

    # ------------------------------------------------------------------ the panel's side
    @app.get("/ui/mobile")
    def ui_phones(request: Request) -> dict[str, Any]:
        """Signed-in phones. Each phone's check result shows only as team totals unless names are turned on."""
        names = coach.settings()["show_names"]
        rows = phones.phones()
        if not names:
            rows = [{**r, "to_fix": None} for r in rows]
        return {"phones": rows, "team": phones.team_checks(), "show_names": names}

    @app.post("/ui/mobile/invites")
    def ui_invite(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """A one-time app invite for a person on the coach's list. Shown once."""
        who = _need(request, "invite people to the app")
        email = str(body.get("email") or "").strip().lower()
        if not coach.person(email):
            raise HTTPException(404, "Add this person to the Security Coach first.")
        try:
            out = phones.invite(email, who)
        except mb.MobileError as e:
            raise err(e) from e
        core.scribe.record(core.name, "phone_invite_created", {"email": out["email"], "by": who})
        name, _ = org()
        return {**out, "organisation": name,
                "steps": ["Install the SentrAI app on your Android phone.",
                          "Type the panel address your admin gives you.",
                          "Tap \"I have an invite\", then type this code and choose a password."]}

    @app.post("/ui/mobile/{sid}/sign-out")
    def ui_sign_out(sid: str, request: Request) -> dict[str, Any]:
        who = _need(request, "sign a phone out")
        try:
            out = phones.end(sid)
        except mb.MobileError as e:
            raise err(e) from e
        core.scribe.record(core.name, "phone_signed_out", {**out, "by": who})
        return out
