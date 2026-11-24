"""Endpoints for the SentrAI phone app (/mobile/*) and the panel's view of phones (/ui/mobile/*).

The app signs in with POST /mobile/login (or POST /mobile/invite/accept the first time for staff, or
POST /mobile/register for anyone's own account, which waits until the company lets the person in) and then sends
its key as ``Authorization: Bearer sm_...``. main.py's token check lets such a key reach /mobile/* only, and puts
the sign-in on ``request.state.phone``. mobile.py has the rules.
"""
from __future__ import annotations

import logging
import os
from email.message import EmailMessage
from email.utils import make_msgid
from typing import Any, Callable

from fastapi import Body, FastAPI, HTTPException, Request

from .config import sentrai_config  # noqa: F401  (config.py puts mvp/ on sys.path)
from . import coach as cm
from . import mobile as mb
from . import ui_risks
import sentrai_accounts as acc  # noqa: E402

log = logging.getLogger("sentrai.mobile")

# Reached without a key: signing in, and what the sign-in screen needs.
OPEN_ROUTES = frozenset({("GET", "/mobile/hello"), ("POST", "/mobile/login"), ("POST", "/mobile/invite/accept"),
                         ("POST", "/mobile/register")})
INVITE_STEPS = ["Install the SentrAI app on your Android phone.",
                "Type the panel address your admin gives you.",
                "Already signed up in the app? Type this code on the \"Waiting\" screen. Otherwise tap "
                "\"I have an invite\", then type this code and choose a password."]


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


def mail_settings() -> dict[str, str] | None:
    """Where invite emails go out: the company's own mail server, else the SentrAI mail relay; None when neither."""
    from . import ui_feedback
    own = ui_feedback.mail_settings()
    if own.get("SMTP_HOST"):
        return {**own, "FROM": own.get("ALERT_EMAIL_FROM") or own.get("SMTP_USER") or f"sentrai@{own['SMTP_HOST']}"}
    host = os.environ.get("SENTRAI_RELAY_SMTP_HOST", "").strip()
    if not host:
        return None
    r = {k: os.environ.get("SENTRAI_RELAY_SMTP_" + k, "").strip() for k in ("PORT", "SECURITY", "USER", "PASSWORD")}
    return {"SMTP_HOST": host, "SMTP_PORT": r["PORT"], "SMTP_SECURITY": r["SECURITY"], "SMTP_USER": r["USER"],
            "SMTP_PASSWORD": r["PASSWORD"],
            "FROM": os.environ.get("SENTRAI_RELAY_FROM", "").strip() or r["USER"] or f"sentrai@{host}"}


def invite_mail(invite: dict[str, Any], organisation: str, by_name: str, address: str) -> EmailMessage:
    """The invite email. The code only, no links: a link in a security product's email is what phishing looks like."""
    msg = EmailMessage()
    who = organisation or "Your company"
    msg["Subject"] = f"Your SentrAI app invite from {who}"
    msg["To"] = invite["email"]
    msg["Message-ID"] = make_msgid(domain="sentrai")
    hello = f"Hi {invite['name'].split(' ')[0]}," if invite.get("name") else "Hi,"
    msg.set_content("\n".join([
        hello, "", f"{by_name or 'Your admin'} at {who} has invited you to the SentrAI app, which helps you stay "
        "safe at work.", "", f"Your invite code: {invite['code']}",
        f"It works once, until {invite['expires_at'].replace('T', ' ')[:16]} UTC.", "",
        *(f"{n}. {x}" for n, x in enumerate(INVITE_STEPS, 1)),
        *([f"", f"Panel address: {address}"] if address else []), "",
        "If you weren't expecting this, you can ignore it. SentrAI never asks for your password by email.", "",
        "-- SentrAI"]))
    return msg


def install(app: FastAPI, core: Any, coach: cm.Coach, phones: mb.Mobile, staff: Any,
            org: Callable[[], tuple[str, str]], notice: Callable[[], str], sender: Any = None) -> None:
    def err(e: Exception) -> HTTPException:
        return HTTPException(getattr(e, "status", 400), str(e))

    def inside(p: dict[str, Any]) -> bool:
        """A panel account, or someone the company has let in. Waiting sign-ups see nothing of the company."""
        return p["kind"] == "panel" or (coach.person(p["email"]) is not None and not phones.is_waiting(p["email"]))

    def member(request: Request) -> dict[str, Any]:
        p = _phone(request)
        if not inside(p):
            raise HTTPException(403, "Your company hasn't let you in yet. Type the invite code your admin sends you.")
        return p

    def me_for(p: dict[str, Any]) -> dict[str, Any]:
        if not inside(p):
            return {"email": p["email"], "kind": p["kind"], "device": p["device"], "organisation": "",
                    "role": "Waiting", "name": phones.name_of(p["email"]) or p["email"].split("@")[0],
                    "sees_alerts": False, "manages_team": False, "waiting": True, "coach": {"in_coach": False}}
        name, _ = org()
        account = acc.get(p["email"]) if p["kind"] == "panel" else None
        view = coach.for_phone(p["email"])
        return {"email": p["email"], "kind": p["kind"], "device": p["device"], "organisation": name,
                "role": acc.ROLE_LABEL.get((account or {}).get("role", ""), "Staff"),
                "name": (account or {}).get("name") or view.get("name") or p["email"].split("@")[0],
                "sees_alerts": bool(account and acc.can(account["role"], "view")),
                "manages_team": bool(account and acc.can(account["role"], "configure")), "waiting": False,
                "coach": view}

    def let_in(email: str, name: str = "") -> None:
        """Someone used their invite: put them on the coach's list (where everything else knows them from)."""
        if not coach.person(email):
            try:
                coach.upsert_person({"email": email, **({"name": name} if name else {})})
            except cm.CoachError:
                pass

    def make_invite(email: str, name: str, by: str, by_name: str) -> dict[str, Any]:
        email = str(email or "").strip().lower()
        if acc.get(email):
            raise HTTPException(409, "This person has a SentrAI website account: they sign in to the app with it, "
                                     "no invite needed.")
        if phones.has_password(email) and not phones.is_waiting(email) and coach.person(email):
            raise HTTPException(409, "This person is already in the app.")
        try:
            out = phones.invite(email, by, name or (coach.person(email) or {}).get("name", ""))
        except mb.MobileError as e:
            raise err(e) from e
        organisation, _ = org()
        out = {**out, "name": out.get("name") or phones.name_of(out["email"]), "organisation": organisation,
               "steps": INVITE_STEPS, "emailed": False}
        e = mail_settings()
        if e:
            msg = invite_mail(out, organisation, by_name, os.environ.get("SENTRAI_DASHBOARD_URL", "").strip())
            msg["From"] = e["FROM"]
            try:
                from . import ui_feedback
                (sender or ui_feedback.send_mail)(msg, e)
                out["emailed"] = True
            except Exception as exc:  # noqa: BLE001 - the code is still shown to the inviter
                log.warning("App invite for %s made but not emailed: %s", out["email"], exc)
                out["email_error"] = "The email didn't go out. Give the person the code yourself."
        core.scribe.record(core.name, "phone_invite_created", {"email": out["email"], "by": by,
                                                               "emailed": out["emailed"]})
        return out

    def team() -> dict[str, Any]:
        return {"open_signup": phones.signup_open, "waiting": phones.waiting(), "invites": phones.invites(),
                "max_waiting": mb.MAX_WAITING, "waiting_days": mb.WAITING_DAYS}

    def turn_away(email: str, by: str) -> dict[str, Any]:
        email = str(email or "").strip().lower()
        if not phones.is_waiting(email):
            raise HTTPException(404, "Nobody is waiting with that email.")
        gone = phones.forget(email)
        core.scribe.record(core.name, "phone_signup_turned_away", {"email": email, "by": by})
        return {"email": email, "removed": gone}

    def set_signup(on: Any, by: str) -> dict[str, Any]:
        if not isinstance(on, bool):
            raise HTTPException(400, 'Send {"on": true} or {"on": false}.')
        phones.set_signup(on, by)
        core.scribe.record(core.name, "phone_signup_switched", {"on": on, "by": by})
        return team()

    def manager(request: Request) -> tuple[str, str]:
        """The signed-in phone of an Owner or Admin: (email, name)."""
        p = _phone(request)
        account = acc.get(p["email"]) if p["kind"] == "panel" else None
        if not account or not acc.can(account["role"], "configure"):
            raise HTTPException(403, "Only an Owner or Admin can manage who is in the app.")
        return account["email"], account.get("name") or account["email"]

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
        return {"app": "sentrai", "min_password": mb.MIN_PASSWORD, "open_signup": phones.signup_open}

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
        if phones.check_staff(email, password):
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
        let_in(email, phones.name_of(email))
        phones.cleared(ip)
        core.scribe.record(core.name, "phone_invite_used", {"email": email})
        return signed_in(request, email, "staff", body.get("device"))

    @app.post("/mobile/register")
    def register(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """Anyone's own app account: {"email", "password", "name"}. It waits, seeing nothing of the company, until
        an Owner or Admin sends the person an invite and they type its code (POST /mobile/join)."""
        ip = _address(request)
        if acc.get(str(body.get("email") or "").strip().lower()):
            raise HTTPException(409, "This email has a SentrAI website account. Sign in with it instead.")
        try:
            phones.guard(ip)
            email = phones.register(str(body.get("email") or ""), str(body.get("password") or ""),
                                    str(body.get("name") or ""), ip)
        except mb.MobileError as e:
            raise err(e) from e
        core.scribe.record(core.name, "phone_signup", {"email": email, "address": ip})
        return signed_in(request, email, "staff", body.get("device"))

    @app.post("/mobile/join")
    def join(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """A waiting person types the invite code that was sent to their email."""
        p = _phone(request)
        ip = _address(request)
        try:
            phones.guard(ip)
            inv = phones.join(p["email"], str(body.get("code") or ""))
        except mb.MobileError as e:
            if e.status == 403:
                phones.failed(ip)
            raise err(e) from e
        phones.cleared(ip)
        let_in(p["email"], phones.name_of(p["email"]) or inv.get("name", ""))
        core.scribe.record(core.name, "phone_invite_used", {"email": p["email"], "phone": p["id"]})
        return me_for(p)

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
        member(request)
        return {"text": notice()}

    @app.post("/mobile/notice")
    def confirm_notice(request: Request) -> dict[str, Any]:
        """The person has read the staff notice. Their held coaching notes are then shown."""
        p = member(request)
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
        p = member(request)
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
        p = member(request)
        try:
            return coach.answer_lesson(p["email"], lesson_id, body.get("answers"))
        except cm.CoachError as e:
            raise HTTPException(400, str(e)) from e

    @app.get("/mobile/my-data")
    def my_data(request: Request) -> dict[str, Any]:
        """Everything SentrAI holds about this person, for them to read."""
        p = _phone(request)
        if not inside(p):  # a sign-up's email isn't proven yet: only this sign-in and what they typed
            return {"coach": {}, "account": {"email": p["email"], "name": phones.name_of(p["email"]),
                                             "waiting": True},
                    "phones": [r for r in phones.phones() if r["id"] == p["id"]]}
        try:
            held = coach.my_data(p["email"])
        except cm.CoachError:
            held = {}
        return {"coach": held, "phones": [r for r in phones.phones() if r["email"] == p["email"]]}

    @app.post("/mobile/check")
    def check(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """The phone check's yes/no answers. New problems become coaching notes when the coach is switched on
        for the phone app; otherwise only the result is kept. Waiting sign-ups check their phone on the phone only."""
        p = member(request)
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
        p = member(request)
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
                "phones": phones.team_checks(), "signups_waiting": len(phones.waiting())}

    # ------------------------------------------------------------------ owners and admins: who is in the app
    @app.get("/mobile/team")
    def mobile_team(request: Request) -> dict[str, Any]:
        manager(request)
        return team()

    @app.post("/mobile/team/invite")
    def mobile_invite(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """Invite someone, or let in someone who signed up: {"email", "name"?}. The code is emailed when a mail
        server or the SentrAI relay is set, and shown here once either way."""
        by, by_name = manager(request)
        return make_invite(body.get("email"), str(body.get("name") or ""), by, by_name)

    @app.post("/mobile/team/turn-away")
    def mobile_turn_away(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        by, _ = manager(request)
        return turn_away(body.get("email"), by)

    @app.post("/mobile/team/signup")
    def mobile_signup(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """Turn open sign-up on or off: {"on": true|false}."""
        by, _ = manager(request)
        return set_signup(body.get("on"), by)

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
        """A one-time app invite: {"email", "name"?}. Using it puts the person on the coach's list. Shown once, and
        emailed when mail is set up."""
        who = _need(request, "invite people to the app")
        account = getattr(request.state, "account", None) or {}
        return make_invite(body.get("email"), str(body.get("name") or ""), who, account.get("name") or "")

    @app.get("/ui/mobile/signups")
    def ui_signups(request: Request) -> dict[str, Any]:
        """Open sign-up on or off, people waiting to be let in, and open invites."""
        return team()

    @app.post("/ui/mobile/signups")
    def ui_signup_switch(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        return set_signup(body.get("on"), _need(request, "change who may sign up"))

    @app.post("/ui/mobile/signups/turn-away")
    def ui_turn_away(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        return turn_away(body.get("email"), _need(request, "turn people away"))

    @app.post("/ui/mobile/{sid}/sign-out")
    def ui_sign_out(sid: str, request: Request) -> dict[str, Any]:
        who = _need(request, "sign a phone out")
        try:
            out = phones.end(sid)
        except mb.MobileError as e:
            raise err(e) from e
        core.scribe.record(core.name, "phone_signed_out", {**out, "by": who})
        return out
