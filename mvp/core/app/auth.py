"""Browser sign-in for the web dashboard: password, then authenticator code, then a session cookie.

The accounts, roles and one-time codes are sentrai_accounts' (the same ones the Streamlit console uses).
This module adds what a browser needs on top of the shared API token, which a page must never hold:
a short-lived "pending" cookie between the two steps, a session cookie after them, and the
same 5-tries-per-5-minutes limit per address. Sessions live in memory: a core restart signs everyone out.

A request with a session cookie is treated as that person: reads need a signed-in role, writes need
"act" (Owner/Admin), and a write must carry `X-SentrAI-Web: 1`, which another site cannot add to a request.
"""
from __future__ import annotations

import secrets
import threading
import time
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request, Response

from .config import sentrai_config  # noqa: F401  (config.py puts mvp/ on sys.path)
import sentrai_accounts as acc  # noqa: E402

SESSION_COOKIE = "sentrai_session"
PENDING_COOKIE = "sentrai_pending"
SESSION_S = 12 * 3600
PENDING_S = 5 * 60
FAIL_LIMIT, FAIL_WINDOW_S = 5, 300
WEB_HEADER = "x-sentrai-web"
OPEN_PATHS = frozenset({"/auth/login", "/auth/totp", "/auth/register-owner", "/auth/invite", "/auth/invite/accept",
                        "/auth/state"})

_lock = threading.Lock()
_sessions: dict[str, dict[str, Any]] = {}
_pending: dict[str, dict[str, Any]] = {}
_fails: dict[str, list[float]] = {}


def _address(request: Request) -> str:
    ip = request.client.host if request.client else None
    forwarded = request.headers.get("x-forwarded-for", "")
    if ip in (None, "127.0.0.1", "::1") and forwarded.strip():  # only a local proxy may name the real address
        ip = forwarded.split(",")[-1].strip()
    return ip or "local"


def _wait(ip: str) -> float:
    now = time.time()
    with _lock:
        fails = [t for t in _fails.get(ip, []) if now - t < FAIL_WINDOW_S]
        _fails[ip] = fails
        return 0.0 if len(fails) < FAIL_LIMIT else FAIL_WINDOW_S - (now - fails[0])


def _failed(ip: str) -> None:
    with _lock:
        _fails.setdefault(ip, []).append(time.time())


def _guard(ip: str) -> None:
    wait = _wait(ip)
    if wait:
        raise HTTPException(429, f"Too many wrong tries. Wait {int(wait) // 60 + 1} min and try again.")


def _secure(request: Request) -> bool:
    return request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"


def _set(response: Response, request: Request, name: str, value: str, age: int) -> None:
    response.set_cookie(name, value, max_age=age, httponly=True, samesite="strict", secure=_secure(request), path="/")


def _public(account: dict) -> dict:
    role = str(account.get("role") or "")
    return {"email": account["email"], "name": account.get("name") or "", "role": role,
            "role_label": acc.ROLE_LABEL.get(role, role),
            "permissions": sorted(p for p in ("view", "act", "configure", "export", "people") if acc.can(role, p))}


def session_for(request: Request) -> dict | None:
    """The signed-in account for this request's cookie, or None. Expired sessions are dropped."""
    token = request.cookies.get(SESSION_COOKIE, "")
    with _lock:
        s = _sessions.get(token)
        if s and s["expires"] < time.time():
            del _sessions[token]
            s = None
    if not s:
        return None
    account = acc.get(s["email"])  # removed or reset since signing in: the session ends
    if not account or not account["authenticator"]:
        with _lock:
            _sessions.pop(token, None)
        return None
    return account


def check_cookie_request(request: Request) -> dict | None:
    """Used by the core's token check: the account when the cookie is good, else None.

    Raises 403 for a write the role may not make, or one without the web header."""
    account = session_for(request)
    if account is None:
        return None
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if request.headers.get(WEB_HEADER) != "1":
            raise HTTPException(403, "missing X-SentrAI-Web header")
        if not acc.can(account["role"], "act"):
            raise HTTPException(403, "Your role can read everything but change nothing.")
    return account


def _start_session(response: Response, request: Request, email: str) -> dict:
    ip = _address(request)
    before, where = acc.record_sign_in(email, ip)
    with _lock:
        _fails.pop(ip, None)
    token = secrets.token_urlsafe(32)
    with _lock:
        _sessions[token] = {"email": email, "expires": time.time() + SESSION_S}
    _set(response, request, SESSION_COOKIE, token, SESSION_S)
    response.delete_cookie(PENDING_COOKIE, path="/")
    return {"last_sign_in": before, "last_address": where}


def _pending_email(request: Request) -> str:
    token = request.cookies.get(PENDING_COOKIE, "")
    with _lock:
        p = _pending.get(token)
        if p and p["expires"] < time.time():
            del _pending[token]
            p = None
    if not p or not acc.get(p["email"]):
        raise HTTPException(401, "Sign in again.")
    return p["email"]


def install(app: FastAPI, core_notify=None) -> None:
    """core_notify(email, role_label, address): tells the core who signed in (its admins.py), best effort."""
    def signed(response: Response, request: Request, email: str) -> dict:
        info = _start_session(response, request, email)
        me = acc.get(email) or {}
        if core_notify:
            try:
                core_notify(email, acc.ROLE_LABEL.get(me.get("role", ""), ""), _address(request))
            except Exception:  # noqa: BLE001 - signing in never waits on this
                pass
        return {**info, "me": _public(me)}

    @app.get("/auth/state")
    def state() -> dict:
        """What the sign-in screen needs before anyone is known."""
        return {"has_accounts": acc.has_accounts(), "setup_code_waiting": acc.setup_code_waiting()}

    @app.get("/auth/me")
    def me(request: Request) -> dict:
        account = session_for(request)
        if not account:
            raise HTTPException(401, "not signed in")
        return _public(account)

    @app.post("/auth/login")
    def login(request: Request, response: Response, body: dict = Body(...)) -> dict:
        ip = _address(request)
        _guard(ip)
        email = str(body.get("email") or "")
        account = acc.check_password(email, str(body.get("password") or ""))
        if not account:
            _failed(ip)
            raise HTTPException(401, "Wrong email or password.")
        token = secrets.token_urlsafe(32)
        with _lock:
            _pending[token] = {"email": account["email"], "expires": time.time() + PENDING_S}
        _set(response, request, PENDING_COOKIE, token, PENDING_S)
        return {"next": "code" if account["authenticator"] else "add_authenticator"}

    @app.post("/auth/totp")
    def totp(request: Request, response: Response, body: dict = Body(...)) -> dict:
        ip = _address(request)
        _guard(ip)
        email = _pending_email(request)
        how = acc.check_second_factor(email, str(body.get("code") or "").strip())
        if not how:
            _failed(ip)
            raise HTTPException(401, "That code is wrong or already used.")
        return {**signed(response, request, email), "used": how, "recovery_left": acc.recovery_left(email)}

    @app.post("/auth/authenticator/start")
    def authenticator_start(request: Request) -> dict:
        email = _pending_email(request)
        if acc.get(email)["authenticator"]:
            raise HTTPException(409, "This account already has an authenticator.")
        secret = acc.start_authenticator(email)
        return {"secret": secret, "uri": acc.totp_uri(email, secret)}

    @app.post("/auth/authenticator/confirm")
    def authenticator_confirm(request: Request, response: Response, body: dict = Body(...)) -> dict:
        ip = _address(request)
        _guard(ip)
        email = _pending_email(request)
        try:
            codes = acc.confirm_authenticator(email, str(body.get("code") or "").strip())
        except acc.AccountError as e:
            _failed(ip)
            raise HTTPException(400, str(e)) from e
        return {**signed(response, request, email), "recovery_codes": codes}

    @app.post("/auth/register-owner")
    def register_owner(request: Request, response: Response, body: dict = Body(...)) -> dict:
        ip = _address(request)
        _guard(ip)
        try:
            account = acc.register_owner(str(body.get("code") or ""), str(body.get("name") or ""),
                                         str(body.get("email") or ""), str(body.get("password") or ""))
        except acc.AccountError as e:
            _failed(ip)
            raise HTTPException(400, str(e)) from e
        token = secrets.token_urlsafe(32)
        with _lock:
            _pending[token] = {"email": account["email"], "expires": time.time() + PENDING_S}
        _set(response, request, PENDING_COOKIE, token, PENDING_S)
        return {"next": "add_authenticator"}

    @app.get("/auth/invite")
    def invite(code: str) -> dict:
        found = acc.invite_for(code)
        if not found:
            raise HTTPException(404, "This invite link is wrong or has expired.")
        return found

    @app.post("/auth/invite/accept")
    def invite_accept(request: Request, response: Response, body: dict = Body(...)) -> dict:
        ip = _address(request)
        _guard(ip)
        try:
            account = acc.accept_invite(str(body.get("code") or ""), str(body.get("name") or ""),
                                        str(body.get("password") or ""))
        except acc.AccountError as e:
            _failed(ip)
            raise HTTPException(400, str(e)) from e
        token = secrets.token_urlsafe(32)
        with _lock:
            _pending[token] = {"email": account["email"], "expires": time.time() + PENDING_S}
        _set(response, request, PENDING_COOKIE, token, PENDING_S)
        return {"next": "add_authenticator"}

    @app.post("/auth/logout")
    def logout(request: Request, response: Response) -> dict:
        with _lock:
            _sessions.pop(request.cookies.get(SESSION_COOKIE, ""), None)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"ok": True}

