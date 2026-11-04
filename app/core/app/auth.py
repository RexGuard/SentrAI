"""Browser sign-in for the web dashboard: password, then authenticator code, then a session cookie.

The accounts, roles and one-time codes are sentrai_accounts' (the same ones the Streamlit console uses).
This module adds what a browser needs on top of the shared API token, which a page must never hold:
a short-lived "pending" cookie between the two steps, a session cookie after them, and the
same 5-tries-per-5-minutes limit per address.

Sessions are kept in web-sessions.json in the core's folder ("core.web_sessions"), so a restart or an update
(`sentrai-update`) does not sign anyone out. The file holds only a SHA-256 of each cookie, never the cookie
itself, plus a fingerprint of the password and authenticator (sentrai_accounts.session_stamp): a new password,
an authenticator reset or a removed account ends that person's sessions.
It is written readable by the service user only. Half-finished sign-ins (the pending cookie) stay in memory.

A request with a session cookie is treated as that person: reads need a signed-in role, writes need
"act" (Owner/Admin), and a write must carry `X-SentrAI-Web: 1`, which another site cannot add to a request.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request, Response

from .config import sentrai_config  # noqa: F401  (config.py puts app/ on sys.path)
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
_sessions: dict[str, dict[str, Any]] = {}  # SHA-256 of the cookie -> {"email", "expires", "pw": stamp}
_store: Path | None = None  # where _sessions is saved; None keeps them in memory only
_pending: dict[str, dict[str, Any]] = {}
_fails: dict[str, list[float]] = {}


def _key(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _save() -> None:
    """Write the sessions to the store. Call with _lock held. Best effort: a failed write only means a
    restart would sign people out, as before."""
    if _store is None:
        return
    try:
        _store.parent.mkdir(parents=True, exist_ok=True)
        tmp = _store.with_name(_store.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"sessions": _sessions}, f)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, _store)
    except OSError:
        pass


def _load(store: Path | None) -> None:
    """Use `store` for sessions from now on, and bring back the unexpired ones saved there."""
    global _store
    now = time.time()
    kept: dict[str, dict[str, Any]] = {}
    if store is not None:
        try:
            data = json.loads(store.read_text(encoding="utf-8"))
            saved = data.get("sessions") if isinstance(data, dict) else None
        except (OSError, ValueError):
            saved = None
        for key, s in (saved or {}).items():
            if (isinstance(s, dict) and isinstance(s.get("email"), str) and isinstance(s.get("pw"), str)
                    and isinstance(s.get("expires"), (int, float)) and s["expires"] > now):
                kept[key] = {"email": s["email"], "expires": float(s["expires"]), "pw": s["pw"]}
    with _lock:
        _store = store
        _sessions.clear()
        _sessions.update(kept)
        if store is not None:
            _save()  # drops the expired ones from the file too


def _drop(key: str) -> None:
    with _lock:
        if _sessions.pop(key, None) is not None:
            _save()


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
    if not token:
        return None
    key = _key(token)
    with _lock:
        s = _sessions.get(key)
    if not s:
        return None
    if s["expires"] < time.time():
        _drop(key)
        return None
    account = acc.get(s["email"])  # removed, reset or a new password since signing in: the session ends
    stamp = acc.session_stamp(s["email"]) or ""
    if not account or not account["authenticator"] or not hmac.compare_digest(stamp, s["pw"]):
        _drop(key)
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
        _sessions[_key(token)] = {"email": email, "expires": time.time() + SESSION_S, "pw": acc.session_stamp(email) or ""}
        _save()
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


def install(app: FastAPI, core_notify=None, store: Path | None = None) -> None:
    """core_notify(email, role_label, address): tells the core who signed in (its admins.py), best effort.
    store: the file that keeps sessions across restarts (None: in memory only)."""
    _load(store)

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
        token = request.cookies.get(SESSION_COOKIE, "")
        if token:
            _drop(_key(token))
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"ok": True}



class OperatorFromSession:
    """ASGI middleware: a signed-in person is the operator. A JSON write from the web dashboard that names an
    "operator" gets the session's email there instead, so the audit trail records who really pressed the button,
    whatever the page sent. Requests with the API token (scripts, the Streamlit console) are left as they are."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("method") in ("GET", "HEAD", "OPTIONS"):
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        sent_token = request.headers.get("authorization") or request.headers.get("x-sentrai-token")
        account = None if sent_token else session_for(request)
        if account is None:
            await self.app(scope, receive, send)
            return
        chunks, more = [], True
        while more:
            message = await receive()
            chunks.append(message.get("body", b""))
            more = message.get("more_body", False)
        body = b"".join(chunks)
        try:
            data = json.loads(body) if body else None
        except ValueError:
            data = None
        if isinstance(data, dict) and "operator" in data:
            data["operator"] = account["email"]
            body = json.dumps(data).encode()
            scope = {**scope, "headers": [(k, v) for k, v in scope["headers"] if k != b"content-length"]
                     + [(b"content-length", str(len(body)).encode())]}
        done = False

        async def replay() -> dict:
            nonlocal done
            if done:
                return await receive()
            done = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay, send)
