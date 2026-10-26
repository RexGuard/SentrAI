"""Dashboard accounts: who may sign in, with which role, and their authenticator.

One JSON file per machine, next to the settings file (~/.cactai/accounts.json, readable by its owner
only). It holds password hashes, authenticator secrets and hashes of one-time codes; never a password.

How people get in:
  - A new machine has no accounts. `python cactai_config.py admin` (on a server: `sudo cactai-admin`)
    prints a one-time setup code; whoever has it creates the Owner account on the dashboard's first
    screen. The code works once, for SETUP_CODE_HOURS. install.sh can also make the Owner directly.
  - Everyone after that is invited by an Owner or Admin (no open sign-up). An invite is a code, or a
    link that carries it, valid for INVITE_HOURS.
  - Every sign-in is email, password, then a 6-digit authenticator code (TOTP, RFC 6238), or one of the
    8 recovery codes made when the authenticator was added.

Settings from before accounts existed (one email and password hash in the settings file) become the
Owner account the first time this file is read; that Owner adds an authenticator at the next sign-in.

Roles: Owner and Admin run SentrAI; an Auditor reads everything and changes nothing.
Stdlib only, like cactai_config, so the launchers can use it from any venv.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
import time
import urllib.parse

import cactai_config as cfg

ROLES = ("owner", "admin", "auditor")
ROLE_LABEL = {"owner": "Owner", "admin": "Admin", "auditor": "Auditor"}
# view: every page · act: approve, block, scan, quarantine, protection switch · configure: save settings
# export: download reports and the journal · people: the Team page
PERMISSIONS = {
    "owner": {"view", "act", "configure", "export", "people"},
    "admin": {"view", "act", "configure", "export", "people"},
    "auditor": {"view", "export"},
}
MIN_PASSWORD = 12
SETUP_CODE_HOURS = 24
INVITE_HOURS = 72
RECOVERY_CODES = 8
TOTP_STEP_S = 30
TOTP_DIGITS = 6
ISSUER = "SentrAI"
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O or 1/I to misread

_lock = threading.RLock()


class AccountError(ValueError):
    """Something a person did that cannot be done; the message says why, in plain words."""


accounts_path = cfg.accounts_path


def can(role: str | None, permission: str) -> bool:
    return permission in PERMISSIONS.get(role or "", set())


def _now() -> float:
    return time.time()


def _norm(email: str) -> str:
    return email.strip().lower()


def _digest(code: str) -> str:
    """One-time codes are random and long, so a plain SHA-256 is enough to keep them out of the file."""
    return hashlib.sha256(code.strip().upper().replace("-", "").replace(" ", "").encode()).hexdigest()


def _code(groups: int) -> str:
    return "-".join("".join(secrets.choice(_CODE_ALPHABET) for _ in range(4)) for _ in range(groups))


# ------------------------------------------------------------------ file

def _empty() -> dict:
    return {"accounts": [], "setup_code": None, "invites": []}


def _legacy_owner() -> dict | None:
    """The single sign-in from the settings file (or the environment), as an Owner account."""
    login = cfg.dashboard_login()
    stored = login["hash"] or (cfg.hash_password(login["plain"]) if login["plain"] else "")
    if not stored:
        return None
    email = _norm(login["email"])
    return _new_account(email, email.split("@")[0], "owner", stored)


def _read() -> dict:
    path = accounts_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        data = _empty()
        owner = _legacy_owner()
        if owner:
            data["accounts"].append(owner)
            _write(data)
        return data
    except json.JSONDecodeError as exc:
        raise AccountError(f"{path} is not valid JSON; fix or remove it") from exc
    return {**_empty(), **data} if isinstance(data, dict) else _empty()


def _write(data: dict) -> None:
    path = accounts_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    cfg._write_private(tmp, json.dumps(data, indent=2) + "\n")
    os.replace(tmp, path)


def _new_account(email: str, name: str, role: str, password_hash: str) -> dict:
    return {"email": _norm(email), "name": name.strip() or _norm(email).split("@")[0], "role": role,
            "hash": password_hash, "totp": "", "totp_pending": "", "totp_step": 0, "recovery": [],
            "created": _now(), "last_sign_in": None, "last_ip": ""}


def _find(data: dict, email: str) -> dict | None:
    email = _norm(email)
    return next((a for a in data["accounts"] if a["email"] == email), None)


def _public(a: dict) -> dict:
    return {"email": a["email"], "name": a["name"], "role": a["role"], "authenticator": bool(a["totp"]),
            "created": a["created"], "last_sign_in": a["last_sign_in"], "last_ip": a["last_ip"],
            "password_set": bool(a["hash"])}


def _check_new_password(password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise AccountError(f"Use at least {MIN_PASSWORD} characters for the password.")


def _check_email(email: str) -> None:
    local, _, domain = email.strip().partition("@")
    if not local or "." not in domain or any(c.isspace() for c in email.strip()):
        raise AccountError("Please type an email address, like admin@example.com.")


# ------------------------------------------------------------------ reading

def people() -> list[dict]:
    """Every account, Owners first, without secrets."""
    with _lock:
        accounts = _read()["accounts"]
    return [_public(a) for a in sorted(accounts, key=lambda a: (ROLES.index(a["role"]), a["email"]))]


def get(email: str) -> dict | None:
    with _lock:
        a = _find(_read(), email)
    return _public(a) if a else None


def has_accounts() -> bool:
    with _lock:
        return bool(_read()["accounts"])


def pending_invites() -> list[dict]:
    with _lock:
        data = _read()
    now = _now()
    return [{"email": i["email"], "role": i["role"], "by": i["by"], "expires": i["expires"], "reset": i.get("reset", False)}
            for i in data["invites"] if i["expires"] > now]


# ------------------------------------------------------------------ first run

def new_setup_code() -> str:
    """A one-time code for creating the Owner account. A new one replaces the old one."""
    code = _code(3)
    with _lock:
        data = _read()
        if data["accounts"]:
            raise AccountError("This machine already has an Owner; invite people from the Team page.")
        data["setup_code"] = {"hash": _digest(code), "expires": _now() + SETUP_CODE_HOURS * 3600}
        _write(data)
    return code


def setup_code_waiting() -> bool:
    with _lock:
        sc = _read()["setup_code"]
    return bool(sc and sc["expires"] > _now())


def register_owner(code: str, name: str, email: str, password: str) -> dict:
    """The first screen: the setup code makes this person the Owner. The code is then used up."""
    _check_email(email)
    _check_new_password(password)
    with _lock:
        data = _read()
        if data["accounts"]:
            raise AccountError("This machine already has an Owner. Sign in, or ask them for an invite.")
        sc = data["setup_code"]
        if not sc or sc["expires"] <= _now() or not hmac.compare_digest(sc["hash"], _digest(code)):
            raise AccountError("That setup code is wrong or has expired. Run `python cactai_config.py admin` "
                               "(on a server: `sudo cactai-admin`) for a new one.")
        account = _new_account(email, name, "owner", cfg.hash_password(password))
        data["accounts"].append(account)
        data["setup_code"] = None
        _write(data)
    return _public(account)


def make_owner(email: str, password: str, name: str = "") -> dict:
    """install.sh with an email and password: the person at the shell becomes the Owner directly."""
    _check_email(email)
    _check_new_password(password)
    with _lock:
        data = _read()
        if data["accounts"]:
            raise AccountError("This machine already has an Owner.")
        account = _new_account(email, name, "owner", cfg.hash_password(password))
        data["accounts"].append(account)
        data["setup_code"] = None
        _write(data)
    return _public(account)


# ------------------------------------------------------------------ sign-in

def check_password(email: str, password: str) -> dict | None:
    """The account when email and password match, else None. Takes as long either way."""
    with _lock:
        a = _find(_read(), email)
    if not a or not a["hash"]:
        cfg.check_password(password, cfg.hash_password("x"))  # same work, so timing tells nothing
        return None
    return _public(a) if cfg.check_password(password, a["hash"]) else None


def totp_code(secret: str, at: float | None = None) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    counter = int((_now() if at is None else at) // TOTP_STEP_S)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** TOTP_DIGITS).zfill(TOTP_DIGITS)


def _totp_step(secret: str, code: str, after: int) -> int | None:
    """The time step the code belongs to (now, or one step either side), if it is newer than `after`."""
    code = code.strip().replace(" ", "")
    if not (code.isdigit() and len(code) == TOTP_DIGITS):
        return None
    now = _now()
    for drift in (0, -1, 1):
        step = int(now // TOTP_STEP_S) + drift
        if step > after and hmac.compare_digest(totp_code(secret, step * TOTP_STEP_S), code):
            return step
    return None


def totp_uri(email: str, secret: str) -> str:
    label = urllib.parse.quote(f"{ISSUER}:{email}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={ISSUER}&digits={TOTP_DIGITS}&period={TOTP_STEP_S}"


def start_authenticator(email: str) -> str:
    """A new authenticator secret for this account, kept aside until a code from it is typed."""
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    with _lock:
        data = _read()
        a = _find(data, email)
        if not a:
            raise AccountError("No such account.")
        a["totp_pending"] = secret
        _write(data)
    return secret


def confirm_authenticator(email: str, code: str) -> list[str]:
    """The typed code proves the app was set up: keep the secret, return new recovery codes (shown once)."""
    with _lock:
        data = _read()
        a = _find(data, email)
        if not a or not a["totp_pending"]:
            raise AccountError("Start adding the authenticator again.")
        step = _totp_step(a["totp_pending"], code, 0)
        if step is None:
            raise AccountError("That code doesn't match. Check the time on your phone and type the newest code.")
        codes = [_code(2) for _ in range(RECOVERY_CODES)]
        a.update(totp=a["totp_pending"], totp_pending="", totp_step=step, recovery=[_digest(c) for c in codes])
        _write(data)
    return codes


def check_second_factor(email: str, code: str) -> str | None:
    """'totp' or 'recovery' when the code is good (a recovery code is then used up), else None."""
    with _lock:
        data = _read()
        a = _find(data, email)
        if not a or not a["totp"]:
            return None
        step = _totp_step(a["totp"], code, a["totp_step"])  # a code works once
        if step is not None:
            a["totp_step"] = step
            _write(data)
            return "totp"
        digest = _digest(code)
        for n, stored in enumerate(a["recovery"]):
            if hmac.compare_digest(stored, digest):
                del a["recovery"][n]
                _write(data)
                return "recovery"
    return None


def recovery_left(email: str) -> int:
    with _lock:
        a = _find(_read(), email)
    return len(a["recovery"]) if a else 0


def record_sign_in(email: str, ip: str) -> tuple[float | None, str]:
    """Note this sign-in; returns the one before it (time, IP), so the person can spot someone else's."""
    with _lock:
        data = _read()
        a = _find(data, email)
        if not a:
            return None, ""
        before = a["last_sign_in"], a["last_ip"]
        a["last_sign_in"], a["last_ip"] = _now(), ip
        _write(data)
    return before


# ------------------------------------------------------------------ people

def _may_manage(by: dict | None, role: str) -> None:
    if not by or not can(by["role"], "people"):
        raise AccountError("Only an Owner or an Admin can manage people.")
    if role == "owner" and by["role"] != "owner":
        raise AccountError("Only an Owner can add, change or remove an Owner.")


def _owners(data: dict) -> int:
    return sum(1 for a in data["accounts"] if a["role"] == "owner")


def invite(by_email: str, email: str, role: str) -> str:
    """An invite code for this email and role (a new invite for the same email replaces the old one)."""
    _check_email(email)
    if role not in ROLES:
        raise AccountError(f"The role is one of: {', '.join(ROLE_LABEL.values())}.")
    code = secrets.token_urlsafe(18)
    with _lock:
        data = _read()
        _may_manage(_find(data, by_email), role)
        if _find(data, email):
            raise AccountError(f"{_norm(email)} already has an account.")
        data["invites"] = [i for i in data["invites"] if i["email"] != _norm(email) and i["expires"] > _now()]
        data["invites"].append({"hash": _digest(code), "email": _norm(email), "role": role, "by": _norm(by_email),
                                "expires": _now() + INVITE_HOURS * 3600})
        _write(data)
    return code


def invite_for(code: str) -> dict | None:
    """What an invite code is for ({email, role, reset}), or None when it is wrong or expired."""
    if not code:
        return None
    with _lock:
        data = _read()
    digest = _digest(code)
    for i in data["invites"]:
        if i["expires"] > _now() and hmac.compare_digest(i["hash"], digest):
            return {"email": i["email"], "role": i["role"], "reset": i.get("reset", False)}
    return None


def accept_invite(code: str, name: str, password: str) -> dict:
    """The invited person sets their name and password; the authenticator comes right after."""
    _check_new_password(password)
    with _lock:
        data = _read()
        digest = _digest(code)
        found = next((i for i in data["invites"] if i["expires"] > _now() and hmac.compare_digest(i["hash"], digest)),
                     None)
        if not found:
            raise AccountError("This invite is wrong or has expired. Ask for a new one.")
        data["invites"].remove(found)
        a = _find(data, found["email"])
        if a:  # a reset: same account and role, new password and authenticator
            a.update(hash=cfg.hash_password(password), totp="", totp_pending="", recovery=[],
                     name=name.strip() or a["name"])
        else:
            a = _new_account(found["email"], name, found["role"], cfg.hash_password(password))
            data["accounts"].append(a)
        _write(data)
    return _public(a)


def withdraw_invite(by_email: str, email: str) -> None:
    with _lock:
        data = _read()
        for i in [i for i in data["invites"] if i["email"] == _norm(email)]:
            _may_manage(_find(data, by_email), i["role"])
            data["invites"].remove(i)
        _write(data)


def set_role(by_email: str, email: str, role: str) -> None:
    if role not in ROLES:
        raise AccountError(f"The role is one of: {', '.join(ROLE_LABEL.values())}.")
    with _lock:
        data = _read()
        a = _find(data, email)
        if not a:
            raise AccountError("No such account.")
        by = _find(data, by_email)
        _may_manage(by, a["role"])
        _may_manage(by, role)
        if a["role"] == "owner" and role != "owner" and _owners(data) == 1:
            raise AccountError("SentrAI needs at least one Owner. Make someone else Owner first.")
        a["role"] = role
        _write(data)


def remove(by_email: str, email: str) -> None:
    with _lock:
        data = _read()
        a = _find(data, email)
        if not a:
            raise AccountError("No such account.")
        _may_manage(_find(data, by_email), a["role"])
        if a["role"] == "owner" and _owners(data) == 1:
            raise AccountError("SentrAI needs at least one Owner. Make someone else Owner first.")
        data["accounts"].remove(a)
        _write(data)


def reset(by_email: str, email: str) -> str:
    """For a forgotten password or a lost phone: a code (or link) that sets both again. Until it is used
    the old password no longer works."""
    code = secrets.token_urlsafe(18)
    with _lock:
        data = _read()
        a = _find(data, email)
        if not a:
            raise AccountError("No such account.")
        _may_manage(_find(data, by_email), a["role"])
        if _norm(by_email) == a["email"]:
            raise AccountError("Ask another Owner or Admin, or reset it from the server with cactai-admin --reset.")
        a.update(hash="", totp="", totp_pending="", recovery=[])
        data["invites"] = [i for i in data["invites"] if i["email"] != a["email"]]
        data["invites"].append({"hash": _digest(code), "email": a["email"], "role": a["role"], "by": _norm(by_email),
                                "expires": _now() + INVITE_HOURS * 3600, "reset": True})
        _write(data)
    return code


def shell_reset(email: str = "", password: str = "") -> tuple[str, str]:
    """`cactai-admin --reset`: whoever runs it on the machine is trusted. Sets a new password (made when
    none is given, and returned) and clears the authenticator, which is added again at the next sign-in.
    Without an email it is the first Owner."""
    if password:
        _check_new_password(password)
    with _lock:
        data = _read()
        a = _find(data, email) if email else next((a for a in data["accounts"] if a["role"] == "owner"), None)
        if not a:
            raise AccountError(f"No account for {email}." if email else "There is no account yet.")
        password = password or cfg.new_password()
        a.update(hash=cfg.hash_password(password), totp="", totp_pending="", recovery=[])
        _write(data)
    return a["email"], password
