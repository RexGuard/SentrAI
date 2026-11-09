"""The SentrAI phone app: who may sign in on a phone, their sign-ins, and what each phone's check found.

Two kinds of people sign in on the app, both with email and password:

* **Panel accounts** (Owner, Admin, Auditor) use the same email, password and authenticator code as the web
  dashboard. The app shows them open alerts as well as their own coaching.
* **Staff** coached by the Security Coach. An Owner or Admin sends a person an app invite from the Coach page
  (a one-time code, valid INVITE_HOURS); the person types it into the app once with a password of their
  choosing, and from then on signs in with email and password. Staff can only read and answer their own
  coaching, run the phone check and send a staff report: nothing about anyone else.

A sign-in gives the phone a key (``sm_...``) that lasts SESSION_DAYS from its last use. Only SHA-256 hashes of
keys and invite codes are kept, with password hashes, in mobile.json next to the database (mode 0600). A new
password, an authenticator reset, a removed panel account or a person erased from the coach ends their phone
sign-ins.

The phone check runs on the phone. It sends back only yes/no answers and two counts (CHECK_FIELDS); app names,
links checked and everything else stay on the phone.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable

KEY_PREFIX = "sm_"
INVITE_HOURS = 72
SESSION_DAYS = 30
MIN_PASSWORD = 10
MAX_DEVICE = 60
FAIL_LIMIT, FAIL_WINDOW_S = 5, 300
OUT_OF_DATE_DAYS = 120  # a security patch older than this counts as "months behind"
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

# What the phone check may send. Anything else in the body is dropped, never stored.
CHECK_FIELDS = {"screen_lock": bool, "usb_debugging": bool, "rooted": bool, "encrypted": bool,
                "outside_apps": int, "screen_reading_apps": int, "android": int, "patch": str, "app_version": str}
# check -> coach kind, and whether a value means "something to fix"
CHECK_KINDS: dict[str, tuple[str, Callable[[Any], bool]]] = {
    "screen_lock": ("phone_no_lock", lambda v: v is False),
    "patch_days": ("phone_out_of_date", lambda v: isinstance(v, int) and v > OUT_OF_DATE_DAYS),
    "outside_apps": ("phone_outside_apps", lambda v: isinstance(v, int) and v > 0),
    "screen_reading_apps": ("phone_screen_readers", lambda v: isinstance(v, int) and v > 0),
    "usb_debugging": ("phone_dev_mode", lambda v: v is True),
    "rooted": ("phone_rooted", lambda v: v is True),
}


class MobileError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def _email(v: Any) -> str:
    e = str(v or "").strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", e) or len(e) > 254:
        raise MobileError("Please type a work email address.")
    return e


def normalise_code(code: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(code or "").upper())


def device_name(v: Any) -> str:
    name = " ".join(re.sub(r"[\x00-\x1f\x7f]", " ", str(v or "")).split())[:MAX_DEVICE]
    return name or "Phone"


def clean_check(body: dict[str, Any], today: date | None = None) -> dict[str, Any]:
    """Keep only the fixed fields, with the right types; work out how old the security patch is."""
    out: dict[str, Any] = {}
    for k, t in CHECK_FIELDS.items():
        v = body.get(k)
        if t is bool and isinstance(v, bool):
            out[k] = v
        elif t is int and isinstance(v, int) and not isinstance(v, bool):
            out[k] = max(0, min(10_000, v))
        elif t is str and isinstance(v, str):
            out[k] = re.sub(r"[^0-9A-Za-z.\-]", "", v)[:20]
    if out.get("patch"):
        try:
            when = date.fromisoformat(out["patch"])
            out["patch_days"] = max(0, ((today or date.today()) - when).days)
        except ValueError:
            out.pop("patch")
    return out


def problems(check: dict[str, Any]) -> list[str]:
    """The coach kinds a check result points at."""
    return [kind for field, (kind, bad) in CHECK_KINDS.items() if field in check and bad(check[field])]


class Mobile:
    def __init__(self, path: Path, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self.clock = clock
        self.lock = threading.RLock()
        self._fails: dict[str, list[float]] = {}
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            loaded = {}
        self._data: dict[str, Any] = {k: dict(loaded.get(k) or {}) for k in ("staff", "invites", "sessions",
                                                                              "checks")}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=1)
        os.replace(tmp, self.path)

    # ------------------------------------------------------------- wrong tries
    def guard(self, who: str) -> None:
        now = self.clock()
        with self.lock:
            fails = [t for t in self._fails.get(who, []) if now - t < FAIL_WINDOW_S]
            self._fails[who] = fails
            if len(fails) >= FAIL_LIMIT:
                wait = FAIL_WINDOW_S - (now - fails[0])
                raise MobileError(f"Too many wrong tries. Wait {int(wait) // 60 + 1} min and try again.", 429)

    def failed(self, who: str) -> None:
        with self.lock:
            self._fails.setdefault(who, []).append(self.clock())

    def cleared(self, who: str) -> None:
        with self.lock:
            self._fails.pop(who, None)

    # ------------------------------------------------------------- staff invites and passwords
    def invite(self, email: str, by: str) -> dict[str, Any]:
        """A one-time code for one coached person (a new one replaces the old). Shown once."""
        email = _email(email)
        raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(12))
        now = self.clock()
        with self.lock:
            self._data["invites"] = {h: i for h, i in self._data["invites"].items()
                                     if i["expires_ts"] > now and i["email"] != email}
            self._data["invites"][_hash(raw)] = {"email": email, "by": by, "at": _iso(now),
                                                 "expires_ts": now + INVITE_HOURS * 3600}
            self._save()
        return {"code": f"{raw[:4]}-{raw[4:8]}-{raw[8:]}", "email": email,
                "expires_at": _iso(now + INVITE_HOURS * 3600)}

    def accept(self, code: str, password: str) -> str:
        """Use an invite: set the person's app password. Returns their email."""
        if len(password or "") < MIN_PASSWORD:
            raise MobileError(f"Use at least {MIN_PASSWORD} characters for the password.")
        now = self.clock()
        with self.lock:
            key = _hash(normalise_code(code))
            inv = self._data["invites"].get(key)
            if not inv or inv["expires_ts"] <= now:
                raise MobileError("This invite code is wrong or has expired. Ask for a new one.", 403)
            del self._data["invites"][key]
            salt = secrets.token_hex(16)
            self._data["staff"][inv["email"]] = {"salt": salt, "hash": self._pw(password, salt),
                                                 "set_at": _iso(now)}
            # a new password ends the person's earlier phone sign-ins
            self._data["sessions"] = {k: s for k, s in self._data["sessions"].items()
                                      if not (s["kind"] == "staff" and s["email"] == inv["email"])}
            self._save()
            return inv["email"]

    @staticmethod
    def _pw(password: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000).hex()

    def check_staff(self, email: str, password: str) -> bool:
        with self.lock:
            rec = self._data["staff"].get(str(email or "").strip().lower())
        if not rec:
            self._pw(password or "", "00" * 16)  # same work, so timing tells nothing
            return False
        return hmac.compare_digest(self._pw(password or "", rec["salt"]), rec["hash"])

    def has_password(self, email: str) -> bool:
        with self.lock:
            return email in self._data["staff"]

    def pending_invite(self, email: str) -> bool:
        now = self.clock()
        with self.lock:
            return any(i["email"] == email and i["expires_ts"] > now for i in self._data["invites"].values())

    # ------------------------------------------------------------- sign-ins
    def start(self, email: str, kind: str, device: str, stamp: str = "") -> dict[str, Any]:
        """A new phone sign-in. kind: "staff" or "panel". stamp: the panel account's session stamp."""
        key = KEY_PREFIX + secrets.token_urlsafe(32)
        now = self.clock()
        sid = "ph-" + secrets.token_hex(4)
        with self.lock:
            self._data["sessions"][_hash(key)] = {"id": sid, "email": email, "kind": kind,
                                                  "device": device_name(device), "stamp": stamp,
                                                  "created_at": _iso(now), "last_ts": now, "last_at": _iso(now)}
            self._save()
        return {"key": key, "id": sid, "expires_days": SESSION_DAYS}

    def session(self, key: str, stamp_of: Callable[[str], str | None]) -> dict[str, Any] | None:
        """The sign-in a key belongs to, or None (unknown, expired, or the panel password changed)."""
        if not key.startswith(KEY_PREFIX):
            return None
        now = self.clock()
        with self.lock:
            h = _hash(key)
            s = self._data["sessions"].get(h)
            if not s:
                return None
            if now - s["last_ts"] > SESSION_DAYS * 86400 or \
                    (s["kind"] == "panel" and stamp_of(s["email"]) != s["stamp"]) or \
                    (s["kind"] == "staff" and s["email"] not in self._data["staff"]):
                del self._data["sessions"][h]
                self._save()
                return None
            if now - s["last_ts"] > 300:  # write at most every 5 minutes per phone
                s["last_ts"], s["last_at"] = now, _iso(now)
                self._save()
            return dict(s)

    def end(self, sid: str) -> dict[str, Any]:
        with self.lock:
            h = next((h for h, s in self._data["sessions"].items() if s["id"] == sid), None)
            if not h:
                raise MobileError("No such phone sign-in.", 404)
            s = self._data["sessions"].pop(h)
            self._data["checks"].pop(sid, None)
            self._save()
            return {"id": sid, "email": s["email"], "device": s["device"]}

    def forget(self, email: str) -> dict[str, int]:
        """Remove a person from the app: password, invites, sign-ins and phone checks."""
        email = str(email or "").strip().lower()
        with self.lock:
            ids = {s["id"] for s in self._data["sessions"].values() if s["email"] == email}
            gone = {"password": int(self._data["staff"].pop(email, None) is not None),
                    "sign_ins": len(ids),
                    "checks": sum(1 for i in ids if self._data["checks"].pop(i, None) is not None)}
            self._data["sessions"] = {h: s for h, s in self._data["sessions"].items() if s["email"] != email}
            self._data["invites"] = {h: i for h, i in self._data["invites"].items() if i["email"] != email}
            self._save()
            return gone

    def phones(self) -> list[dict[str, Any]]:
        with self.lock:
            out = []
            for s in self._data["sessions"].values():
                c = self._data["checks"].get(s["id"])
                out.append({k: s[k] for k in ("id", "email", "kind", "device", "created_at", "last_at")}
                           | {"checked_at": c["at"] if c else None,
                              "to_fix": len(problems(c["result"])) if c else None})
            return sorted(out, key=lambda r: r["last_at"], reverse=True)

    # ------------------------------------------------------------- phone check
    def record_check(self, sid: str, body: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        """Save the latest check for this phone. Returns the cleaned result and the problems that are new since
        the last check (only those become coaching moments, so the same thing is not raised every day)."""
        result = clean_check(body)
        now = self.clock()
        with self.lock:
            before = self._data["checks"].get(sid)
            old = set(problems(before["result"])) if before else set()
            self._data["checks"][sid] = {"at": _iso(now), "result": result}
            self._save()
        return result, [k for k in problems(result) if k not in old]

    def team_checks(self) -> dict[str, Any]:
        """Totals for the owner: how many phones checked, and how many have each problem. No names."""
        with self.lock:
            checks = list(self._data["checks"].values())
        by: dict[str, int] = {}
        for c in checks:
            for k in problems(c["result"]):
                by[k] = by.get(k, 0) + 1
        return {"phones_checked": len(checks), "all_good": sum(1 for c in checks if not problems(c["result"])),
                "by_problem": by}
