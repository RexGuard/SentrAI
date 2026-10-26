"""Machines that join a central SentrAI panel (one agent per machine).

The panel's owner makes a one-time join code; the agent on the new machine swaps it for its own
key (POST /fleet/enrol). That key only lets the agent send its own machine's events and read its
own block list, and the owner can revoke it without touching any other machine. Only SHA-256
hashes of codes and keys are kept, in fleet.json next to the database (mode 0600).

Agents reach the panel over HTTPS (app/serve.py, SENTRAI_PANEL_PORT) and pin its certificate: the join
code comes with the certificate's SHA-256 fingerprint (``pin``), and an agent that sees any other
certificate refuses to talk, so a self-signed panel needs no certificate file copied around.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

KEY_PREFIX = "sa_"
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O or 1/I to misread
CODE_TTL_S = 24 * 3600.0
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
# Wrong join codes: after this many in the window, enrolment refuses everyone until the window passes.
MAX_BAD_CODES = 10
BAD_CODE_WINDOW_S = 600.0


class FleetError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def normalise_code(code: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (code or "").upper())


PIN_RE = re.compile(r"^[0-9a-f]{64}$")


def normalise_pin(pin: str) -> str:
    """"sha256:AB:CD:..." in any case, with or without colons -> "sha256:abcd..."; "" if it is not one."""
    p = re.sub(r"[\s:]", "", (pin or "").strip().lower().removeprefix("sha256:"))
    return f"sha256:{p}" if PIN_RE.match(p) else ""


def cert_pin(cert_file: str | os.PathLike | None) -> str:
    """The pin agents check: SHA-256 of the panel certificate (the first one in the PEM file)."""
    if not cert_file:
        return ""
    try:
        text = Path(cert_file).read_text(encoding="ascii", errors="replace")
    except OSError:
        return ""
    m = re.search(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", text, re.S)
    if not m:
        return ""
    try:
        der = base64.b64decode("".join(m.group(1).split()), validate=True)
    except ValueError:
        return ""
    return "sha256:" + hashlib.sha256(der).hexdigest()


def panel_info() -> dict[str, str]:
    """What a new machine needs to reach this panel: its HTTPS address (SENTRAI_PANEL_URL) and pin."""
    return {"panel_url": os.environ.get("SENTRAI_PANEL_URL", "").strip().rstrip("/"),
            "pin": cert_pin(os.environ.get("SENTRAI_PANEL_CERT", "").strip())}


class Fleet:
    def __init__(self, path: Path, clock=time.time) -> None:
        self.path = path
        self.clock = clock
        self.lock = threading.Lock()
        self._bad: list[float] = []
        self._data: dict[str, Any] = {"codes": {}, "agents": {}}
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self._data = {"codes": dict(loaded.get("codes") or {}), "agents": dict(loaded.get("agents") or {})}
        except (OSError, ValueError):
            pass

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2)
        os.replace(tmp, self.path)

    # ------------------------------------------------------------- join codes
    def join_code(self, created_by: str, name: str | None = None, ttl_s: float = CODE_TTL_S) -> dict[str, Any]:
        """A new one-time code, shown once. ``name`` (optional) fixes the machine name the agent gets."""
        if name is not None and name != "" and not HOST_RE.match(name):
            raise FleetError("machine names use letters, digits, dot, dash and underscore (up to 63)")
        raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(12))
        code = f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"
        now = self.clock()
        with self.lock:
            self._data["codes"] = {h: c for h, c in self._data["codes"].items() if c["expires_ts"] > now}
            self._data["codes"][_hash(raw)] = {"created_by": created_by, "created_at": _iso(now),
                                               "expires_ts": now + ttl_s, "name": name or None}
            self._save()
        return {"code": code, "expires_at": _iso(now + ttl_s), "name": name or None}

    def pending_codes(self) -> int:
        now = self.clock()
        return sum(1 for c in self._data["codes"].values() if c["expires_ts"] > now)

    # -------------------------------------------------------------- enrolment
    def enrol(self, code: str, host: str) -> dict[str, Any]:
        now = self.clock()
        with self.lock:
            self._bad = [t for t in self._bad if now - t < BAD_CODE_WINDOW_S]
            if len(self._bad) >= MAX_BAD_CODES:
                raise FleetError("too many wrong join codes; try again in a few minutes", 429)
            entry = self._data["codes"].get(_hash(normalise_code(code)))
            if entry is None or entry["expires_ts"] <= now:
                self._bad.append(now)
                raise FleetError("join code is wrong, used or expired; make a new one on the panel", 403)
            host = entry.get("name") or (host or "").strip()
            if not HOST_RE.match(host):
                raise FleetError("machine names use letters, digits, dot, dash and underscore (up to 63)")
            if any(a["host"] == host and not a.get("revoked_at") for a in self._data["agents"].values()):
                raise FleetError(f"a machine named {host!r} has already joined; revoke it on the panel first "
                                 f"or join with another --name", 409)
            del self._data["codes"][_hash(normalise_code(code))]  # one use only
            agent_id = secrets.token_hex(6)
            key = f"{KEY_PREFIX}{agent_id}.{secrets.token_urlsafe(32)}"
            self._data["agents"][agent_id] = {
                "agent_id": agent_id, "host": host, "key_sha256": _hash(key), "joined_at": _iso(now),
                "invited_by": entry.get("created_by"), "last_seen": None, "revoked_at": None, "revoked_by": None,
            }
            self._save()
        return {"agent_id": agent_id, "host": host, "key": key}

    def check(self, key: str) -> dict[str, Any] | None:
        """The agent a key belongs to, or None (unknown, malformed or revoked)."""
        if not key.startswith(KEY_PREFIX) or "." not in key:
            return None
        agent_id = key[len(KEY_PREFIX):].split(".", 1)[0]
        a = self._data["agents"].get(agent_id)
        if a is None or a.get("revoked_at") or not hmac.compare_digest(a["key_sha256"], _hash(key)):
            return None
        return a

    def seen(self, agent: dict[str, Any]) -> None:
        """Remember when an agent last called in (kept in memory; saved with the next change)."""
        agent["last_seen"] = _iso(self.clock())

    def revoke(self, agent_id: str, by: str) -> dict[str, Any]:
        with self.lock:
            a = self._data["agents"].get(agent_id)
            if a is None:
                raise FleetError(f"no machine with id {agent_id}", 404)
            if not a.get("revoked_at"):
                a["revoked_at"], a["revoked_by"] = _iso(self.clock()), by
                self._save()
            return self.public(a)

    def offline_report(self, agent: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
        """An agent is back after the panel was out of reach: keep a short summary of what it did alone."""
        summary = {"from": report.get("from"), "to": report.get("to"), "scored": int(report.get("scored") or 0),
                   "local_blocks": len(report.get("actions") or []), "reported_at": _iso(self.clock())}
        with self.lock:
            a = self._data["agents"].get(agent["agent_id"])
            if a is not None:
                a["offline"] = summary
                a["offline_total"] = int(a.get("offline_total") or 0) + summary["local_blocks"]
                self._save()
        return summary

    @staticmethod
    def public(a: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in a.items() if k != "key_sha256"}

    def agents(self) -> list[dict[str, Any]]:
        return [self.public(a) for a in self._data["agents"].values()]
