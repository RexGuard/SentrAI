"""Part 3 of 3: the responder. Carries out a containment action, and undoes it.

A responder is any `Responder` subclass: list the action types it handles in `actions`,
implement `apply()` and `revert()`. Every action is temporary and reversible, so both
are required. The allowlist of action types is simply whatever the registered
responders can handle.

Nothing here touches the host firewall, shell or OS: blocks are enforced by the target
app polling GET /blocklist, and the other playbooks are recorded only, unless a
`WebhookResponder` hands them to another system (a WAF, a router, a SOAR) by URL.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
from abc import ABC, abstractmethod
from collections import Counter
from collections.abc import Callable
from typing import Any

log = logging.getLogger("sentrai.responders")

Action = dict[str, Any]  # {"action_id", "type", "target", ...} built by Areole.apply


class Responder(ABC):
    name = "responder"
    actions: tuple[str, ...] = ()
    enforcement = "recorded (simulated)"

    @abstractmethod
    def apply(self, action: Action) -> bool:
        """Put the action in place. Return True when it is verified to be in force."""

    @abstractmethod
    def revert(self, action: Action) -> bool | None:
        """Take the action out again (rollback, rejection or TTL expiry). Return True when the undo is
        verified, False when it failed (the core retries it and tells the on-duty person), None when this
        responder cannot tell."""

    def reset(self) -> None:
        """Forget all state (demo reset)."""


class BlocklistResponder(Responder):
    """Blocks IPs and locks accounts through the app-level blocklist (GET /blocklist)."""

    name = "blocklist"
    actions = ("block_ip", "lock_user")
    enforcement = "blocklist"

    def __init__(self) -> None:
        # Counted, so two incidents blocking the same IP need two reverts to unblock it.
        self._active: Counter[tuple[str, str]] = Counter()

    def apply(self, action: Action) -> bool:
        """True only when the target is usable and now on the list: an empty target, or a
        block_ip target that is not an IP address, is never put on the blocklist."""
        target = str(action.get("target") or "").strip()
        if not target or (action["type"] == "block_ip" and not _is_ip(target)):
            return False
        key = (action["type"], action["target"])
        self._active[key] += 1
        return self._active[key] > 0

    def revert(self, action: Action) -> bool | None:
        key = (action["type"], action["target"])
        if key not in self._active:
            return True  # never applied (refused target) or already reverted
        self._active[key] -= 1
        if self._active[key] <= 0:
            del self._active[key]
        return True

    def reset(self) -> None:
        self._active.clear()

    def blocklist(self) -> dict[str, list[str]]:
        return {
            "ips": sorted(t for kind, t in self._active if kind == "block_ip"),
            "users": sorted(t for kind, t in self._active if kind == "lock_user"),
        }


class SimulatedResponder(Responder):
    """Playbooks the MVP only records (WAF rule, rate limit, kill process, revoke ACL)."""

    name = "simulated"
    actions = ("rate_limit", "waf_rule", "kill_process", "revoke_public_acl")

    def apply(self, action: Action) -> bool:
        return True

    def revert(self, action: Action) -> bool | None:
        return True


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# poster(url, body bytes, headers) -> HTTP status code; raises on network errors.
Poster = Callable[[str, bytes, dict[str, str]], int]


def _httpx_poster(timeout_s: float) -> Poster:
    import httpx

    def post(url: str, body: bytes, headers: dict[str, str]) -> int:
        return httpx.post(url, content=body, headers=headers, timeout=timeout_s, follow_redirects=False).status_code

    return post


class WebhookResponder(Responder):
    """Hands containment actions to another system by URL: a firewall API, a WAF, a SOAR playbook.

    Each apply and revert is one JSON POST, ``{"op": "apply"|"revert", "action_id", "type", "target",
    "incident", "expires_at", ...}``. With a secret, the body is signed: ``X-SentrAI-Signature:
    sha256=<HMAC of the body>`` plus ``Authorization: Bearer <secret>``. An action counts as in force
    only when the receiver answers 2xx. Action types SentrAI already enforces itself (the blocklist)
    are still applied there first, so GET /blocklist keeps working.
    """

    name = "webhook"
    enforcement = "webhook"

    def __init__(self, url: str, actions: tuple[str, ...], secret: str = "", timeout_s: float = 3.0,
                 inner: Callable[[str], Responder | None] | None = None, poster: Poster | None = None) -> None:
        if not url.lower().startswith(("https://", "http://")):
            raise ValueError("the responder webhook URL must start with https:// or http://")
        self.url = url
        self.actions = tuple(actions)
        self.secret = secret
        self.inner = inner or (lambda _t: None)
        self.poster = poster or _httpx_poster(timeout_s)
        self.last_error: str | None = None

    def _send(self, op: str, action: Action) -> bool:
        payload = {"op": op, **{k: v for k, v in action.items() if not str(k).startswith("_")}}
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "SentrAI-responder/1"}
        if self.secret:
            headers["Authorization"] = f"Bearer {self.secret}"
            headers["X-SentrAI-Signature"] = "sha256=" + hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()
        try:
            status = self.poster(self.url, body, headers)
        except Exception as exc:  # network error, timeout, bad URL: the action is simply not in force
            self.last_error = f"{type(exc).__name__}: {exc}"[:200]
            log.warning("responder webhook %s failed: %s", op, self.last_error)
            return False
        if not 200 <= status < 300:
            self.last_error = f"HTTP {status}"
            log.warning("responder webhook %s answered HTTP %s", op, status)
            return False
        return True

    def apply(self, action: Action) -> bool:
        inner = self.inner(action["type"])
        ok_inner = inner.apply(action) if inner is not None else True
        ok = self._send("apply", action)
        action["webhook"] = {"url": self.url, "ok": ok, **({"error": self.last_error} if not ok else {})}
        return ok_inner and ok

    def revert(self, action: Action) -> bool | None:
        inner = self.inner(action["type"])
        ok_inner = inner.revert(action) if inner is not None else True
        ok = self._send("revert", action)
        action["webhook_revert"] = {"url": self.url, "ok": ok, **({"error": self.last_error} if not ok else {})}
        return ok and ok_inner is not False

    def reset(self) -> None:
        self.last_error = None


class Responders:
    """Routes each action to the responder that handles its type."""

    def __init__(self, *responders: Responder) -> None:
        self.all = list(responders)
        self._by_type = {t: r for r in responders for t in r.actions}

    @property
    def allowlist(self) -> set[str]:
        return set(self._by_type)

    def for_type(self, action_type: str) -> Responder:
        try:
            return self._by_type[action_type]
        except KeyError:
            raise ValueError(f"{action_type} is not an allowlisted playbook") from None

    def apply(self, action: Action) -> bool:
        return self.for_type(action["type"]).apply(action)

    def revert(self, action: Action) -> bool | None:
        return self.for_type(action["type"]).revert(action)

    def reset(self) -> None:
        for r in self.all:
            r.reset()
