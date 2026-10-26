"""Cloudflare blocking for `block_ip`: the attacker is stopped at Cloudflare's edge, before it reaches you.

`CloudflareResponder` wraps the `block_ip` responder the core already uses (the app blocklist, and the
host firewall when that is on) and also puts each blocked address into Cloudflare. It is called at
exactly the points every responder is, so the business limits, TTL expiry, rollback and recorded undo
apply unchanged: the Cloudflare entry goes when SentrAI's block goes.

Two ways to block (CLOUDFLARE_METHOD):

  * ``access_rule`` (default)  one IP Access rule per address, on a zone (CLOUDFLARE_ZONE_ID) or on
                               every site in the account (CLOUDFLARE_ACCOUNT_ID). Works on every plan.
                               Token permission: Zone > Firewall Services > Edit, or
                               Account > Account Firewall Access Rules > Edit.
  * ``list``                   one item per address in an account IP list (CLOUDFLARE_LIST_ID). You add
                               one WAF custom rule yourself, e.g. ``ip.src in $sentrai_blocklist`` -> Block.
                               Cloudflare's recommended way. Permission: Account > Account Filter Lists > Edit.

CLOUDFLARE_MODE picks what an access rule does: block (default), managed_challenge, challenge or
js_challenge. A challenge is gentler: a real person behind a shared address can still get through.

Safety:
  * The token is read from the environment or the settings file (CLOUDFLARE_API_TOKEN or
    CLOUDFLARE_API_TOKEN_FILE), never written to the audit trail or shown by the API.
  * Protected, private, loopback and link-local addresses never reach Cloudflare.
  * SentrAI only ever removes entries it made itself (their note starts with "SentrAI"), never one you
    added by hand.
  * A Cloudflare failure never weakens the local block: the action stays in force locally and the
    failure is recorded on it. A removal that fails is reported as a failed undo, so the core retries
    it and tells the on-duty person, and no forgotten block is left at the edge.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from collections import Counter
from collections.abc import Callable
from typing import Any

from .firewall import unsafe_reason
from .responders import Action, Responder

log = logging.getLogger("cactai.cloudflare")

API = "https://api.cloudflare.com/client/v4"
METHODS = ("access_rule", "list")
MODES = ("block", "managed_challenge", "challenge", "js_challenge")
NOTE_PREFIX = "SentrAI"

# requester(method, url, headers, params, json body) -> (HTTP status, parsed JSON body or {}); raises on network errors.
Requester = Callable[[str, str, dict[str, str], "dict[str, Any] | None", Any], "tuple[int, dict[str, Any]]"]


class CloudflareError(Exception):
    pass


def _httpx_requester(timeout_s: float) -> Requester:
    import httpx

    def request(method: str, url: str, headers: dict[str, str], params: dict[str, Any] | None, body: Any) -> tuple[int, dict]:
        r = httpx.request(method, url, headers=headers, params=params, json=body, timeout=timeout_s,
                          follow_redirects=False)
        try:
            data = r.json()
        except ValueError:
            data = {}
        return r.status_code, data if isinstance(data, dict) else {}

    return request


def _errors(data: dict[str, Any]) -> list[dict[str, Any]]:
    return [e for e in data.get("errors") or [] if isinstance(e, dict)]


class CloudflareAPI:
    """The few Cloudflare API calls SentrAI needs. Every call is one HTTPS request with a Bearer token."""

    def __init__(self, token: str, zone_id: str = "", account_id: str = "", list_id: str = "",
                 timeout_s: float = 5.0, requester: Requester | None = None) -> None:
        if not token:
            raise ValueError("a Cloudflare API token is needed")
        if not zone_id and not account_id:
            raise ValueError("set CLOUDFLARE_ZONE_ID (one site) or CLOUDFLARE_ACCOUNT_ID (every site)")
        self._token = token
        self.zone_id = zone_id
        self.account_id = account_id
        self.list_id = list_id
        self.request = requester or _httpx_requester(timeout_s)

    def __repr__(self) -> str:  # never show the token
        return f"CloudflareAPI(zone_id={self.zone_id!r}, account_id={self.account_id!r})"

    def call(self, method: str, path: str, params: dict[str, Any] | None = None, body: Any = None) -> Any:
        headers = {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json",
                   "User-Agent": "SentrAI-cloudflare/1"}
        try:
            status, data = self.request(method, API + path, headers, params, body)
        except Exception as exc:  # network error or timeout
            raise CloudflareError(f"{type(exc).__name__}: {exc}"[:200]) from None
        if not 200 <= status < 300 or data.get("success") is False:
            errs = _errors(data)
            text = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in errs) or f"HTTP {status}"
            err = CloudflareError(text[:300])
            err.codes = {e.get("code") for e in errs}  # type: ignore[attr-defined]
            err.status = status  # type: ignore[attr-defined]
            raise err
        return data.get("result")

    # -- IP Access rules
    def _rules_path(self) -> str:
        return (f"/zones/{self.zone_id}" if self.zone_id else f"/accounts/{self.account_id}") + "/firewall/access_rules/rules"

    def find_rule(self, ip: str) -> dict[str, Any] | None:
        rows = self.call("GET", self._rules_path(), {"configuration.target": _target(ip), "configuration.value": ip,
                                                     "per_page": 5}) or []
        return next((r for r in rows if (r.get("configuration") or {}).get("value") == ip), None)

    def add_rule(self, ip: str, mode: str, note: str) -> str:
        r = self.call("POST", self._rules_path(), body={"mode": mode, "notes": note,
                                                        "configuration": {"target": _target(ip), "value": ip}})
        return str((r or {}).get("id") or "")

    def delete_rule(self, rule_id: str) -> None:
        self.call("DELETE", f"{self._rules_path()}/{rule_id}")

    # -- account IP list
    def _items_path(self) -> str:
        return f"/accounts/{self.account_id}/rules/lists/{self.list_id}/items"

    def find_item(self, ip: str) -> dict[str, Any] | None:
        rows = self.call("GET", self._items_path(), {"search": ip, "per_page": 25}) or []
        return next((r for r in rows if r.get("ip") == ip), None)

    def _wait(self, result: Any, wait_s: float = 5.0) -> None:
        """List writes are asynchronous: wait for the bulk operation to finish (or fail)."""
        op = (result or {}).get("operation_id") if isinstance(result, dict) else None
        if not op:
            return
        deadline = time.monotonic() + wait_s
        while True:
            st = self.call("GET", f"/accounts/{self.account_id}/rules/lists/bulk_operations/{op}") or {}
            if st.get("status") == "completed":
                return
            if st.get("status") == "failed":
                raise CloudflareError(f"list update failed: {st.get('error') or 'unknown error'}"[:200])
            if time.monotonic() >= deadline:
                raise CloudflareError("list update still pending after a few seconds")
            time.sleep(0.5)

    def add_item(self, ip: str, note: str) -> str:
        self._wait(self.call("POST", self._items_path(), body=[{"ip": ip, "comment": note}]))
        item = self.find_item(ip)
        if not item:
            raise CloudflareError("the address did not appear in the list")
        return str(item.get("id") or "")

    def delete_item(self, item_id: str) -> None:
        self._wait(self.call("DELETE", self._items_path(), body={"items": [{"id": item_id}]}))

    # -- connection test
    def check(self, method: str) -> str:
        """Reads (never writes) the place SentrAI would write to. Returns a short description."""
        if method == "list":
            info = self.call("GET", f"/accounts/{self.account_id}/rules/lists/{self.list_id}") or {}
            return f"IP list {info.get('name') or self.list_id} ({info.get('num_items', '?')} items)"
        self.call("GET", self._rules_path(), {"per_page": 1})
        return f"IP Access rules on {'zone ' + self.zone_id if self.zone_id else 'account ' + self.account_id}"


def _target(ip: str) -> str:
    return "ip6" if ipaddress.ip_address(ip).version == 6 else "ip"


def _private(ip: str) -> bool:
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


class CloudflareResponder(Responder):
    """`block_ip` through the local responder first, then at Cloudflare's edge."""

    name = "cloudflare"
    actions = ("block_ip",)

    def __init__(self, api: CloudflareAPI, method: str = "access_rule", mode: str = "block",
                 protected_ips: set[str] | None = None, inner: Responder | None = None) -> None:
        if method not in METHODS:
            raise ValueError(f"CLOUDFLARE_METHOD must be one of {', '.join(METHODS)} (got {method!r})")
        if mode not in MODES:
            raise ValueError(f"CLOUDFLARE_MODE must be one of {', '.join(MODES)} (got {mode!r})")
        if method == "list" and not (api.account_id and api.list_id):
            raise ValueError("CLOUDFLARE_METHOD=list needs CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_LIST_ID")
        self.api = api
        self.method = method
        self.mode = mode
        self.protected_ips = protected_ips if protected_ips is not None else set()
        self.inner = inner
        base = getattr(inner, "enforcement", "blocklist") if inner is not None else "blocklist"
        self.enforcement = f"{base} + Cloudflare ({'IP list' if method == 'list' else mode})"
        # Counted like the blocklist: two incidents blocking one address need two reverts to unblock it.
        self._refs: Counter[str] = Counter()
        self._ids: dict[str, str] = {}  # address -> Cloudflare rule or list item id SentrAI made
        self.last_ok: float | None = None
        self.last_error: str | None = None

    def _note(self, action: Action) -> str:
        return f"{NOTE_PREFIX} {action.get('incident') or ''} {action.get('action_id') or ''}".strip()[:500]

    def _ours(self, found: dict[str, Any] | None) -> str | None:
        """The id of an existing entry SentrAI made (adopted after a restart), None for anything else."""
        if not found:
            return None
        note = str(found.get("notes") or found.get("comment") or "")
        return str(found.get("id")) if note.startswith(NOTE_PREFIX) and found.get("id") else None

    def _ok(self) -> None:
        self.last_ok, self.last_error = time.time(), None

    def _fail(self, action: Action, key: str, exc: Exception, extra: dict[str, Any] | None = None) -> None:
        self.last_error = str(exc)[:300]
        action[key] = {"method": self.method, "ok": False, "error": self.last_error, **(extra or {})}
        log.warning("cloudflare %s failed for %s: %s", key, action.get("target"), self.last_error)

    def _add(self, ip: str, action: Action) -> str:
        """Adds the address, or adopts an entry SentrAI already made. Returns its id."""
        find = self.api.find_item if self.method == "list" else self.api.find_rule
        found = find(ip)
        mine = self._ours(found)
        if mine:
            return mine
        if found:  # someone added this address by hand: it is already covered, and never ours to delete
            return ""
        if self.method == "list":
            return self.api.add_item(ip, self._note(action))
        try:
            return self.api.add_rule(ip, self.mode, self._note(action))
        except CloudflareError as exc:
            if 10009 in getattr(exc, "codes", set()):  # duplicate: appeared between find and add
                return self._ours(find(ip)) or ""
            raise

    def apply(self, action: Action) -> bool:
        ok = self.inner.apply(action) if self.inner is not None else True
        ip = str(action.get("target") or "").strip()
        reason = unsafe_reason(ip, self.protected_ips) or ("private address" if _private(ip) else None)
        if reason:
            action["cloudflare"] = {"method": self.method, "skipped": reason}
            return ok
        self._refs[ip] += 1
        if ip in self._ids or self._refs[ip] > 1:  # another incident already blocked it at Cloudflare
            action["cloudflare"] = {"method": self.method, "ok": True, "already_blocked": True}
            return ok
        try:
            rid = self._add(ip, action)
        except CloudflareError as exc:
            self._refs[ip] -= 1
            if self._refs[ip] <= 0:
                del self._refs[ip]
            self._fail(action, "cloudflare", exc)
            return ok  # the local block still counts; the Cloudflare failure is on the action
        if rid:
            self._ids[ip] = rid
        action["cloudflare"] = {"method": self.method, "mode": self.mode, "ok": True,
                                **({"id": rid} if rid else {"note": "already blocked in Cloudflare by hand"})}
        self._ok()
        return ok

    def revert(self, action: Action) -> bool | None:
        ok = self.inner.revert(action) if self.inner is not None else True
        ip = str(action.get("target") or "").strip()
        if ip not in self._refs:
            return ok  # skipped, failed to add, or already reverted
        self._refs[ip] -= 1
        if self._refs[ip] > 0:
            return ok  # another incident still holds this block
        del self._refs[ip]
        rid = self._ids.get(ip)
        if not rid:
            return ok  # covered by an entry SentrAI did not make: leave it alone
        try:
            (self.api.delete_item if self.method == "list" else self.api.delete_rule)(rid)
        except CloudflareError as exc:
            if getattr(exc, "status", None) == 404:  # already gone (removed by hand)
                self._ids.pop(ip, None)
                action["cloudflare_revert"] = {"method": self.method, "ok": True, "note": "already removed"}
                return ok
            self._refs[ip] += 1  # still in Cloudflare: keep tracking it so the retry tries again
            self._fail(action, "cloudflare_revert", exc, {"id": rid})
            return False
        self._ids.pop(ip, None)
        action["cloudflare_revert"] = {"method": self.method, "ok": True, "id": rid}
        self._ok()
        return ok

    def reset(self) -> None:
        for ip, rid in sorted(self._ids.items()):
            try:
                (self.api.delete_item if self.method == "list" else self.api.delete_rule)(rid)
            except CloudflareError as exc:
                log.warning("cloudflare reset could not remove %s: %s", ip, exc)
        self._refs.clear()
        self._ids.clear()
        if self.inner is not None:
            self.inner.reset()

    # Pass-throughs so the core can treat this like the blocklist responder it wraps.
    def blocklist(self) -> dict[str, list[str]]:
        return self.inner.blocklist() if self.inner is not None and hasattr(self.inner, "blocklist") else {"ips": [], "users": []}

    def status(self) -> dict[str, Any]:
        return {"method": self.method, "mode": self.mode, "blocked": sorted(self._ids), "last_error": self.last_error}

    def test(self) -> dict[str, Any]:
        try:
            where = self.api.check(self.method)
        except CloudflareError as exc:
            self.last_error = str(exc)[:300]
            return {"ok": False, "error": self.last_error}
        self._ok()
        return {"ok": True, "detail": f"Token works. SentrAI will block through {where}."}


def from_settings(s: Any, inner: Responder, requester: Requester | None = None) -> CloudflareResponder | None:
    """The Cloudflare responder, or None when no token is set. Bad settings raise ValueError."""
    if not s.cloudflare_api_token:
        return None
    api = CloudflareAPI(s.cloudflare_api_token, s.cloudflare_zone_id, s.cloudflare_account_id, s.cloudflare_list_id,
                        s.cloudflare_timeout_s, requester)
    return CloudflareResponder(api, s.cloudflare_method, s.cloudflare_mode, s.protected_ips, inner=inner)
