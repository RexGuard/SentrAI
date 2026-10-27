"""AbuseIPDB extension, core part: what the internet already knows about an attacking address.

When an incident opens with a public source address, SentrAI asks AbuseIPDB how often other people have
reported it, and writes the answer on the incident ("reported 312 times, 100% abuse confidence, ISP,
country, Tor exit"). It is context for the person deciding, not evidence: it never opens, closes or scores
an incident by itself.

Settings (extension.json): ABUSEIPDB_API_KEY (or ABUSEIPDB_API_KEY_FILE). ABUSEIPDB_CACHE_HOURS (default
24) keeps each answer so a busy attacker costs one lookup a day (the free plan allows 1,000).

Lookups run on one background thread, so a slow or missing AbuseIPDB never holds up detection. Private,
loopback and protected addresses are never sent.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from app.extensions import Context, Extension, NotSetUp, is_protected, when

log = logging.getLogger("sentrai.ext.abuseipdb")

API = "https://api.abuseipdb.com/api/v2/check"
CACHE_SIZE = 2048

# getter(url, headers, params) -> (HTTP status, parsed JSON or {}); raises on network errors.
Getter = Callable[[str, dict[str, str], dict[str, Any]], "tuple[int, dict[str, Any]]"]


def _httpx_getter(timeout_s: float) -> Getter:
    import httpx

    def get(url: str, headers: dict[str, str], params: dict[str, Any]) -> tuple[int, dict]:
        r = httpx.get(url, headers=headers, params=params, timeout=timeout_s, follow_redirects=False)
        try:
            data = r.json()
        except ValueError:
            data = {}
        return r.status_code, data if isinstance(data, dict) else {}

    return get


def lookable(ip: str, protected: set[str] | None = None) -> bool:
    """Only public addresses that are not protected are ever sent."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not is_protected(ip, protected or set())


def summary(rep: dict[str, Any]) -> str:
    """One line for timelines and alerts."""
    if rep.get("error"):
        return f"AbuseIPDB lookup failed: {rep['error']}"
    bits = [f"reported {rep.get('reports', 0)} time(s)", f"{rep.get('score', 0)}% abuse confidence"]
    if rep.get("isp"):
        bits.append(str(rep["isp"]))
    if rep.get("country"):
        bits.append(str(rep["country"]))
    if rep.get("tor"):
        bits.append("Tor exit node")
    return "AbuseIPDB: " + ", ".join(bits)


class AbuseIPDB:
    name = "abuseipdb"

    def __init__(self, api_key: str, cache_hours: float = 24.0, timeout_s: float = 4.0,
                 getter: Getter | None = None) -> None:
        if not api_key:
            raise ValueError("an AbuseIPDB API key is needed")
        self._key = api_key
        self.ttl_s = max(0.0, cache_hours) * 3600
        self.get = getter or _httpx_getter(timeout_s)
        self._cache: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
        self._lock = threading.Lock()
        self.lookups = 0
        self.last_ok: float | None = None
        self.last_error: str | None = None

    def __repr__(self) -> str:  # never show the key
        return "AbuseIPDB()"

    def check(self, ip: str) -> dict[str, Any]:
        """The reputation of one address, from the cache when fresh. Never raises."""
        with self._lock:
            hit = self._cache.get(ip)
            if hit and time.time() - hit[0] < self.ttl_s:
                self._cache.move_to_end(ip)
                return {**hit[1], "cached": True}
        try:
            status, data = self.get(API, {"Key": self._key, "Accept": "application/json"},
                                    {"ipAddress": ip, "maxAgeInDays": 90})
        except Exception as exc:  # network error or timeout
            return self._failed(f"{type(exc).__name__}: {exc}")
        if status != 200:
            errs = data.get("errors") or []
            detail = errs[0].get("detail") if errs and isinstance(errs[0], dict) else None
            return self._failed(detail or f"HTTP {status}")
        d = data.get("data") or {}
        rep = {"source": "AbuseIPDB", "ip": ip, "score": int(d.get("abuseConfidenceScore") or 0),
               "reports": int(d.get("totalReports") or 0), "country": d.get("countryCode"), "isp": d.get("isp"),
               "usage": d.get("usageType"), "domain": d.get("domain"), "tor": bool(d.get("isTor")),
               "last_reported": d.get("lastReportedAt"), "checked_at": time.time()}
        with self._lock:
            self.lookups += 1
            self.last_ok, self.last_error = time.time(), None
            self._cache[ip] = (time.time(), rep)
            while len(self._cache) > CACHE_SIZE:
                self._cache.popitem(last=False)
        return rep

    def _failed(self, error: str) -> dict[str, Any]:
        self.last_error = error[:200]
        log.warning("AbuseIPDB lookup failed: %s", self.last_error)
        return {"source": "AbuseIPDB", "error": self.last_error}

    def test(self) -> dict[str, Any]:
        rep = self.check("1.1.1.1")  # a well-known public resolver: always answers, never abusive
        if rep.get("error"):
            return {"ok": False, "error": rep["error"]}
        return {"ok": True, "detail": "Key works. Each new attacking address will be looked up once a day at most."}


class Lookups:
    """Runs lookups on one background thread and hands each answer to `on_result(ip, reputation)`."""

    def __init__(self, client: AbuseIPDB, on_result: Callable[[str, dict[str, Any]], None],
                 protected: set[str] | None = None, background: bool = True) -> None:
        self.client = client
        self.on_result = on_result
        self.protected = protected or set()
        self._pool = ThreadPoolExecutor(1, thread_name_prefix="abuseipdb") if background else None
        self.closed = False

    def request(self, ip: str | None) -> bool:
        """Queues a lookup for a public address. Returns False when the address is never sent."""
        if not ip or not lookable(ip, self.protected):
            return False
        if self._pool is None:
            self._run(ip)
        else:
            self._pool.submit(self._run, ip)
        return True

    def _run(self, ip: str) -> None:
        if self.closed:
            return
        try:
            self.on_result(ip, self.client.check(ip))
        except Exception:  # a broken callback must not kill the worker
            log.exception("could not record the AbuseIPDB answer for %s", ip)

    def close(self) -> None:
        """Removed: queued lookups are dropped, a running one finishes without being recorded."""
        self.closed = True
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)


def _n(n: int, word: str) -> str:
    return f"{n} {word if n == 1 else word + 's'}"


class Reputation(Extension):
    def __init__(self, ctx: Context, client: AbuseIPDB) -> None:
        self.ctx = ctx
        self.client = client
        self.lookups = Lookups(client, self._answer, ctx.settings.protected_ips, ctx.settings.background)

    def incident_opened(self, inc: dict[str, Any]) -> None:
        self.lookups.request(inc.get("src_ip"))

    def _answer(self, ip: str, rep: dict[str, Any]) -> None:
        if self.lookups.closed:
            return
        self.ctx.note(ip, "reputation", rep, summary(rep))
        self.ctx.record("reputation_lookup", {"ip": ip, **{k: v for k, v in rep.items()
                                                          if k in ("score", "reports", "country", "error")}})

    def status(self) -> dict[str, Any]:
        c = self.client
        return {"configured": True, "testable": True, "last_ok": when(c.last_ok), "last_error": c.last_error,
                "detail": f"{_n(c.lookups, 'lookup')} since start, answers kept {c.ttl_s / 3600:g} h"}

    def test(self) -> dict[str, Any]:
        return self.client.test()

    def close(self) -> None:
        self.lookups.close()


def setup(ctx: Context, getter: Getter | None = None) -> Extension:
    key = ctx.setting("ABUSEIPDB_API_KEY")
    if not key:
        return NotSetUp("Paste a free API key to turn it on.")
    return Reputation(ctx, AbuseIPDB(key, ctx.number("ABUSEIPDB_CACHE_HOURS", 24.0), getter=getter))
