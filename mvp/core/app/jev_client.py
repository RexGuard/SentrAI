"""Stage 2: Jev (TypeSafe System One) client.

Active only when TYPESAFE_API_KEY is set AND `typesafe_sdk` imports. Every call is
wrapped in a timeout and try/except; after repeated failures a short circuit breaker
opens so ingestion never stalls. When unavailable, classify() returns None and the
caller uses the fallback heuristic.
"""

from __future__ import annotations

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from .risk import CATEGORIES

log = logging.getLogger("cactai.jev")

# Choice criteria: label -> description string (SDK accepts str or None per label).
CATEGORY_DESCRIPTIONS: dict[str, str] = {
    "benign": "Normal use: ordinary page views, successful logins, routine queries.",
    "brute_force": "Repeated password guessing or many failed logins against an account.",
    "sql_injection": "SQL syntax injected into input, e.g. ' OR 1=1, UNION SELECT, comment sequences.",
    "xss": "Script or HTML injected into input, e.g. <script>, javascript:, onerror=.",
    "port_scan": "Probing many ports or services on a host.",
    "privilege_escalation": "A process gaining higher privileges or a web server spawning a shell.",
    "data_exfiltration": "Bulk export or copy of data out of the system.",
    "misconfiguration": "Insecure configuration such as public buckets, open admin ports, default passwords.",
    "log_tampering": "Deleting, emptying or editing logs or shell history, or stopping logging, to hide activity.",
    "malware": "A web shell, backdoor, reverse shell, crypto miner or container escape tool on the host.",
}
assert set(CATEGORY_DESCRIPTIONS) == set(CATEGORIES)


@dataclass
class JevResult:
    category: str
    confidence: float
    malicious: float
    probabilities: dict[str, float]


class JevClient:
    def __init__(self, timeout_s: float = 3.0) -> None:
        self.timeout_s = timeout_s
        self.enabled = False
        self.status = "disabled"
        self.calls = 0
        self.failures = 0
        self.last_error: str | None = None
        self._consecutive_failures = 0
        self._open_until = 0.0
        self._client: Any = None
        self._questions: dict[str, Any] = {}
        self._pool: ThreadPoolExecutor | None = None

        api_key = os.getenv("TYPESAFE_API_KEY", "").strip()
        if not api_key:
            self.status = "disabled: TYPESAFE_API_KEY not set (fallback classifier in use)"
            return
        try:
            from typesafe_sdk import Choice, Noul, TypeSafeClient  # type: ignore

            try:
                from typesafe_sdk import RetryPolicy  # type: ignore

                self._client = TypeSafeClient(api_key=api_key, timeout=timeout_s, retry=RetryPolicy(max_retries=0))
            except Exception:  # older SDK without RetryPolicy / kwargs
                self._client = TypeSafeClient(api_key=api_key)
            self._questions = {
                "category": Choice(
                    instructions="What kind of activity does `event.raw` show?",
                    criteria=CATEGORY_DESCRIPTIONS,
                ),
                "malicious": Noul(instructions="Is `event.raw` likely part of an attack rather than normal use?"),
            }
            self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="jev")
            self.enabled = True
            self.status = "enabled"
        except Exception as exc:  # import or construction failed
            self.status = f"disabled: typesafe_sdk unavailable ({type(exc).__name__})"
            self.last_error = str(exc)

    def available(self) -> bool:
        return self.enabled and time.time() >= self._open_until

    def classify(self, event: dict[str, Any]) -> JevResult | None:
        if not self.available() or self._pool is None:
            return None
        state = {
            "event": {
                "layer": event.get("layer"),
                "source": event.get("source"),
                "host": event.get("host"),
                "raw": event.get("raw"),
            }
        }
        self.calls += 1
        try:
            fut = self._pool.submit(self._client.system_one, state=state, questions=self._questions)
            resp = fut.result(timeout=self.timeout_s + 0.5)
            result = self._parse(resp)
            self._consecutive_failures = 0
            return result
        except Exception as exc:
            self.failures += 1
            self._consecutive_failures += 1
            self.last_error = f"{type(exc).__name__}: {exc}"[:300]
            log.warning("Jev call failed: %s", self.last_error)
            if self._consecutive_failures >= 3:
                self._open_until = time.time() + 60.0  # circuit breaker
            return None

    @staticmethod
    def _answer(resp: Any, group: str, name: str) -> Any:
        try:
            return getattr(resp, group)[name]
        except Exception:
            ans = resp.answers[name]
            return getattr(ans, "root", ans)

    def _parse(self, resp: Any) -> JevResult:
        cat = self._answer(resp, "choices", "category")
        mal = self._answer(resp, "nouls", "malicious")
        choice = str(cat.choice)
        probs = dict(getattr(cat, "probabilities", {}) or {})
        conf = getattr(cat, "confidence", None)
        if conf is None:
            conf = probs.get(choice, 0.5)
        if choice not in CATEGORIES:
            raise ValueError(f"unexpected category {choice!r}")
        return JevResult(category=choice, confidence=float(conf), malicious=float(mal.noul), probabilities=probs)
