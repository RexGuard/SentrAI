"""Part 2 of 3: the classifier. Labels one event with a category and confidence.

A classifier is any `Classifier` subclass: implement `classify()` and return a
`Classification`, or None to hand the event to the next classifier. `ClassifierChain`
runs them in order; the default chain is rules -> Jev -> fallback keywords.

Output confidence is always clipped to 0.5-1.0 (the AI Confidence Factor).
`malicious` is the probability that the event is part of an attack; 0.4-0.6 means
"needs review" (never auto-contained), < 0.4 means no incident.
"""

from __future__ import annotations

import math
import re
import threading
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote_plus

from .jev_client import JevClient, JevResult
from .risk import clip_confidence
from .rules import RulesEngine


@dataclass
class Classification:
    category: str
    confidence: float
    malicious: float
    reason: str
    related_event_ids: list[str] = field(default_factory=list)
    classified_by: str = ""  # stamped by ClassifierChain with the classifier's name


class Classifier(ABC):
    """One classification step. Return None when this classifier cannot decide."""

    name = "classifier"

    @abstractmethod
    def classify(self, event: dict[str, Any], now: float) -> Classification | None: ...


class ClassifierChain:
    """Asks each classifier in turn; the first answer wins."""

    def __init__(self, *classifiers: Classifier) -> None:
        self.classifiers = list(classifiers)

    def classify(self, event: dict[str, Any], now: float) -> Classification:
        for c in self.classifiers:
            result = c.classify(event, now)
            if result is not None:
                result.classified_by = result.classified_by or c.name
                return result
        return Classification("benign", 0.5, 0.0, "no classifier recognised the event", classified_by="none")


class RulesClassifier(Classifier):
    """Deterministic signatures and thresholds (rules.py). Always confidence 1.0."""

    name = "rules"

    def __init__(self, rules: RulesEngine) -> None:
        self.rules = rules

    def classify(self, event: dict[str, Any], now: float) -> Classification | None:
        hit = self.rules.check(event, now)
        if hit is None:
            return None
        malicious = 0.0 if hit.category == "benign" else 1.0
        return Classification(hit.category, 1.0, malicious, hit.reason, hit.related_event_ids)


# What varies between two copies of the same log line: addresses, times, ids, pids and ports.
_TEMPLATE_RX = [
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<ts>"),
    (re.compile(r"\[\d{1,2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]"), "<ts>"),  # nginx [19/Oct/2026:10:00:00 +0000]
    (re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"), "<ts>"),
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "<ts>"),
    (re.compile(r"\b\d{9,13}(?:\.\d+)?\b"), "<ts>"),  # unix time
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<id>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    (re.compile(r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])", re.I), "<ip>"),
    (re.compile(r"\b[0-9a-f]{16,}\b", re.I), "<hex>"),
    (re.compile(r"\[\d+\]"), "[<pid>]"),
    (re.compile(r"\bport\s+\d+\b", re.I), "port <n>"),
]


def log_template(event: dict[str, Any]) -> str:
    """The cache key: where the line came from plus its text with the varying parts replaced, so
    the same request from many IPs, or repeated over a day, is asked about once."""
    text = str(event.get("raw") or "")
    for rx, repl in _TEMPLATE_RX:
        text = rx.sub(repl, text)
    return f"{event.get('layer')}|{event.get('source')}|{' '.join(text.split())}"


class JevCache:
    """Least-recently-used answers from Jev, keyed on the log template. Thread-safe."""

    def __init__(self, size: int = 2048, ttl_s: float = 3600.0) -> None:
        self.size = max(0, size)
        self.ttl_s = ttl_s
        self.hits = 0
        self.misses = 0
        self._items: OrderedDict[str, tuple[float, JevResult]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> JevResult | None:
        with self._lock:
            item = self._items.get(key)
            if item is not None and (self.ttl_s <= 0 or time.monotonic() - item[0] < self.ttl_s):
                self._items.move_to_end(key)
                self.hits += 1
                return item[1]
            if item is not None:
                del self._items[key]  # expired
            self.misses += 1
            return None

    def put(self, key: str, result: JevResult) -> None:
        if self.size == 0:
            return
        with self._lock:
            self._items[key] = (time.monotonic(), result)
            self._items.move_to_end(key)
            while len(self._items) > self.size:
                self._items.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def __len__(self) -> int:
        return len(self._items)

    def stats(self) -> dict[str, Any]:
        return {"size": len(self), "max": self.size, "hits": self.hits, "misses": self.misses}


class JevClassifier(Classifier):
    """TypeSafe System One. Skipped once the per-request time budget (`deadline`) is spent;
    a cached answer for the same log template is used without calling Jev at all."""

    name = "jev"

    def __init__(self, jev: JevClient, cache: JevCache | None = None) -> None:
        self.jev = jev
        self.cache = cache if cache is not None else JevCache()
        self.deadline = math.inf  # set per ingest request by Saguaro

    def classify(self, event: dict[str, Any], now: float) -> Classification | None:
        if not getattr(self.jev, "enabled", True):
            return None  # no key: nothing was ever cached, skip the template work
        key = log_template(event)
        r = self.cache.get(key)
        cached = r is not None
        if r is None:
            if time.monotonic() >= self.deadline:
                return None
            r = self.jev.classify(event)
            if r is None:
                return None
            self.cache.put(key, r)
        return Classification(
            r.category, clip_confidence(r.confidence), round(r.malicious, 3),
            f"Jev System One: {r.category} p={r.confidence:.2f}, malicious p={r.malicious:.2f}"
            + (" (cached: same log template)" if cached else ""),
        )


# (patterns, category, confidence 0.5-0.8, malicious probability). Whole-word regexes so
# ordinary text ("oracle", "scandal", a SELECT in a routine query log) does not trip them.
FALLBACK_TABLE: list[tuple[tuple[str, ...], str, float, float]] = [
    ((r"\bsudo\s", r"chmod\s+\+s", r"/etc/shadow", r"\bwhoami\b", r"/bin/sh\b", r"\bcmd\.exe\b", r"powershell\s+-e"), "privilege_escalation", 0.7, 0.75),
    ((r"\bdrop\s+table\b", r"\binformation_schema\b", r"\bsleep\s*\(", r"'\s*or\b", r"\"\s*or\b"), "sql_injection", 0.65, 0.7),
    ((r"<img\b", r"<svg\b", r"\balert\s*\(", r"document\.cookie"), "xss", 0.65, 0.7),
    ((r"\bxmrig\b", r"stratum\+tcp://", r"/dev/tcp/\S+", r"\bweb\s?shell\b", r"\bc99shell\b"), "malware", 0.7, 0.75),
    ((r"\bnmap\b", r"\bmasscan\b", r"\bsyn\s+scan\b", r"\bport\s*scan"), "port_scan", 0.7, 0.75),
    ((r"\bpublic-read\b", r"0\.0\.0\.0/0", r"\bpublic\s+acl\b", r"\bdefault\s+password\b", r"\bport\s+22\s+open\b"), "misconfiguration", 0.75, 0.7),
    ((r"\bdump\b", r"\bbulk\b", r"\bcopy\s+\w+\s+to\b", r"\bdownload\s+all\b"), "data_exfiltration", 0.6, 0.55),  # weak -> needs review
    ((r"\bbrute\b", r"\btoo\s+many\s+login", r"\baccount\s+locked\b"), "brute_force", 0.6, 0.55),
]
_FALLBACK_RX = [(tuple(re.compile(p, re.I) for p in pats), cat, conf, mal) for pats, cat, conf, mal in FALLBACK_TABLE]


class FallbackClassifier(Classifier):
    """Keyword heuristic used when rules and Jev give no answer. Always answers."""

    name = "fallback"

    def classify(self, event: dict[str, Any], now: float = 0.0) -> Classification:
        text = unquote_plus(str(event.get("raw") or "")).lower()
        for patterns, category, conf, mal in _FALLBACK_RX:
            m = next((m for rx in patterns if (m := rx.search(text))), None)
            if m:
                return Classification(category, clip_confidence(conf), mal, f"fallback heuristic: matched '{m.group(0).strip()}'")
        if any(k in text for k in (" 401", " 403", "denied", "unauthorized")):
            return Classification("benign", 0.6, 0.3, "fallback heuristic: isolated access denial")
        if any(k in text for k in (" 500", " 502", " 503", "error")):
            return Classification("benign", 0.6, 0.35, "fallback heuristic: server error, no attack signature")
        return Classification("benign", 0.8, 0.1, "fallback heuristic: no suspicious markers")


def default_chain(rules: RulesEngine, jev: JevClient,
                  cache: JevCache | None = None) -> tuple[ClassifierChain, JevClassifier]:
    """rules -> Jev -> fallback. Returns the Jev step too so Saguaro can set its time budget."""
    jev_step = JevClassifier(jev, cache)
    return ClassifierChain(RulesClassifier(rules), jev_step, FallbackClassifier()), jev_step
