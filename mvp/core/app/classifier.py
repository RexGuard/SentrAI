"""Three-stage classification: rules -> Jev -> fallback heuristic.

Output confidence is always clipped to 0.5-1.0 (the AI Confidence Factor).
`malicious` is the probability that the event is part of an attack; 0.4-0.6 means
"needs review" (never auto-contained), < 0.4 means no incident.
"""

from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote_plus

from .jev_client import JevClient
from .risk import clip_confidence
from .rules import RulesEngine


@dataclass
class Classification:
    category: str
    confidence: float
    malicious: float
    classified_by: str  # rules | jev | fallback
    reason: str
    related_event_ids: list[str] = field(default_factory=list)


# (patterns, category, confidence 0.5-0.8, malicious probability). Whole-word regexes so
# ordinary text ("oracle", "scandal", a SELECT in a routine query log) does not trip them.
FALLBACK_TABLE: list[tuple[tuple[str, ...], str, float, float]] = [
    ((r"\bsudo\s", r"chmod\s+\+s", r"/etc/shadow", r"\bwhoami\b", r"/bin/sh\b", r"\bcmd\.exe\b", r"powershell\s+-e"), "privilege_escalation", 0.7, 0.75),
    ((r"\bdrop\s+table\b", r"\binformation_schema\b", r"\bsleep\s*\(", r"'\s*or\b", r"\"\s*or\b"), "sql_injection", 0.65, 0.7),
    ((r"<img\b", r"<svg\b", r"\balert\s*\(", r"document\.cookie"), "xss", 0.65, 0.7),
    ((r"\bnmap\b", r"\bmasscan\b", r"\bsyn\s+scan\b", r"\bport\s*scan"), "port_scan", 0.7, 0.75),
    ((r"\bpublic-read\b", r"0\.0\.0\.0/0", r"\bpublic\s+acl\b", r"\bdefault\s+password\b", r"\bport\s+22\s+open\b"), "misconfiguration", 0.75, 0.7),
    ((r"\bdump\b", r"\bbulk\b", r"\bcopy\s+\w+\s+to\b", r"\bdownload\s+all\b"), "data_exfiltration", 0.6, 0.55),  # weak -> needs review
    ((r"\bbrute\b", r"\btoo\s+many\s+login", r"\baccount\s+locked\b"), "brute_force", 0.6, 0.55),
]
_FALLBACK_RX = [(tuple(re.compile(p, re.I) for p in pats), cat, conf, mal) for pats, cat, conf, mal in FALLBACK_TABLE]


def fallback_classify(event: dict[str, Any]) -> Classification:
    text = unquote_plus(str(event.get("raw") or "")).lower()
    for patterns, category, conf, mal in _FALLBACK_RX:
        m = next((m for rx in patterns if (m := rx.search(text))), None)
        if m:
            return Classification(
                category, clip_confidence(conf), mal, "fallback", f"fallback heuristic: matched '{m.group(0).strip()}'"
            )
    if any(k in text for k in (" 401", " 403", "denied", "unauthorized")):
        return Classification("benign", 0.6, 0.3, "fallback", "fallback heuristic: isolated access denial")
    if any(k in text for k in (" 500", " 502", " 503", "error")):
        return Classification("benign", 0.6, 0.35, "fallback", "fallback heuristic: server error, no attack signature")
    return Classification("benign", 0.8, 0.1, "fallback", "fallback heuristic: no suspicious markers")


class Classifier:
    def __init__(self, rules: RulesEngine, jev: JevClient) -> None:
        self.rules = rules
        self.jev = jev
        self.jev_deadline = math.inf  # set per ingest request by Saguaro

    def classify(self, event: dict[str, Any], now: float) -> Classification:
        hit = self.rules.check(event, now)
        if hit is not None:
            return Classification(
                hit.category,
                1.0,
                0.0 if hit.category == "benign" else 1.0,
                "rules",
                hit.reason,
                hit.related_event_ids,
            )
        result = self.jev.classify(event) if time.monotonic() < self.jev_deadline else None
        if result is not None:
            return Classification(
                result.category,
                clip_confidence(result.confidence),
                round(result.malicious, 3),
                "jev",
                f"Jev System One: {result.category} p={result.confidence:.2f}, malicious p={result.malicious:.2f}",
            )
        return fallback_classify(event)
