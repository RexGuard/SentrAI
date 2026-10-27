"""Part 2 of 3: the classifier. Labels one event with a category and confidence.

A classifier is any `Classifier` subclass: implement `classify()` and return a
`Classification`, or None to hand the event to the next classifier. `ClassifierChain`
runs them in order: rules, then the steps added extensions bring (TypeSafe's Jev, in
mvp/extensions/typesafe), then the fallback keywords.

Output confidence is always clipped to 0.5-1.0 (the AI Confidence Factor).
`malicious` is the probability that the event is part of an attack; 0.4-0.6 means
"needs review" (never auto-contained), < 0.4 means no incident.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote_plus

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

    def begin(self) -> None:
        """A new batch of events arrived (one POST /events): start its time budget, if it has one."""

    def reset(self) -> None:
        """Forget what it learned (demo reset)."""


class ClassifierChain:
    """Asks each classifier in turn; the first answer wins."""

    def __init__(self, *classifiers: Classifier) -> None:
        self.classifiers = list(classifiers)

    def begin(self) -> None:
        for c in self.classifiers:
            c.begin()

    def reset(self) -> None:
        for c in self.classifiers:
            c.reset()

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
        malicious = hit.malicious if hit.malicious is not None else 0.0 if hit.category == "benign" else 1.0
        return Classification(hit.category, 1.0, malicious, hit.reason, hit.related_event_ids)


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
    """Keyword heuristic used when the rules (and any classifier extension) give no answer. Always answers."""

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


def default_chain(rules: RulesEngine) -> ClassifierChain:
    """rules -> fallback: what the core runs with no classifier extension added."""
    return ClassifierChain(RulesClassifier(rules), FallbackClassifier())
