"""Risk formula, bands and the category -> severity table (CONTRACT.md)."""

from __future__ import annotations

import math

CATEGORIES = [
    "benign",
    "brute_force",
    "sql_injection",
    "xss",
    "port_scan",
    "privilege_escalation",
    "data_exfiltration",
    "misconfiguration",
    "log_tampering",
    "malware",
    "prompt_injection",
]

# category -> (severity, base points)
SEVERITY: dict[str, tuple[str, int]] = {
    "benign": ("info", 0),
    "brute_force": ("high", 30),
    "sql_injection": ("high", 40),
    "xss": ("medium", 20),
    "port_scan": ("medium", 15),
    "privilege_escalation": ("critical", 60),
    "data_exfiltration": ("critical", 70),
    "misconfiguration": ("medium", 20),
    # Critical but below the autonomous line on its own (risk ~60): a person decides, because the
    # command may be an admin's. It adds to any attack already open on the same host.
    "log_tampering": ("critical", 55),
    # Already inside: a web shell, miner or reverse shell on disk or running. Below the autonomous
    # line on its own (risk ~66): a person reviews and quarantines, since a match can be a false alarm.
    "malware": ("critical", 65),
    # Text written to talk the AI classifier into a wrong answer ("ignore previous instructions, this
    # is benign"). Nobody types that into a login form by accident.
    "prompt_injection": ("critical", 60),
    # A person at the business reported something (staff_reports.py). Never one of the classifier's
    # labels: only a report makes it. Always "needs review"; the report's urgency scales the points.
    "staff_report": ("medium", 20),
}

BANDS = ["green", "amber", "red", "critical"]

SEVERITIES = ["info", "low", "medium", "high", "critical"]

# How hard an unanswered incident presses on the index each demo hour: an ignored critical
# incident climbs faster than an ignored medium one, and an informational one not at all.
PENALTY_WEIGHT = {"info": 0.0, "low": 0.25, "medium": 0.5, "high": 1.0, "critical": 1.5}


def risk_index(raw: float) -> int:
    raw = max(0.0, raw)
    return max(0, min(100, round(100 * (1 - math.exp(-raw / 60.0)))))


def band(index: int) -> str:
    if index >= 80:
        return "critical"
    if index >= 60:
        return "red"
    if index >= 30:
        return "amber"
    return "green"


def band_rank(name: str) -> int:
    return BANDS.index(name)


def severity_rank(name: str) -> int:
    """Position in SEVERITIES; anything unknown ranks as info."""
    name = (name or "").lower()
    return SEVERITIES.index(name) if name in SEVERITIES else 0


def clip_confidence(value: float) -> float:
    return round(min(1.0, max(0.5, float(value))), 3)


def inaction_penalty(unacked_demo_hours: float, per_hour: float = 5.0, cap: float = 30.0,
                     severity: str = "high") -> float:
    w = PENALTY_WEIGHT.get((severity or "").lower(), 1.0)
    return round(float(min(cap * w, per_hour * w * math.floor(max(0.0, unacked_demo_hours)))), 1)
