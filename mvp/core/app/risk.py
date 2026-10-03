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
}

BANDS = ["green", "amber", "red", "critical"]


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


def clip_confidence(value: float) -> float:
    return round(min(1.0, max(0.5, float(value))), 3)


def inaction_penalty(unacked_demo_hours: float, per_hour: float = 5.0, cap: float = 30.0) -> float:
    return float(min(cap, per_hour * math.floor(max(0.0, unacked_demo_hours))))
