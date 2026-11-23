"""A plain risk tag on every approval: how much could go wrong if a person says yes, worked out by fixed rules.

Each waiting approval gets low / medium / high, a 0 to 100 score and the reasons in everyday words ("locks the
admin account", "blocks an address inside your own network"). No AI is asked: the same incident always gets the
same tag, it is worked out again each time the list is shown, and every point can be traced to a reason. The
Approvals page sorts by it and offers "Approve all low".

This is about the fix, not the attack: a high tag means "look before you say yes", not "this attack is worse".
"""
from __future__ import annotations

import ipaddress
from typing import Any, Iterable

from .rules import TRIPWIRE_REASONS, TRIPWIRE_SOURCES

LEVELS = ((60, "high"), (30, "medium"), (0, "low"))
WORDS = {"low": "Low risk to approve", "medium": "Check before approving", "high": "Look closely first"}

# What each kind of fix can break.
ACTION_POINTS = {
    "block_ip": (15, "blocks one internet address"),
    "lock_user": (30, "locks an account, so that person cannot sign in until it is unlocked"),
    "rate_limit": (5, "slows one page down for one address"),
    "waf_rule": (5, "adds a web filter rule"),
    "kill_process": (25, "stops a running program"),
    "revoke_public_acl": (25, "takes public access away from a file or folder"),
}
ADMIN_NAMES = {"admin", "administrator", "root", "sysadmin", "superuser", "sa", "postgres", "owner"}


# A company's own network: office and home ranges, the carrier range some routers use, the machine itself.
# (Not ipaddress.is_private, which also counts the documentation and benchmark ranges.)
OWN_NETWORK = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10")]


def _private(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("/")[0])
    except ValueError:
        return False
    return any(ip.version == n.version and ip in n for n in OWN_NETWORK)


def _fixes(inc: dict, planned: list[dict] | None) -> list[dict[str, Any]]:
    """The fixes in question: those in force now on a contained incident (keep or roll back), otherwise the ones
    a yes would apply (Saguaro.planned_fixes), without those the safety check would hold back anyway."""
    if inc.get("status") == "contained":
        return [{"type": str(a.get("type")), "target": str(a.get("target") or "")}
                for a in inc.get("actions") or [] if isinstance(a, dict) and a.get("status") == "active"]
    return [{"type": str(p.get("type")), "target": str(p.get("target") or ""), "admin": bool(p.get("admin_address"))}
            for p in planned or [] if p.get("allowed", True)]


def score(inc: dict, planned: list[dict] | None = None, seen_on: Iterable[str] = ()) -> dict[str, Any]:
    """{"level", "word", "score", "reasons"} for one approval. planned: Saguaro.planned_fixes()[id];
    seen_on: the machines the same attacking address shows up on."""
    points = 0
    reasons: list[str] = []

    def add(n: int, why: str) -> None:
        nonlocal points
        points += n
        reasons.append(why)

    fixes = _fixes(inc, planned)
    if not fixes:
        add(10, "SentrAI could not tell exactly what a yes would change")
    for p in fixes:
        n, why = ACTION_POINTS.get(p["type"], (20, f"makes a change ({p['type'].replace('_', ' ')})"))
        add(n, why + (f" ({p['target']})" if p["target"] else ""))
        if p["type"] == "lock_user" and p["target"].lower() in ADMIN_NAMES:
            add(20, f"'{p['target']}' looks like an administrator account: locking it can lock your own team out")
        if p["type"] in ("block_ip", "rate_limit") and _private(p["target"]):
            add(30, f"{p['target']} is inside your own network: it may be a staff computer or the office router")
        if p.get("admin"):
            add(30, f"one of your administrators has signed in from {p['target']}: blocking it may lock them out")
    hosts = sorted(set(seen_on) - {str(inc.get("host") or "")})
    if len(hosts) >= 2:
        add(10, f"the same address also shows up on {len(hosts)} other computers, so a block reaches further")
    confidence = float(inc.get("ai_confidence") or 0)
    if inc.get("needs_review"):
        add(25, "the check that raised it was unsure, so it needs a person's eye")
    elif inc.get("classified_by") != "rules" and confidence < 0.8:
        add(15, f"the AI was only {round(confidence * 100)}% sure")
    if float(inc.get("asset_criticality") or 1) >= 1.5:
        add(10, "it is on an important computer, where a wrong block hurts more")
    if str(inc.get("category") or "") in ("benign", "misconfiguration"):
        add(10, "it may not be an attack at all")
    # What makes a yes safer.
    if inc.get("classified_by") == "rules" and not inc.get("needs_review"):
        points -= 15
        reasons.append("a fixed rule confirmed the pattern, not just the AI")
    if str(inc.get("classification_reason") or "").startswith(TRIPWIRE_REASONS) \
            or any(str(s).split(":", 1)[-1] in TRIPWIRE_SOURCES for s in inc.get("signals") or []):
        points -= 15
        reasons.append("it touched a decoy that no real person uses")
    if inc.get("status") == "contained":
        reasons.append("the block is already in force: keeping it changes nothing now, rolling it back lifts it")
    points = max(0, min(100, points))
    level = next(name for floor, name in LEVELS if points >= floor)
    return {"level": level, "word": WORDS[level], "score": points, "reasons": reasons}


def seen_on_map(incidents: Iterable[dict]) -> dict[str, set[str]]:
    """Each attacking address and the machines its incidents were on."""
    out: dict[str, set[str]] = {}
    for i in incidents:
        if i.get("src_ip") and i.get("host"):
            out.setdefault(str(i["src_ip"]), set()).add(str(i["host"]))
    return out
