"""Risk bubbles for the web dashboard's Command center: everything that needs a person, in one list per severity.

Approvals (waiting for a decision, or a block to keep or undo) and incidents that need a person used to be two
tables. They are the same incidents seen twice, so this joins them: one bubble per incident (or one per wave of
many addresses doing the same thing), grouped Critical / High / Medium / Low, each with what happened, what it
means in plain words, the suggested fix and the one-click actions that are possible right now.

GET /ui/risks            the counts per severity (the bubbles on the Command center)
GET /ui/risks?severity=x those counts plus the bubbles of that severity, most urgent first
The actions themselves go through POST /ui/approvals/bulk, so the guardrails and the audit log are the same.
"""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Query

from .agents import next_steps
from .ui_approvals import can, category_label, span_label
from .ui_incidents import OPEN_STATUSES, SEVERITY_RANK, age_hours, attention

LEVELS = ("critical", "high", "medium", "low")

# What each kind of risk means for the business, for someone who does not work in IT.
MEANING = {
    "brute_force": "Someone is guessing passwords to get into an account. If they guess right, they are in.",
    "sql_injection": "Someone is trying to trick the website into handing over or changing what is in its database.",
    "xss": "Someone is trying to plant code on the website that would run in your visitors' browsers.",
    "port_scan": "Someone is looking around your machine for an open door. Usually the step before an attack.",
    "privilege_escalation": "An attacker may have taken control of the machine. This is serious and needs a person now.",
    "data_exfiltration": "A lot of customer data was asked for at once. It could be data theft.",
    "misconfiguration": "A setting is left open (public access, an open admin port or a default password).",
    "log_tampering": "Someone tried to erase or change the record of what happened. Attackers do this to hide their "
                     "tracks. SentrAI kept its own copy, so nothing is lost.",
    "prompt_injection": "Someone tried to trick SentrAI's AI into ignoring an attack. It was caught by the rules first.",
    "malware": "A harmful file or program was found on the machine.",
    "staff_report": "A member of staff reported something that looked wrong.",
    "unauthorised_admin": "Someone used the machine's highest (root) access from a sign-in SentrAI does not know.",
}

# The quick actions, in plain words. `verb` is what POST /ui/approvals/bulk takes.
ACTIONS = {
    "approve": {"label": "Do the suggested fix", "hint": "Applies the fix above. Written to the audit log."},
    "reject": {"label": "Not a threat", "hint": "Closes it without acting. You say why."},
    "rollback": {"label": "Undo the block", "hint": "Lets the address or account back in."},
    "keep": {"label": "Keep the block", "hint": "Keeps it blocked after the time limit."},
    "mine": {"label": "This was me", "hint": "SentrAI learns this sign-in and stops asking."},
}


def needs_person(inc: dict) -> bool:
    """Open and waiting on someone: a decision, a block to keep or undo, or one of the reasons on Incidents."""
    if inc.get("status") not in OPEN_STATUSES:
        return False
    c = can(inc)
    return bool(c["decide"] or c["contain_controls"] or attention(inc))


def level(inc: dict) -> str:
    sev = str(inc.get("severity") or "").lower()
    return sev if sev in LEVELS else "low"


def actions(members: list[dict]) -> list[dict[str, str]]:
    """The quick actions every member of the bubble allows (a wave acts on all its members at once)."""
    out = []
    flags = [can(i) for i in members]
    if all(f["mine"] for f in flags):
        out.append("mine")
    if all(f["decide"] for f in flags):
        out += ["approve", "reject"]
    if all(f["contain_controls"] for f in flags):
        out += ["keep", "rollback"]
    return [{"verb": v, **ACTIONS[v]} for v in out]


def bubble(members: list[dict], wave: str = "") -> dict[str, Any]:
    """One risk bubble: a single incident, or a wave of the same thing against one machine."""
    first = sorted(members, key=lambda i: -age_hours(i))[0]  # the oldest says how long it has waited
    cat = str(first.get("category") or "")
    owners = sorted({str(i.get("owner")) for i in members if i.get("owner")})
    sources = sorted({str(i.get("src_ip")) for i in members if i.get("src_ip")})
    title = category_label(cat)
    if wave:
        title += f" from {len(sources) or len(members)} address{'es' if (len(sources) or len(members)) != 1 else ''}"
    reasons: list[str] = []
    for i in members:
        for r in attention(i):
            if r not in reasons:
                reasons.append(r)
    return {
        "id": wave or str(first.get("id")), "ids": [str(i.get("id")) for i in members], "wave": wave,
        "incident": str(first.get("id")), "title": title, "category": cat, "severity": level(first),
        "host": first.get("host") or "-", "source": ", ".join(sources[:3]) + (" …" if len(sources) > 3 else ""),
        "owner": ", ".join(owners) if owners else "Nobody yet",
        "open_for": span_label(age_hours(first) * 3600), "hours": round(age_hours(first), 2),
        "overdue": any(i.get("sla_breached") and not i.get("acked") for i in members),
        "status": str(first.get("status")), "acked": bool(first.get("acked")),
        "needs": reasons,
        "what_happened": first.get("explanation") or first.get("summary") or f"{title} on {first.get('host') or 'a machine'}.",
        "meaning": MEANING.get(cat, "Something unusual happened that SentrAI could not act on alone."),
        "fix": first.get("recommended_action") or "",
        "steps": first.get("next_steps") or next_steps(first),
        "unsure": bool(first.get("needs_review")),
        "actions": actions(members),
        # For the chat's suggestion buttons (Chat.tsx SuggestionCard): enough to tell what is still possible.
        "inc": {"id": str(first.get("id")), "status": str(first.get("status")), "category": cat,
                "acked": bool(first.get("acked")),
                "actions": [{"status": a.get("status")} for a in first.get("actions") or [] if isinstance(a, dict)]},
    }


def bubbles(incidents: list[dict]) -> list[dict[str, Any]]:
    waves: dict[str, list[dict]] = {}
    out = []
    for inc in incidents:
        if inc.get("wave"):
            waves.setdefault(str(inc["wave"]), []).append(inc)
        else:
            out.append(bubble([inc]))
    for w, members in waves.items():
        by_level: dict[str, list[dict]] = {}
        for m in members:  # a wave seldom mixes severities, but keep each bubble in one place
            by_level.setdefault(level(m), []).append(m)
        for lv, ms in by_level.items():
            out.append(bubble(ms, wave=w if len(by_level) == 1 else f"{w}-{lv}"))
    # Overdue first, then those nobody owns, then the oldest.
    return sorted(out, key=lambda b: (SEVERITY_RANK.get(b["severity"], 9), not b["overdue"],
                                      b["owner"] != "Nobody yet", -b["hours"]))


def summary(rows: list[dict[str, Any]], incidents: list[dict]) -> list[dict[str, Any]]:
    out = []
    for lv in LEVELS:
        mine = [b for b in rows if b["severity"] == lv]
        out.append({"severity": lv, "count": sum(len(b["ids"]) for b in mine), "bubbles": len(mine),
                    "overdue": sum(1 for b in mine if b["overdue"]),
                    "oldest": max(mine, key=lambda b: b["hours"])["open_for"] if mine else ""})
    return out


def headline(levels: list[dict[str, Any]]) -> str:
    total = sum(lv["count"] for lv in levels)
    if not total:
        return "Nothing needs a person right now. All quiet at the gate."
    first = next(lv for lv in levels if lv["count"])
    return (f"{total} thing{'s' if total != 1 else ''} need{'' if total != 1 else 's'} a person. "
            f"Start with {first['severity'].capitalize()}.")


def install(app: FastAPI, core: Any) -> None:
    @app.get("/ui/risks")
    def get_risks(severity: str | None = Query(None)) -> dict[str, Any]:
        """The Command center's severity bubbles; with `severity`, that level's risk bubbles too."""
        if severity is not None and severity not in LEVELS:
            raise HTTPException(400, f"severity is one of {', '.join(LEVELS)}")
        incidents = [i for i in core.list_incidents(host=None) if needs_person(i)]
        rows = bubbles(incidents)
        levels = summary(rows, incidents)
        out: dict[str, Any] = {"levels": levels, "headline": headline(levels),
                               "protection_on": not core.protection().get("monitor_only", False)}
        if severity:
            out["rows"] = [b for b in rows if b["severity"] == severity]
        return out
