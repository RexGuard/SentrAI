"""How long a fix lasts: the owner picks it on approve, and SentrAI suggests what they picked before.

Out of the box every temporary fix lasts its type's length (HOTPATCH_TTL_HOURS / ACTION_TTL_HOURS, capped by
MAX_TTL_HOURS). On approve a person may pick another length. check() refuses one that is not reasonable, and
says why in plain words: a fix shorter than 15 minutes ends before anyone notices, and one longer than the
business limit should be made permanent on purpose (Keep the block) instead.

suggest() works the suggestion out from the incidents themselves, like lessons.py: when the last two approvals of
the same kind of alert picked the same length, and it is not the usual one, SentrAI suggests it, naming those
incidents. Nothing is stored apart from the decisions already on each incident.
"""
from __future__ import annotations

from typing import Any, Iterable

from .summary import plain_title

MIN_HOURS = 0.25
SAME_IN_A_ROW = 2
CHOICES = (1.0, 2.0, 4.0, 8.0, 12.0, 24.0)  # what the Approvals page offers (within the limit)


def words(hours: float) -> str:
    if hours < 1:
        return f"{round(hours * 60)} minutes"
    whole = int(hours) if float(hours).is_integer() else hours
    return f"{whole} hour{'s' if hours != 1 else ''}"


def check(hours: Any, max_hours: float) -> str | None:
    """Why this length is not reasonable, or None when it is fine."""
    try:
        h = float(hours)
    except (TypeError, ValueError):
        return "the length is a number of hours, such as 4"
    if h != h or h < MIN_HOURS:  # NaN or too short
        return f"a fix shorter than {round(MIN_HOURS * 60)} minutes ends before anyone notices; pick at least that"
    if max_hours > 0 and h > max_hours:
        return (f"your limit for a temporary fix is {words(max_hours)} (set by your SentrAI team). For longer, approve "
                f"it and then choose Keep the block, which makes it permanent on purpose")
    return None


def choices(max_hours: float, usual: float | None = None) -> list[float]:
    out = sorted({h for h in CHOICES if max_hours <= 0 or h <= max_hours} | ({usual} if usual else set()))
    return [h for h in out if h >= MIN_HOURS]


def suggest(inc: dict[str, Any], incidents: Iterable[dict[str, Any]], usual: float | None,
            max_hours: float) -> dict[str, Any] | None:
    """{"hours", "words", "because", "evidence"} when the last approvals of this kind agree on another length."""
    cat = str(inc.get("category") or "")
    if not cat:
        return None
    picked: list[tuple[str, str, float]] = []  # (when, incident, hours)
    for other in incidents:
        if str(other.get("id")) == str(inc.get("id")) or str(other.get("category") or "") != cat:
            continue
        for d in other.get("decisions") or []:
            if isinstance(d, dict) and d.get("decision") == "approve" and d.get("hours") is not None:
                picked.append((str(d.get("at") or ""), str(other.get("id")), float(d["hours"])))
    picked.sort(reverse=True)
    last = picked[:SAME_IN_A_ROW]
    if len(last) < SAME_IN_A_ROW or len({h for _, _, h in last}) != 1:
        return None
    hours = last[0][2]
    if (usual is not None and abs(hours - usual) < 1e-9) or check(hours, max_hours):
        return None
    ids = sorted(i for _, i, _ in last)
    return {"hours": hours, "words": words(hours), "evidence": ids,
            "because": f"You chose {words(hours)} the last {len(last)} times for {plain_title(cat).lower()} "
                       f"({', '.join(ids)})."}
