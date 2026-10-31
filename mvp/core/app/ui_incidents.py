"""What the web dashboard's Incidents page needs: counts, what needs a person, every incident with its owner,
and the waves. Same rules as the Streamlit console (shaping.py: attention, board_counts, board_rows, split_waves,
wave_line, wave_rows), in plain Python."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import FastAPI, Query, Request

from .ui_approvals import STATUS, can, category_label, parse_ts, span_label

OPEN_STATUSES = ("open", "acknowledged", "contained")
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
WAVE_DOING = {"port_scan": "scanning", "brute_force": "guessing passwords on"}


def age_hours(inc: dict) -> float:
    opened = parse_ts(inc.get("opened_at"))
    if opened is None:
        return 0.0
    return max(0.0, (datetime.now(opened.tzinfo) - opened).total_seconds() / 3600)


def attention(inc: dict) -> list[str]:
    """Why a person should look at this incident now, most urgent first. Empty when it is fine."""
    if inc.get("status") not in OPEN_STATUSES:
        return []
    why = []
    if not inc.get("owner"):
        why.append("No owner")
    if inc.get("sla_breached") and not inc.get("acked"):
        why.append("Overdue, nobody answered")
    if int(inc.get("escalation_level") or 0) > 0 and not inc.get("acked"):
        why.append(f"Escalated to {inc.get('owner')}")
    c = can(inc)
    if c["mine"]:
        why.append("Was this you?")
    elif inc.get("needs_review"):
        why.append("AI unsure, needs review")
    if inc.get("status") == "contained" or c["contain_controls"]:
        why.append("Keep or roll back the block")
    elif c["decide"] and not inc.get("acked"):
        why.append("Waiting for a decision")
    return why


def needs_attention(incidents: list[dict]) -> list[dict]:
    rows = [i for i in incidents if attention(i)]
    return sorted(rows, key=lambda i: (bool(i.get("acked")), SEVERITY_RANK.get(str(i.get("severity")), 9),
                                       -age_hours(i)))


def counts(incidents: list[dict], me: set[str]) -> dict[str, int]:
    incs = [i for i in incidents if i.get("status") in OPEN_STATUSES]
    return {"open": len(incs), "attention": sum(1 for i in incs if attention(i)),
            "overdue": sum(1 for i in incs if i.get("sla_breached") and not i.get("acked")),
            "escalated": sum(1 for i in incs if int(i.get("escalation_level") or 0) > 0),
            "unassigned": sum(1 for i in incs if not i.get("owner")),
            "mine": sum(1 for i in incs if str(i.get("owner") or "").lower().lstrip("@") in me)}


def split_waves(incidents: list[dict]) -> tuple[list[dict], dict[str, list[dict]]]:
    singles: list[dict] = []
    waves: dict[str, list[dict]] = {}
    for inc in incidents:
        if inc.get("wave"):
            waves.setdefault(str(inc["wave"]), []).append(inc)
        else:
            singles.append(inc)
    return singles, waves


def wave_line(members: list[dict]) -> str:
    first = members[0] if members else {}
    doing = WAVE_DOING.get(str(first.get("category")), f"{category_label(first.get('category')).lower()} on")
    n = len({m.get("src_ip") or m.get("id") for m in members})
    return f"{n} address{'es' if n != 1 else ''} {doing} {first.get('host') or 'a machine'} need a person"


def row(inc: dict) -> dict[str, Any]:
    closed = inc.get("status") not in OPEN_STATUSES
    needs = attention(inc)
    return {"id": inc.get("id", "?"), "what": category_label(inc.get("category")), "host": inc.get("host") or "-",
            "severity": str(inc.get("severity") or "-"), "status": STATUS.get(str(inc.get("status")), str(inc.get("status"))),
            "owner": inc.get("owner") or "Nobody", "backup": inc.get("backup") or "-",
            "open_for": "-" if closed else span_label(age_hours(inc) * 3600),
            "needs": ("Closed by " + str(inc.get("resolved_by") or inc.get("acked_by") or "-")) if closed
            else ("; ".join(needs) if needs else "In hand"),
            "closed": closed, "attention": bool(needs), "wave": inc.get("wave") or "",
            "can_resolve": not closed, "summary": inc.get("summary") or inc.get("reason") or "",
            "rank": [closed, not needs, SEVERITY_RANK.get(str(inc.get("severity")), 9)]}


def board(incidents: list[dict]) -> list[dict]:
    return sorted((row(i) for i in incidents), key=lambda r: r["rank"])


def wave_row(w: dict) -> dict[str, Any]:
    return {"id": w.get("id", "?"), "what": category_label(w.get("category")), "machine": w.get("host") or "-",
            "addresses": int(w.get("addresses") or 0),
            "networks": ", ".join(f"{n.get('network')} ({n.get('addresses')})" for n in (w.get("networks") or [])[:3])
            or "spread out", "started": str(w.get("started_at") or "")[11:16] or "-",
            "last_seen": str(w.get("last_seen_at") or "")[11:16] or "-", "going": bool(w.get("active"))}


def install(app: FastAPI, core: Any) -> None:
    @app.get("/ui/incidents")
    def get_incidents_page(request: Request, closed: bool = Query(False), mine: bool = Query(False)) -> dict[str, Any]:
        incidents = core.list_incidents(host=None)
        account = getattr(request.state, "account", None) or {}
        names = {str(account.get(k) or "").lower().lstrip("@") for k in ("name", "email")} - {""}
        names |= {n.split("@")[0] for n in names if "@" in n}
        todo, todo_waves = split_waves(needs_attention(incidents))
        shown = [i for i in incidents if (closed or i.get("status") in OPEN_STATUSES)
                 and (not mine or str(i.get("owner") or "").lower().lstrip("@") in names)]
        contacts = (core.routing_public() or {}).get("contacts") or []
        return {"counts": counts(incidents, names), "todo": [row(i) for i in todo],
                "todo_waves": [{"id": w, "line": wave_line(m), "count": len(m)} for w, m in todo_waves.items()],
                "all": board(shown), "waves": [wave_row(w) for w in core.list_waves()],
                "contacts": [{"id": c.get("id"), "name": c.get("name")} for c in contacts if isinstance(c, dict)],
                "can_resolve": True}
