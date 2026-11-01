"""What the web dashboard's Approvals page needs, ready to draw: GET /ui/approvals, the bulk actions and the groups.

The same rules as the Streamlit console (dashboard sentrai_ui/shaping.py: pending_approvals, approval_group,
saved_groups, add_to_group, bulk_split, bulk_result), in plain Python so the core needs no pandas. Groups are
kept in the same file Streamlit uses (sentrai_config.approval_groups), so both consoles show the same ones.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request

from .config import sentrai_config as cfg
from .saguaro import BadRequestError, ConflictError

ACTIVE = ("open", "acknowledged")
ADMIN_CATEGORY = "unauthorised_admin"
CATEGORY = {
    "benign": "Benign", "brute_force": "Brute force", "sql_injection": "SQL injection", "xss": "Cross-site scripting",
    "port_scan": "Port or web scan", "privilege_escalation": "Privilege escalation",
    "data_exfiltration": "Data exfiltration", "misconfiguration": "Misconfiguration", "log_tampering": "Log tampering",
    "malware": "Malware found", "staff_report": "Staff report", "prompt_injection": "Prompt injection",
    "unauthorised_admin": "Root access from an unrecognised sign-in",
}
STATUS = {"open": "Open", "acknowledged": "Acknowledged", "contained": "Contained", "resolved": "Resolved",
          "rejected": "Rejected"}
GROUP_BY = ("attacker", "machine", "type")


def category_label(category: Any) -> str:
    return CATEGORY.get(str(category), str(category).replace("_", " ").capitalize()) if category else "Unknown"


def parse_ts(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value))
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts.astimezone() if ts.tzinfo else ts


def span_label(seconds: float) -> str:
    mins = int(max(0.0, seconds) // 60)
    if mins < 1:
        return "under 1 min"
    if mins < 60:
        return f"{mins} min"
    if mins < 1440:
        return f"{mins // 60} h {mins % 60} min"
    return f"{mins // 1440} d {mins % 1440 // 60} h"


def can(inc: dict) -> dict[str, bool]:
    """Which operator buttons are meaningful for this incident."""
    status = str(inc.get("status") or "")
    has_active = any(a.get("status") == "active" for a in inc.get("actions") or [] if isinstance(a, dict))
    return {"decide": status in ACTIVE, "ack": status == "open" and not inc.get("acked"),
            "contain_controls": status == "contained" or has_active,
            "mine": status in ACTIVE and str(inc.get("category") or "") == ADMIN_CATEGORY}


def contribution(inc: dict) -> float:
    return round(float(inc.get("points") or 0) + float(inc.get("inaction_penalty") or 0), 1)


def pending(incidents: list[dict]) -> list[dict]:
    """Open ones to approve or reject, contained ones to keep or roll back; decisions first, biggest first."""
    waiting = [i for i in incidents if (c := can(i))["decide"] or c["contain_controls"]]
    return sorted(waiting, key=lambda i: (not can(i)["decide"], -contribution(i)))


def attacker(inc: dict) -> str:
    acts = [a for a in inc.get("actions") or [] if isinstance(a, dict) and a.get("target")]
    return str(inc.get("src_ip") or (acts[-1]["target"] if acts else "") or "Unknown source")


def group_name(inc: dict, by: str) -> str:
    if by == "attacker":
        return attacker(inc)
    if by == "machine":
        return str(inc.get("host") or "Unknown machine")
    return category_label(inc.get("category"))


def needs(inc: dict) -> list[str]:
    why = []
    if not inc.get("owner"):
        why.append("No owner")
    if inc.get("sla_breached") and not inc.get("acked"):
        why.append("Overdue, nobody answered")
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


def row(inc: dict) -> dict[str, Any]:
    opened = parse_ts(inc.get("opened_at"))
    age = (datetime.now(opened.tzinfo) - opened).total_seconds() if opened else 0.0
    acts = [a for a in inc.get("actions") or [] if isinstance(a, dict) and a.get("target")]
    live = [a for a in acts if a.get("status") == "active"] or acts
    return {
        "id": inc.get("id"), "what": category_label(inc.get("category")), "host": inc.get("host") or "-",
        "severity": str(inc.get("severity") or "-"),
        "status": STATUS.get(str(inc.get("status")), str(inc.get("status"))),
        "owner": inc.get("owner") or "Nobody", "opened": str(inc.get("opened_at") or ""), "open_for": span_label(age), "needs": needs(inc),
        "target": str(live[-1]["target"]) if live else str(inc.get("src_ip") or ""),
        "points": contribution(inc), "can": can(inc), "attacker": attacker(inc),
        "summary": inc.get("summary") or inc.get("reason") or "",
    }


def headline(waiting: list[dict]) -> str:
    if not waiting:
        return ""
    decide = sum(1 for i in waiting if can(i)["decide"])
    keep = len(waiting) - decide
    parts = [f"{decide} to approve or reject" if decide else "",
             f"{keep} block{'s' if keep != 1 else ''} to keep or roll back" if keep else ""]
    return f"{len(waiting)} waiting on you: " + " and ".join(p for p in parts if p) + "."


def saved_groups(waiting: list[dict], saved: dict[str, list[str]]) -> tuple[list[tuple[str, list[dict]]], list[dict]]:
    by_id = {str(i.get("id")): i for i in waiting}
    groups, used = [], set()
    for name, ids in saved.items():
        members = [by_id[i] for i in dict.fromkeys(ids) if i in by_id and i not in used]
        used.update(str(m.get("id")) for m in members)
        if members:
            groups.append((name, members))
    return groups, [i for i in waiting if str(i.get("id")) not in used]


def add_to_group(saved: dict[str, list[str]], name: str, ids: list[str], waiting_ids: set[str]) -> dict[str, list[str]]:
    out = {g: [i for i in members if i in waiting_ids and i not in ids] for g, members in saved.items()}
    out[name] = list(dict.fromkeys([*out.get(name, []), *ids]))
    return {g: m for g, m in out.items() if m}


def suggest_name(picked: list[dict], saved: dict[str, list[str]]) -> str:
    for by in GROUP_BY:
        names = {group_name(i, by) for i in picked}
        if len(names) == 1:
            name = names.pop()
            if name not in saved and not name.startswith("Unknown"):
                return name
    n = len(saved) + 1
    while f"Group {n}" in saved:
        n += 1
    return f"Group {n}"


def bulk_result(verb: str, done: list[str], failed: list[tuple[str, str]]) -> str:
    n = len(done) + len(failed)
    text = f"{verb} {len(done)} of {n} incident{'s' if n != 1 else ''}"
    if failed:
        text += ". Not done: " + "; ".join(f"{i} ({why})" for i, why in failed)
    return text


def install(app: FastAPI, core: Any) -> None:
    def operator(request: Request, body: dict) -> str:
        account = getattr(request.state, "account", None)  # a signed-in person is the operator, whatever the body says
        return (account or {}).get("email") or str(body.get("operator") or "dashboard")

    def waiting_now() -> list[dict]:
        return pending(core.list_incidents(host=None))

    @app.get("/ui/approvals")
    def get_approvals(by: str | None = None) -> dict[str, Any]:
        waiting = waiting_now()
        made, rest = saved_groups(waiting, cfg.approval_groups())
        grouped: list[dict] = []
        if by in GROUP_BY:
            buckets: dict[str, list[dict]] = {}
            for inc in rest:
                buckets.setdefault(group_name(inc, by), []).append(inc)
            grouped = [{"name": n, "rows": [row(i) for i in m]}
                       for n, m in sorted(buckets.items(), key=lambda kv: -len(kv[1]))]
        return {"headline": headline(waiting), "total": len(waiting), "rows": [row(i) for i in rest],
                "grouped": grouped, "groups": [{"name": n, "rows": [row(i) for i in m]} for n, m in made],
                "protection_on": not core.protection().get("monitor_only", False)}

    @app.post("/ui/approvals/bulk")
    def post_bulk(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """Approve, reject, roll back, keep or "this was me" for several incidents; each is audited on its own."""
        verb, op = str(body.get("verb") or ""), operator(request, body)
        ids, why = [str(i) for i in body.get("ids") or []], str(body.get("justification") or "").strip()
        if verb not in ("approve", "reject", "rollback", "keep", "mine"):
            raise HTTPException(400, "verb is approve, reject, rollback, keep or mine")
        if verb == "reject" and not why:
            raise HTTPException(400, "a reason is required to reject")
        by_id = {str(i.get("id")): i for i in core.list_incidents(host=None)}
        done: list[str] = []
        failed: list[tuple[str, str]] = []
        for iid in ids:
            inc = by_id.get(iid)
            allowed = can(inc) if inc else {}
            try:
                if not inc:
                    raise KeyError(iid)
                if verb in ("approve", "reject") and not allowed["decide"]:
                    raise BadRequestError("nothing to decide")
                if verb in ("rollback", "keep") and not allowed["contain_controls"]:
                    raise BadRequestError("no block to undo or keep")
                if verb == "mine" and not allowed["mine"]:
                    raise BadRequestError("not a root-access alert")
                if verb in ("approve", "reject"):
                    if allowed["ack"]:
                        core.ack(iid, op, "dashboard")
                    core.decision(iid, op, verb, why or f"Approved as a group of {len(ids)} from the dashboard")
                elif verb == "rollback":
                    core.rollback(iid, op, why or f"Rolled back as a group of {len(ids)} by operator from dashboard")
                elif verb == "keep":
                    core.make_permanent(iid, op, why or "Made permanent as a group by operator from dashboard")
                else:
                    core.mine(iid, op, "dashboard")
                done.append(iid)
            except KeyError:
                failed.append((iid, "not found"))
            except (BadRequestError, ConflictError) as exc:
                failed.append((iid, str(exc)))
        text = {"approve": "Approved & patched", "reject": "Rejected", "rollback": "Rolled back",
                "keep": "Made permanent", "mine": "Closed as your own"}[verb]
        return {"done": done, "failed": [{"id": i, "why": w} for i, w in failed],
                "message": bulk_result(text, done, failed)}

    @app.post("/ui/approvals/groups")
    def post_group(body: dict = Body(...)) -> dict[str, Any]:
        """Put incidents into a group (made if new); {"ungroup": name} dissolves one."""
        saved = cfg.approval_groups()
        if body.get("ungroup"):
            saved = {g: m for g, m in saved.items() if g != body["ungroup"]}
            message = f"Ungrouped {body['ungroup']}"
        else:
            name, ids = str(body.get("name") or "").strip(), [str(i) for i in body.get("ids") or []]
            if not name or not ids:
                raise HTTPException(400, "a name and at least one incident are needed")
            saved = add_to_group(saved, name, ids, {str(i.get("id")) for i in waiting_now()})
            message = f"Grouped {len(ids)} under {name}"
        cfg.save_approval_groups(saved)
        return {"groups": saved, "message": message}

    @app.post("/ui/approvals/group-name")
    def post_group_name(body: dict = Body(...)) -> dict[str, Any]:
        ids = {str(i) for i in body.get("ids") or []}
        picked = [i for i in waiting_now() if str(i.get("id")) in ids]
        return {"name": suggest_name(picked, cfg.approval_groups())}
