"""Pure data-shaping helpers for the SentrAI dashboard.

Everything here is free of Streamlit so it can be unit tested.
"""
from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Iterable

import pandas as pd
import plotly.graph_objects as go

# ---------------------------------------------------------------- bands

# Contract bands: green 0-29, amber 30-59, red 60-79, critical 80-100.
BANDS: list[tuple[str, int, int]] = [
    ("green", 0, 29),
    ("amber", 30, 59),
    ("red", 60, 79),
    ("critical", 80, 100),
]

# Status palette (good / warning / serious / critical). Always shown with a label.
BAND_COLORS: dict[str, str] = {
    "green": "#4fb67c",
    "amber": "#e8b34a",
    "red": "#ec835a",
    "critical": "#e5484d",
}
BAND_LABELS: dict[str, str] = {
    "green": "GREEN · logged only",
    "amber": "AMBER · operator notified",
    "red": "RED · escalated",
    "critical": "CRITICAL · autonomous containment",
}
UNKNOWN_COLOR = "#8b96a8"

SURFACE = "#121a29"
TEXT_PRIMARY = "#e7edf6"
TEXT_SECONDARY = "#a5b2c6"
TEXT_MUTED = "#6f7d93"
FONT = "IBM Plex Sans, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif"
GRID = "rgba(255,255,255,0.07)"


def band_for(index: float | int | None) -> str:
    """Map a 0-100 risk index to its band name."""
    if index is None:
        return "unknown"
    value = max(0, min(100, round(float(index))))
    for name, lo, hi in BANDS:
        if lo <= value <= hi:
            return name
    return "critical"


def band_color(band_or_index: str | float | int | None) -> str:
    """Color for a band name, or for a numeric index."""
    if isinstance(band_or_index, (int, float)) and not isinstance(band_or_index, bool):
        band_or_index = band_for(band_or_index)
    return BAND_COLORS.get(str(band_or_index or "").lower(), UNKNOWN_COLOR)


def resolve_band(risk: dict) -> str:
    """Prefer the band the core reports; fall back to computing it."""
    band = str(risk.get("band") or "").lower()
    return band if band in BAND_COLORS else band_for(risk.get("risk_index"))


# ---------------------------------------------------------------- text helpers

CATEGORY_LABELS = {
    "benign": "Benign",
    "brute_force": "Brute force",
    "sql_injection": "SQL injection",
    "xss": "Cross-site scripting",
    "port_scan": "Port or web scan",
    "privilege_escalation": "Privilege escalation",
    "data_exfiltration": "Data exfiltration",
    "misconfiguration": "Misconfiguration",
    "log_tampering": "Log tampering",
    "malware": "Malware found",
    "staff_report": "Staff report",
    "prompt_injection": "Prompt injection",
    "unauthorised_admin": "Root access from an unrecognised sign-in",
}

# Plain words, sentence case: emoji render differently on every OS and tables can't show icons.
STATUS_LABELS = {
    "open": "Open",
    "acknowledged": "Acknowledged",
    "contained": "Contained",
    "resolved": "Resolved",
    "rejected": "Rejected",
}

CLASSIFIER_LABELS = {"rules": "Rules", "jev": "Jev (AI)", "fallback": "Fallback"}

ACTION_LABELS = {
    "block_ip": "Block IP",
    "lock_user": "Lock account",
    "rate_limit": "Rate limit",
    "waf_rule": "Web firewall rule",
    "kill_process": "Stop process",
    "revoke_public_acl": "Make private again",
}

# Who decided: the two-key automatic path, or a person pressing Approve.
MODE_LABELS = {"autonomous": "Automatic", "operator": "By a person"}


def action_label(kind: Any) -> str:
    if not kind or kind == "-":
        return "-"
    return ACTION_LABELS.get(str(kind), str(kind).replace("_", " ").capitalize())


def mode_label(mode: Any) -> str:
    if not mode or mode == "-":
        return "-"
    return MODE_LABELS.get(str(mode), str(mode).replace("_", " ").capitalize())


def ai_classifier_state(status: Any, extension: dict | None = None) -> tuple[str, str]:
    """The AI classifier's tile: ("On" | "Off" | "Unknown", why). Never claims "On" when the core said nothing.

    `status` is the Jev agent's (GET /agents), there only while the TypeSafe extension is added;
    `extension` is the TypeSafe row of GET /extensions, when the core sent one."""
    text = str(status or "").strip()
    if text.startswith("enabled"):
        return "On", "asked when the rules are unsure"
    if text.startswith("disabled"):
        why = text.split(":", 1)[1].split("(")[0].strip() if ":" in text else ""
        return "Off", why or "keyword fallback in use"
    if extension:
        if not extension.get("added"):
            return "Off", "TypeSafe extension not added"
        trouble = extension.get("error") or extension.get("last_error")
        if trouble or not extension.get("configured"):
            return "Off", str(trouble or "no TypeSafe key saved")
        return "On", "asked when the rules are unsure"
    return "Unknown", "the core did not report it"


def plural(n: Any, word: str, many: str = "") -> str:
    """'1 action', '2 actions', '2 addresses': no '(s)' in what people read."""
    try:
        one = int(n) == 1
    except (TypeError, ValueError):
        one = False
    return f"{n} {word if one else (many or word + 's')}"


def category_label(category: str | None) -> str:
    if not category:
        return "Unknown"
    return CATEGORY_LABELS.get(category, category.replace("_", " ").capitalize())


def status_label(status: str | None) -> str:
    return STATUS_LABELS.get(str(status or ""), str(status or "unknown").replace("_", " ").capitalize())


def parse_ts(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value))
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    # The core writes some times in UTC and some with this computer's offset; show them all in local time,
    # like the page's own clock, so one screen never mixes two time zones.
    return ts.astimezone() if ts.tzinfo else ts


def short_time(value: Any) -> str:
    ts = parse_ts(value)
    return ts.strftime("%H:%M:%S") if ts else (str(value) if value else "-")


def day_time(value: Any) -> str:
    """"27 Oct 15:04", for a change that may be days old."""
    ts = parse_ts(value)
    return f"{ts.day} {ts.strftime('%b %H:%M')}" if ts else (str(value) if value else "-")


def expires_label(value: Any, now: datetime | None = None) -> str:
    """When a block runs out, with how long is left: "20:52:58 (in 1 h 59 min)"."""
    ts = parse_ts(value)
    if not ts:
        return str(value) if value else "-"
    now = now or datetime.now(ts.tzinfo)
    left = (ts - now).total_seconds()
    if left <= 0:
        return f"{ts.strftime('%H:%M:%S')} (expired)"
    return f"{ts.strftime('%H:%M:%S')} (in {span_label(left)})"


def span_label(seconds: float) -> str:
    """A length of time the way people say it: "under 1 min", "7 min", "2 h 5 min", "3 d 4 h"."""
    mins = int(max(0.0, seconds) // 60)
    if mins < 1:
        return "under 1 min"
    if mins < 60:
        return f"{mins} min"
    if mins < 24 * 60:
        return f"{mins // 60} h {mins % 60} min"
    return f"{mins // 1440} d {mins % 1440 // 60} h"


def short_hash(value: str | None, n: int = 10) -> str:
    if not value:
        return "-"
    return value[:n] + "…" if len(value) > n else value


# ---------------------------------------------------------------- incidents

INCIDENT_COLUMNS = [
    "ID",
    "Category",
    "Severity",
    "Confidence",
    "Classified by",
    "Status",
    "Points",
    "Inaction penalty",
    "SLA breached",
    "Source",
]

ACTIVE_STATUSES = ("open", "acknowledged")


def build_incident_table(incidents: Iterable[dict]) -> pd.DataFrame:
    """Shape /incidents into the queue table (newest first, open ones on top)."""
    rows = []
    for inc in incidents or []:
        conf = inc.get("ai_confidence")
        rows.append(
            {
                "ID": inc.get("id", "?"),
                "Category": category_label(inc.get("category")),
                "Severity": str(inc.get("severity") or "-").upper(),
                "Confidence": float(conf) if isinstance(conf, (int, float)) else None,
                "Classified by": CLASSIFIER_LABELS.get(
                    str(inc.get("classified_by")), str(inc.get("classified_by") or "-")
                ),
                "Status": status_label(inc.get("status")),
                "Points": round(float(inc.get("points") or 0), 1),
                "Inaction penalty": int(round(float(inc.get("inaction_penalty") or 0))),
                "SLA breached": bool(inc.get("sla_breached")),
                "Source": inc.get("src_ip") or inc.get("user") or inc.get("host") or "-",
                "_status": inc.get("status"),
                "_opened": parse_ts(inc.get("opened_at")),
            }
        )
    df = pd.DataFrame(rows, columns=INCIDENT_COLUMNS + ["_status", "_opened"])
    if df.empty:
        return df[INCIDENT_COLUMNS]
    df["_active"] = df["_status"].isin(ACTIVE_STATUSES)
    df["_sort_ts"] = df["_opened"].map(lambda t: t.timestamp() if t else 0.0)
    df = df.sort_values(["_active", "_sort_ts"], ascending=[False, False])
    return df[INCIDENT_COLUMNS].reset_index(drop=True)


def pick_default_incident(incidents: list[dict]) -> str | None:
    """Most urgent incident: active first, then highest points + penalty."""
    if not incidents:
        return None
    priority = {"open": 0, "acknowledged": 1, "contained": 2, "rejected": 3, "resolved": 4}

    def key(inc: dict) -> tuple:
        weight = float(inc.get("points") or 0) + float(inc.get("inaction_penalty") or 0)
        return (priority.get(str(inc.get("status")), 5), -weight)

    return sorted(incidents, key=key)[0].get("id")


def incident_contribution(inc: dict) -> float:
    return round(float(inc.get("points") or 0) + float(inc.get("inaction_penalty") or 0), 1)


ADMIN_CATEGORY = "unauthorised_admin"  # root work from a sign-in SentrAI does not know: "This was me" or "Not me"


def available_actions(inc: dict) -> dict[str, bool]:
    """Which operator buttons are meaningful for this incident. "mine" is "This was me": a root-access incident
    still open, which the person answers instead of approving (Approve is "Not me: block it" there)."""
    status = str(inc.get("status") or "")
    actions = inc.get("actions") or []
    has_active = any(a.get("status") == "active" for a in actions if isinstance(a, dict))
    return {
        "decide": status in ACTIVE_STATUSES,
        "ack": status == "open" and not inc.get("acked"),
        "contain_controls": status == "contained" or has_active,
        "mine": status in ACTIVE_STATUSES and str(inc.get("category") or "") == ADMIN_CATEGORY,
    }


def decision_verb(inc: dict) -> str:
    """What an incident row asks of a person: was this you, approve or reject, or keep or roll back."""
    can = available_actions(inc)
    if can["mine"]:
        return "Was this you?"
    return "Approve or reject" if can["decide"] else "Keep or roll back"


CHAT_DECISION_NEEDS = {"approve": "decide", "reject": "decide", "ack": "ack",
                       "rollback": "contain_controls", "make_permanent": "contain_controls", "mine": "mine"}


def suggestion_state(inc: dict | None, decision: str) -> tuple[bool, str]:
    """Whether a decision the orchestrator suggested in chat can still be made, and why not."""
    if not inc:
        return False, "incident not found"
    need = CHAT_DECISION_NEEDS.get(decision)
    if need is None:
        return False, f"unknown decision {decision}"
    if not available_actions(inc)[need]:
        return False, f"no longer possible: incident is {status_label(inc.get('status')).lower()}"
    return True, ""


def check_text(a: dict) -> str:
    """The after-action check in a few words: did it work, did it hurt anything."""
    chk = a.get("check")
    if not isinstance(chk, dict):
        return "pending" if a.get("status") in ("active", "permanent") else "-"
    worked = {True: "worked", False: "did not work", None: "can't see"}.get(chk.get("worked"), "-")
    if chk.get("disruption") is True:
        return f"{worked}, possible disruption"
    return worked + (", no harm seen" if chk.get("disruption") is False else "")


def undo_text(a: dict) -> str:
    """Whether taking the action out worked."""
    undo = a.get("undo")
    if not isinstance(undo, dict):
        return "-"
    if undo.get("ok") is False:
        return f"FAILED ({undo.get('attempts', 1)} tries)"
    return "done" if undo.get("ok") else "unconfirmed"


def incident_target(inc: dict) -> str:
    """What the incident is about, in a few words: the blocked thing if there is one, else the source and host."""
    acts = [a for a in inc.get("actions") or [] if isinstance(a, dict) and a.get("target")]
    live = [a for a in acts if a.get("status") == "active"] or acts
    who = str(live[-1]["target"]) if live else str(inc.get("src_ip") or "")
    host = str(inc.get("host") or "")
    return " on ".join(x for x in (who, host) if x) or "-"


def action_rows(inc: dict) -> pd.DataFrame:
    rows = [
        {
            "Action": a.get("action_id", "-"),
            "Type": action_label(a.get("type")),
            "Target": a.get("target", "-"),
            "Mode": mode_label(a.get("mode")),
            "Approved by": agent_label(a.get("approved_by", "-")),
            "Status": str(a.get("status") or "-").replace("_", " ").capitalize(),
            "Expires": expires_label(a.get("expires_at")) if a.get("status") == "active" else short_time(a.get("expires_at")),
            "Checked": check_text(a),
            "Undo": undo_text(a),
            "Snapshot": short_hash(a.get("snapshot_hash")),
        }
        for a in (inc.get("actions") or [])
        if isinstance(a, dict)
    ]
    return pd.DataFrame(
        rows, columns=["Action", "Type", "Target", "Mode", "Approved by", "Status", "Expires", "Checked", "Undo",
                       "Snapshot"]
    )


# ---------------------------------------------------------------- containment

def build_containment_rows(blocklist: dict | None, incidents: Iterable[dict]) -> pd.DataFrame:
    """Active containment. /blocklist is authoritative; incidents add context."""
    blocklist = blocklist or {}
    context: dict[str, dict] = {}
    for inc in incidents or []:
        for a in inc.get("actions") or []:
            if isinstance(a, dict) and a.get("status") in ("active", "permanent"):
                context[str(a.get("target"))] = {**a, "incident": a.get("incident") or inc.get("id")}

    rows: list[dict] = []
    seen: set[str] = set()
    for kind, key in (("IP", "ips"), ("User", "users")):
        for target in blocklist.get(key) or []:
            target = str(target)
            seen.add(target)
            a = context.get(target, {})
            rows.append(
                {
                    "Kind": kind,
                    "Target": target,
                    "Action": action_label(a.get("type", "block_ip" if kind == "IP" else "lock_user")),
                    "Incident": a.get("incident", "-"),
                    "Mode": mode_label(a.get("mode")),
                    "Approved by": agent_label(a.get("approved_by", "-")),
                    "Expires": "permanent" if a.get("status") == "permanent" else expires_label(a.get("expires_at")),
                }
            )
    # Non-blocklist containment (rate limits, WAF rules...) still worth showing.
    for target, a in context.items():
        if target in seen or a.get("status") != "active":
            continue
        rows.append(
            {
                "Kind": "Rule",
                "Target": target,
                "Action": action_label(a.get("type")),
                "Incident": a.get("incident", "-"),
                "Mode": mode_label(a.get("mode")),
                "Approved by": agent_label(a.get("approved_by", "-")),
                "Expires": expires_label(a.get("expires_at")),
            }
        )
    return pd.DataFrame(rows, columns=["Kind", "Target", "Action", "Incident", "Mode", "Approved by", "Expires"])


# ---------------------------------------------------------------- audit / agents

# Material Symbols name and colour per agent. Blues, violets, teals and greys only: green, amber and red mean risk.
AGENTS = {
    "Warden": ("shield", "#7aa2ff"),
    "Cyanide": ("science", "#5bc0be"),
    "Planner": ("account_tree", "#e08bd0"),
    "Countersign": ("key", "#9aa5b8"),
    "Scribe": ("description", "#8fa7ff"),
    "Gatehouse": ("public", "#4fb3d9"),
    "Watchtower": ("cell_tower", "#b88cf0"),
    "Vault": ("database", "#5bc0be"),
    "Garrison-Linux": ("dns", "#a3b1c6"),
    "Garrison-Win": ("desktop_windows", "#a3b1c6"),
    "Watchdog": ("pets", "#a0a39b"),
    "Help Desk": ("support_agent", "#d98bb5"),
    "Jev": ("psychology", "#c79bf2"),
    "Operator": ("person", "#e7edf6"),
}

_AGENT_BASE = {name: color for name, (_, color) in AGENTS.items()}


def set_palette(colors: dict) -> None:
    """Switch the module's colours to a console theme (theme.chart_colors()). Called once per run."""
    global UNKNOWN_COLOR, SURFACE, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED, GRID
    BAND_COLORS.update(colors["band"])
    UNKNOWN_COLOR, SURFACE, GRID = colors["unknown"], colors["surface"], colors["grid"]
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED = colors["text"], colors["text_secondary"], colors["text_muted"]
    for name, base in _AGENT_BASE.items():  # agent name colours stay readable on the theme's cards
        AGENTS[name] = (AGENTS[name][0], TEXT_PRIMARY if name == "Operator" else colors["readable"](base))


# Names from before the SentrAI sentry theme, still in older audit records and saved actions.
LEGACY_AGENTS = {
    "Saguaro": "Warden", "Needle": "Countersign", "Root": "Gatehouse", "Reservoir": "Vault",
    "SpineNet": "Watchtower", "Spine-Net": "Watchtower", "AreoleLinux": "Garrison-Linux",
    "Areole-Linux": "Garrison-Linux", "AreoleWin": "Garrison-Win", "Areole-Win": "Garrison-Win",
}


def agent_label(name: Any) -> Any:
    """Show an agent under its current name, whatever name the record was saved with."""
    return LEGACY_AGENTS.get(name, name) if isinstance(name, str) else name


# Audit record types keep their stored names; these read better in the feed.
RECORD_TYPE_LABELS = {"needle_review": "countersign review", "admin_action": "admin work",
                      "admin_confirmed": "this was me", "admin_distrusted": "not me",
                      "admin_changed": "administrators changed", "admin_signed_in": "dashboard sign-in"}


# Fallback mapping from audit record type to the agent that normally owns it.
TYPE_TO_AGENT = {
    "event": "Warden",
    "incident_opened": "Warden",
    "incident_updated": "Warden",
    "classification": "Jev",
    "risk_update": "Warden",
    "threshold_crossed": "Warden",
    "snapshot": "Garrison-Linux",
    "action_proposed": "Gatehouse",
    "action_approved": "Countersign",
    "review": "Countersign",
    "action_applied": "Garrison-Linux",
    "containment": "Garrison-Linux",
    "action_expired": "Watchdog",
    "notification_queued": "Scribe",
    "notification_delivered": "Scribe",
    "report_generated": "Scribe",
    "reminder": "Watchdog",
    "sla_breach": "Watchdog",
}
OPERATOR_TYPES = ("ack", "decision", "rollback", "permanent", "operator")


def normalize_audit(payload: Any) -> tuple[list[dict], bool | None]:
    """Accept either a bare list or {"records"/"chain"/"entries": [...], "chain_valid": bool}."""
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)], None
    if isinstance(payload, dict):
        for key in ("records", "chain", "entries", "audit", "items"):
            if isinstance(payload.get(key), list):
                recs = [r for r in payload[key] if isinstance(r, dict)]
                break
        else:
            recs = []
        valid = payload.get("chain_valid")
        return recs, (bool(valid) if valid is not None else None)
    return [], None


def agent_for(record: dict) -> str:
    data = record.get("data") if isinstance(record.get("data"), dict) else {}
    for key in ("agent", "actor", "by"):
        name = data.get(key) or record.get(key)
        if name:
            if str(name).lower() == "operator" and data.get("operator"):
                return f"Operator:{data['operator']}"
            return agent_label(str(name))
    rtype = str(record.get("type") or "")
    if any(rtype.startswith(t) for t in OPERATOR_TYPES):
        op = data.get("operator") or data.get("acked_by")
        return f"Operator:{op}" if op else "Operator"
    return TYPE_TO_AGENT.get(rtype, "Scribe")


def admin_record_summary(rtype: str, data: dict) -> str:
    """The administrators' records (core admins.py) in plain words: whose root work, what was taught or forgotten."""
    who, host = data.get("user") or "?", data.get("host") or "?"
    if rtype == "admin_action":
        text = f"{who} on {host}: {data.get('what') or data.get('raw') or 'root work'}"
        would = data.get("would_be")
        return text + (f" (would have been: {category_label(would)})" if would and would != "benign" else "")
    op = data.get("operator") or "someone"
    if rtype == "admin_confirmed":
        learned = [str(x) for x in data.get("learned") or []]
        return f"{op} said this was them" + (f"; now known: {', '.join(learned)}" if learned else "")
    if rtype == "admin_distrusted":
        gone = [str(x) for x in data.get("forgotten") or []]
        return f"{op} said this was not them" + (f"; forgotten: {', '.join(gone)}" if gone else "")
    if rtype == "admin_changed":
        verb = "forgot" if data.get("action") == "forget" else "added"
        label = f" ({data['label']})" if data.get("label") else ""
        where = f" on {data['host']}" if data.get("host") else ""
        return f"{op} {verb} {data.get('kind') or 'an entry'} {data.get('value') or ''}{label}{where}".rstrip()
    if rtype == "admin_signed_in":
        return (f"{data.get('email') or 'someone'} signed in as {data.get('role') or '?'} from "
                f"{data.get('address') or '?'}: an administrator's address until {day_time(data.get('until'))}")
    return ""


def summarize_record(record: dict) -> str:
    data = record.get("data") if isinstance(record.get("data"), dict) else {}
    rtype = str(record.get("type") or "")
    if rtype.startswith("admin_") and (text := admin_record_summary(rtype, data)):
        return text
    for key in ("summary", "message", "text", "detail", "explanation"):
        if data.get(key):
            return str(data[key])
    parts = []
    for key in ("incident", "incident_id", "id", "category", "decision", "target", "risk_index",
                "channel", "status"):
        if key in data and data[key] not in (None, ""):
            parts.append(f"{key}={data[key]}")
    return ", ".join(parts[:5]) or str(record.get("type") or "record")


def build_activity_feed(records: list[dict], limit: int = 30) -> list[dict]:
    """Newest-first feed entries for rendering."""
    ordered = sorted(records, key=lambda r: (r.get("seq") is None, r.get("seq") or 0))
    feed = []
    for rec in reversed(ordered[-limit:]):
        agent = agent_for(rec)
        base = agent.split(":", 1)[0]
        icon, color = AGENTS.get(base, ("smart_toy", TEXT_SECONDARY))
        feed.append(
            {
                "seq": rec.get("seq"),
                "time": short_time(rec.get("ts")),
                "agent": agent.replace("Operator:", "Operator · "),
                "icon": icon,
                "color": color,
                "type": RECORD_TYPE_LABELS.get(str(rec.get("type")), str(rec.get("type") or "-").replace("_", " ")),
                "summary": summarize_record(rec),
                "hash": short_hash(rec.get("hash"), 8),
            }
        )
    return feed


def agent_table(agents: list[dict] | None, records: list[dict]) -> pd.DataFrame:
    """Who does what, and how busy each one has been in the records on screen.

    Without the core's agent list, the agents seen in the records still show, so the box is never empty
    while the feed beside it is full."""
    seen: dict[str, dict] = {}
    for rec in records or []:
        name = agent_for(rec).split(":", 1)[0]
        row = seen.setdefault(name, {"n": 0, "ts": None})
        row["n"] += 1
        ts = parse_ts(rec.get("ts"))
        if ts and (row["ts"] is None or ts > row["ts"]):
            row["ts"] = ts
    rows = [{"Agent": agent_label(a.get("name")), "Role": a.get("role") or "-",
             "Can act": "Yes" if a.get("can_execute") else "No"} for a in agents or [] if isinstance(a, dict)]
    if not rows:
        rows = [{"Agent": name, "Role": "-", "Can act": "-"} for name in seen]
    for r in rows:
        hit = seen.get(r["Agent"], {})
        r["Records"] = hit.get("n", 0)
        r["Last"] = hit["ts"].strftime("%H:%M:%S") if hit.get("ts") else "-"
    rows.sort(key=lambda r: -r["Records"])
    cols = ["Agent", "Role", "Can act", "Records", "Last"] if agents else ["Agent", "Records", "Last"]
    return pd.DataFrame(rows, columns=cols)


def verify_chain_links(records: list[dict]) -> bool:
    """Client-side sanity check: each prev_hash equals the previous record's hash."""
    ordered = sorted(records, key=lambda r: r.get("seq") or 0)
    for prev, cur in zip(ordered, ordered[1:]):
        if cur.get("prev_hash") != prev.get("hash"):
            return False
    return True


# ---------------------------------------------------------------- charts

# Short word for each band in the machine list (the right-hand label under the number).
BAND_WORD: dict[str, str] = {"green": "Calm", "amber": "Elevated", "red": "High", "critical": "Critical"}


def parse_peers(text: str | None) -> list[tuple[str, str]]:
    """'Office PC=http://10.0.0.5:8000, Web=https://web:8000' -> [(name, url), ...].

    A bare URL is named after itself. Blank or malformed entries are skipped."""
    peers = []
    for item in (text or "").split(","):
        item = item.strip()
        if not item:
            continue
        name, sep, url = item.partition("=")
        if not sep:
            name, url = item, item
        name, url = name.strip(), url.strip()
        if url.startswith(("http://", "https://")):
            peers.append((name or url, url))
    return peers


def machine(name: str, place: str, risk: Any = None, error: str | None = None) -> dict:
    """One SentrAI machine for the machine list, from its /risk payload (or the error reaching it)."""
    if error or not isinstance(risk, dict):
        return {"name": name, "place": place, "online": False, "index": None, "band": "unknown",
                "threshold": None, "monitor_only": False}
    idx = risk.get("risk_index")
    return {"name": name, "place": place, "online": True,
            "index": None if idx is None else max(0.0, min(100.0, float(idx))),
            "band": resolve_band(risk), "threshold": float(risk.get("threshold") or 80),
            "monitor_only": bool(risk.get("monitor_only"))}


AGENT_STALE_S = 60.0  # an agent that has not called in for this long shows as offline


def panel_machines(found: Iterable[dict], agents: Iterable[dict], risk: dict | None,
                   now: datetime | None = None) -> list[dict]:
    """The machine list on a central panel: every machine the core scores (GET /machines) plus joined
    agents that have sent nothing yet, in the same shape as machine(), worst first."""
    now = now or datetime.now(timezone.utc)
    risk = risk or {}
    threshold = float(risk.get("threshold") or 80)
    live = {str(a.get("host")): a for a in agents or [] if isinstance(a, dict) and not a.get("revoked_at")}
    rows, seen = [], set()
    for m in found or []:
        if not isinstance(m, dict) or not m.get("host"):
            continue
        host = str(m["host"])
        seen.add(host)
        agent = live.get(host)
        last = parse_ts((agent or {}).get("last_seen") or m.get("last_seen"))
        if last is not None and last.tzinfo is None:
            last = last.astimezone(timezone.utc)  # a naive time is this computer's local time
        stale = bool(agent) and (last is None or (now - last).total_seconds() > AGENT_STALE_S)
        idx = m.get("risk_index")
        rows.append({"name": host, "place": "Agent" if agent else "Seen in logs", "host": host,
                     "online": not (m.get("silent") or stale),
                     "index": None if idx is None else max(0.0, min(100.0, float(idx))),
                     "band": m.get("band") or band_for(idx), "threshold": threshold,
                     "monitor_only": bool(risk.get("monitor_only")),
                     "open": int(m.get("open_incidents") or 0), "contained": int(m.get("contained_incidents") or 0),
                     "blocked": int(m.get("blocked") or 0), "last_seen": last,
                     "agent_id": (agent or {}).get("agent_id"), "services_at": m.get("services_at"),
                     "services": [x for x in m.get("services") or [] if isinstance(x, dict)],
                     "hardware": m.get("hardware") if isinstance(m.get("hardware"), dict) else None,
                     "sessions": int(m["sessions"]) if isinstance(m.get("sessions"), (int, float)) else None})
    for host, agent in live.items():
        if host not in seen:
            rows.append({"name": host, "place": "Agent", "host": host, "online": False, "waiting": True,
                         "index": None, "band": "unknown", "threshold": threshold, "monitor_only": False,
                         "open": 0, "contained": 0, "blocked": 0, "last_seen": None, "agent_id": agent.get("agent_id")})
    rows.sort(key=lambda r: (-(r["index"] or 0), r["name"]))
    return rows


def services_text(services: Iterable[dict], limit: int = 4) -> str:
    """'nginx :443, sshd :22 (1 open), +2 more' for a machine row; a service under attack goes first."""
    svcs = sorted((x for x in services or [] if isinstance(x, dict) and x.get("name")),
                  key=lambda x: (-int(x.get("open_incidents") or 0), x.get("port") or 0))
    parts = []
    for x in svcs[:limit]:
        port = f" :{x['port']}" if x.get("port") else ""
        hit = f" ({x['open_incidents']} open)" if x.get("open_incidents") else ""
        parts.append(f"{x['name']}{port}{hit}")
    if len(svcs) > limit:
        parts.append(f"+{len(svcs) - limit} more")
    return ", ".join(parts)


def service_rows(services: Iterable[dict]) -> pd.DataFrame:
    """One machine's services for the Machines page (like the servers on a node)."""
    rows = [{"Service": x.get("name"), "Port": x.get("port"), "Protocol": (x.get("proto") or "").upper() or "-",
             "Process": x.get("process") or "-", "Open incidents": int(x.get("open_incidents") or 0)}
            for x in services or [] if isinstance(x, dict) and x.get("name")]
    rows.sort(key=lambda r: (-r["Open incidents"], r["Port"] if r["Port"] is not None else 1 << 17))
    return pd.DataFrame(rows, columns=["Service", "Port", "Protocol", "Process", "Open incidents"])


# ---------------------------------------------------------------- hardware (core hardware.py, agent hardware.py)

def bytes_label(n: Any) -> str:
    """1536 -> '1.5 KB', 8 GiB -> '8.0 GB' (powers of 1024, the way an OS shows memory and disks)."""
    if not isinstance(n, (int, float)) or n < 0:
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return "-"


def rate_label(bps: Any) -> str:
    return "-" if not isinstance(bps, (int, float)) else f"{bytes_label(bps)}/s"


def pct_label(v: Any) -> str:
    return "-" if not isinstance(v, (int, float)) else f"{v:.0f}%"


def _fullest(hw: dict) -> dict | None:
    disks = [d for d in hw.get("disks") or [] if isinstance(d, dict) and isinstance(d.get("percent"), (int, float))]
    return max(disks, key=lambda d: d["percent"]) if disks else None


def _hottest(hw: dict) -> dict | None:
    temps = [t for t in hw.get("temps") or [] if isinstance(t, dict) and isinstance(t.get("current"), (int, float))]
    return max(temps, key=lambda t: t["current"]) if temps else None


def hardware_hot(hw: dict | None) -> set[str]:
    """Which parts are over their alert limit right now: 'cpu', 'memory', 'disk', 'temp' (from the core's warnings)."""
    out = set()
    for w in (hw or {}).get("warnings") or []:
        w = str(w)
        out.add("cpu" if w.startswith("CPU") else "memory" if w.startswith("memory") else
                "disk" if w.startswith("disk") else "temp" if "temperature" in w else "")
    return out - {""}


def hardware_text(hw: dict | None) -> str:
    """'4 cores · 7.8 GB memory · Linux 6.8 · up 3 d 4 h' for the line under a machine's name."""
    if not hw:
        return ""
    cores = (hw.get("cpu") or {}).get("cores")
    total = (hw.get("memory") or {}).get("total")
    up = hw.get("uptime_s")
    parts = [plural(cores, "core") if cores else "", f"{bytes_label(total)} memory" if total else "", hw.get("os") or "",
             f"up {span_label(up)}" if isinstance(up, (int, float)) else ""]
    return " · ".join(str(p) for p in parts if p)


def hardware_cells(hw: dict | None) -> list[tuple[str, str, bool]]:
    """CPU, memory and fullest disk for a machine's row in the list, as a game panel's server list shows them."""
    if not hw:
        return []
    hot, disk = hardware_hot(hw), _fullest(hw)
    return [("CPU", pct_label((hw.get("cpu") or {}).get("percent")), "cpu" in hot),
            ("Memory", pct_label((hw.get("memory") or {}).get("percent")), "memory" in hot),
            ("Disk", pct_label(disk["percent"]) if disk else "-", "disk" in hot)]


def hardware_stats(hw: dict | None) -> list[tuple[str, str, str, bool]]:
    """(label, value, note, over the limit) for the strip at the top of a machine's Hardware tab."""
    if not hw:
        return []
    hot = hardware_hot(hw)
    cpu, mem, net = hw.get("cpu") or {}, hw.get("memory") or {}, hw.get("net") or {}
    load = cpu.get("load")
    disk, temp = _fullest(hw), _hottest(hw)
    out = [("CPU", pct_label(cpu.get("percent")),
            " · ".join(x for x in (plural(cpu["cores"], "core") if cpu.get("cores") else "",
                                    f"load {load[0]:.2f}" if load else "") if x), "cpu" in hot),
           ("Memory", pct_label(mem.get("percent")),
            f"{bytes_label(mem.get('used'))} of {bytes_label(mem.get('total'))}" if mem.get("total") else "", "memory" in hot),
           ("Fullest disk", pct_label(disk["percent"]) if disk else "-",
            f"{disk['mount']} · {bytes_label(disk.get('total'))}" if disk else "no disks reported", "disk" in hot),
           ("Network in", rate_label(net.get("recv_rate")), f"out {rate_label(net.get('sent_rate'))}", False)]
    if temp:
        out.append(("Hottest", f"{temp['current']:.0f} °C", str(temp.get("label") or ""), "temp" in hot))
    up = hw.get("uptime_s")
    out.append(("Uptime", span_label(up) if isinstance(up, (int, float)) else "-", hw.get("os") or "", False))
    return out


def hardware_frame(history: Iterable[dict] | None) -> pd.DataFrame:
    cols = ["t", "cpu", "memory", "disk", "temp", "net_in", "net_out"]
    rows = []
    for p in history or []:
        t = parse_ts(p.get("t")) if isinstance(p, dict) else None
        if t is not None:
            rows.append({"t": t, **{c: p.get(c) if isinstance(p.get(c), (int, float)) else None for c in cols[1:]}})
    df = pd.DataFrame(rows, columns=cols)
    return df.sort_values("t").reset_index(drop=True) if not df.empty else df


def _hardware_layout(fig: go.Figure, yaxis: dict) -> go.Figure:
    fig.update_layout(
        height=230, margin={"l": 8, "r": 8, "t": 10, "b": 8}, paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)", hovermode="x unified",
        legend={"orientation": "h", "y": 1.12, "x": 0, "font": {"size": 12}},
        font={"color": TEXT_SECONDARY, "family": FONT, "size": 12},
        xaxis={"showgrid": False, "linecolor": GRID, "tickformat": "%H:%M"},
        yaxis={"gridcolor": GRID, "zeroline": False, **yaxis})
    return fig


# Line styles, not colours, tell the series apart: colour on this console means risk.
_SERIES = {"cpu": ("CPU", "solid"), "memory": ("Memory", "dash"), "disk": ("Fullest disk", "dot")}


def usage_figure(df: pd.DataFrame, limits: dict | None = None) -> go.Figure:
    """CPU, memory and fullest disk in % over the last hour; the dashed rule is the CPU and memory alert limit."""
    fig = go.Figure()
    for col, (name, dash) in _SERIES.items():
        if not df.empty and df[col].notna().any():
            fig.add_trace(go.Scatter(x=df["t"], y=df[col], mode="lines", name=name, connectgaps=False,
                                     line={"color": TEXT_PRIMARY if col == "cpu" else TEXT_SECONDARY, "width": 2,
                                           "dash": dash},
                                     hovertemplate=f"{name} <b>%{{y:.0f}}%</b><extra></extra>"))
    limit = (limits or {}).get("cpu")
    if isinstance(limit, (int, float)) and (limits or {}).get("alerts", True):
        fig.add_hline(y=float(limit), line={"color": BAND_COLORS["amber"], "width": 1, "dash": "dash"},
                      annotation_text=f"Alert at {limit:.0f}%", annotation_position="top left",
                      annotation_font={"color": TEXT_SECONDARY, "size": 11})
    return _hardware_layout(fig, {"range": [0, 100], "ticksuffix": "%", "tickvals": [0, 25, 50, 75, 100]})


def network_figure(df: pd.DataFrame) -> go.Figure:
    """Traffic in and out per second over the last hour."""
    fig = go.Figure()
    for col, name, dash in (("net_in", "In", "solid"), ("net_out", "Out", "dash")):
        if not df.empty and df[col].notna().any():
            fig.add_trace(go.Scatter(x=df["t"], y=df[col], mode="lines", name=name,
                                     line={"color": TEXT_PRIMARY if col == "net_in" else TEXT_SECONDARY, "width": 2,
                                           "dash": dash},
                                     customdata=[rate_label(v) for v in df[col]],
                                     hovertemplate=f"{name} <b>%{{customdata}}</b><extra></extra>"))
    return _hardware_layout(fig, {"rangemode": "tozero", "tickformat": ".2s", "ticksuffix": "B/s"})


def disk_rows(hw: dict | None) -> pd.DataFrame:
    rows = [{"Disk": d.get("mount"), "Used": bytes_label(d.get("used")), "Size": bytes_label(d.get("total")),
             "Full": float(d["percent"])}
            for d in (hw or {}).get("disks") or [] if isinstance(d, dict) and isinstance(d.get("percent"), (int, float))]
    rows.sort(key=lambda r: -r["Full"])
    return pd.DataFrame(rows, columns=["Disk", "Used", "Size", "Full"])


def temp_rows(hw: dict | None) -> pd.DataFrame:
    rows = [{"Sensor": t.get("label"), "Now": f"{t['current']:.0f} °C",
             "Its own high mark": f"{t['high']:.0f} °C" if isinstance(t.get("high"), (int, float)) else "-"}
            for t in (hw or {}).get("temps") or [] if isinstance(t, dict) and isinstance(t.get("current"), (int, float))]
    return pd.DataFrame(rows, columns=["Sensor", "Now", "Its own high mark"])


def agent_rows(agents: Iterable[dict]) -> pd.DataFrame:
    """Joined machines for the Machines page table (revoked ones last)."""
    rows = []
    for a in agents or []:
        if not isinstance(a, dict):
            continue
        off = a.get("offline") if isinstance(a.get("offline"), dict) else {}
        alone = (f"{off.get('local_blocks', 0)} local blocks, {short_time(off.get('from'))} to "
                 f"{short_time(off.get('to'))}" if off else "")
        rows.append({"Machine": a.get("host"), "Id": a.get("agent_id"), "Joined": short_time(a.get("joined_at")),
                     "Invited by": a.get("invited_by") or "", "Last seen": short_time(a.get("last_seen")) or "never",
                     "Last time offline": alone,
                     "Status": f"Revoked by {a.get('revoked_by') or '?'}" if a.get("revoked_at") else "Active"})
    rows.sort(key=lambda r: (r["Status"] != "Active", str(r["Machine"])))
    return pd.DataFrame(rows, columns=["Machine", "Id", "Joined", "Invited by", "Last seen", "Last time offline",
                                       "Status"])


JOB_LABELS = {"threat_scan": "Threat scan", "backup": "Backup"}
JOB_STATUS = {"queued": "Waiting", "running": "Running", "done": "Done", "failed": "Failed",
              "expired": "Expired", "cancelled": "Cancelled"}


def job_rows(jobs: Iterable[dict]) -> pd.DataFrame:
    """Scans and backups the panel asked one machine to run, newest first."""
    rows = []
    for j in jobs or []:
        if not isinstance(j, dict):
            continue
        rows.append({"Job": JOB_LABELS.get(str(j.get("kind")), str(j.get("kind"))),
                     "Status": JOB_STATUS.get(str(j.get("status")), str(j.get("status"))),
                     "Asked by": j.get("requested_by") or "", "Asked": short_time(j.get("created_at")),
                     "Finished": short_time(j.get("finished_at")) or "", "Result": j.get("summary") or ""})
    return pd.DataFrame(rows, columns=["Job", "Status", "Asked by", "Asked", "Finished", "Result"])


def job_findings(jobs: Iterable[dict]) -> pd.DataFrame:
    """Findings from the newest finished threat scan on one machine."""
    scan = next((j for j in jobs or [] if isinstance(j, dict) and j.get("kind") == "threat_scan"
                 and j.get("status") == "done"), None)
    rows = [{"Severity": f.get("severity"), "What": f.get("label"), "Kind": f.get("kind"),
             "File": f.get("path") + (f" ({f['entry']})" if f.get("entry") else ""), "Line": f.get("line")}
            for f in ((scan or {}).get("result") or {}).get("findings") or [] if isinstance(f, dict)]
    return pd.DataFrame(rows, columns=["Severity", "What", "Kind", "File", "Line"])


def join_commands(panel_url: str, code: str, name: str | None = None, pin: str | None = None) -> dict[str, str]:
    """What to paste on the new machine, from a SentrAI checkout: both install the agent as a service.
    ``pin`` is the panel certificate's fingerprint: the agent then trusts that certificate and no other."""
    url = panel_url.rstrip("/")
    return {
        "linux": f"sudo ./mvp/deploy/install-agent.sh --panel {url} --code {code}" + (f" --name {name}" if name else "")
                 + (f" --pin {pin}" if pin else ""),
        "windows": (f"powershell -ExecutionPolicy Bypass -File .\\mvp\\deploy\\install-agent.ps1 -Panel {url} -Code {code}"
                    + (f" -Name {name}" if name else "") + (f" -Pin {pin}" if pin else "")),
    }


def newly_joined(agents: Iterable[dict], before: Iterable[str] | None) -> list[str]:
    """Host names of machines that joined since a join code was made (``before``: the agent ids then)."""
    if before is None:
        return []
    known = set(before)
    return [str(a.get("host")) for a in agents or [] if isinstance(a, dict)
            and a.get("agent_id") not in known and not a.get("revoked_at")]


def seen_ago(ts: Any, now: datetime | None = None) -> str:
    """When a machine last called in, the way people say it: "just now", "40 s ago", "7 min ago", "never"."""
    ts = parse_ts(ts)
    if ts is None:
        return "never"
    if ts.tzinfo is None:
        ts = ts.astimezone()  # a naive time is this computer's local time
    secs = ((now or datetime.now(timezone.utc)) - ts).total_seconds()
    if secs < 10:
        return "just now"
    return f"{int(secs)} s ago" if secs < 60 else f"{span_label(secs)} ago"


def _machine_state(m: dict) -> tuple[str, str, str]:
    """(icon, state word, colour) for a machine's status shield and stripe."""
    if m.get("waiting"):
        return "hourglass_empty", "Waiting for its first data", UNKNOWN_COLOR
    if not m["online"]:
        return "cancel", "Offline", BAND_COLORS["critical"]
    if m["monitor_only"]:
        return "remove_moderator", "Protection off", BAND_COLORS["amber"]
    return "verified_user", "Protecting", BAND_COLORS["green"]


def _machine_stats(m: dict, now: datetime | None) -> str:
    """CPU, memory and disk (when its agent reports them), incidents, blocks and last call-in for a machine
    on a central panel, as a game panel's server row shows them. Hidden when the list is narrow (console.css)."""
    if "open" not in m:
        return ""
    found = [f"{m['open']} open" if m.get("open") else "", f"{m['contained']} contained" if m.get("contained") else ""]
    cells = [*(hardware_cells(m.get("hardware")) if m.get("online") else []), ("Incidents", " · ".join(x for x in found if x) or "None", bool(m.get("open"))),
             ("Blocks", f"{m['blocked']} in force" if m.get("blocked") else "None", False)]
    if m.get("sessions") is not None:  # a core that keeps track of who is signed in (admins.py)
        cells.append(("Signed in", plural(m["sessions"], "person", "people") if m["sessions"] else "Nobody", False))
    cells.append(("Last seen", seen_ago(m.get("last_seen"), now), False))
    hw = {label for label, _, _ in hardware_cells(m.get("hardware"))}
    return '<span class="m-stats">' + "".join(
        f'<span class="m-stat{" hw" if label in hw else ""}"><span class="m-stat-label">{label}</span>'
        f'<span class="m-stat-value"{" style=color:var(--amber)" if hot else ""}>{html.escape(value)}</span></span>'
        for label, value, hot in cells) + "</span>"


def machine_rows_html(machines: list[dict], link: bool = False, status: bool = False,
                      now: datetime | None = None) -> str:
    """The machine list: one row per machine, like the server list of a game panel (Pterodactyl, Calagopus).

    A status stripe and shield on the left (protecting, protection off, offline or waiting), the machine's
    name with a small risk bar under it, its incidents, blocks and last call-in on a central panel, and the
    risk number with its band word on the right. Styled by .machines in console.css; only the data-driven
    widths and colours are inline. With link set each row opens that machine's own page, so it ends with an
    arrow. With status set the row is the status card on that page: the state word takes the name's place."""
    rows = []
    for m in machines:
        icon, state, tone = _machine_state(m)
        name, place = html.escape(str(m["name"])), html.escape(str(m["place"]))
        if m.get("waiting"):
            num, word, color, width = "-", "Waiting", UNKNOWN_COLOR, 0.0
            place = f"{place} · waiting for its first data"
        elif not m["online"]:
            num, word, color, width = "0", "Offline", UNKNOWN_COLOR, 0.0
        else:
            color = band_color(m["band"])
            num = "-" if m["index"] is None else f"{m['index']:.0f}"
            word, width = BAND_WORD.get(m["band"], "Unknown"), m["index"] or 0.0
            place = f"{place} · threshold {m['threshold']:.0f}"
            if m.get("services") and not status:
                place = f"{place} · {html.escape(services_text(m['services']))}"
        title = html.escape(state) if status else name
        more = '<span class="m-more mi" aria-hidden="true">chevron_right</span>' if link else ""
        rows.append(
            f'<li class="machine{" clickable" if link else ""}{" status" if status else ""}">'
            f'<span class="m-stripe" aria-hidden="true" style="background:{tone}"></span>'
            f'<span class="m-icon mi" style="color:{tone}" aria-hidden="true">{icon}</span>'
            f'<span class="m-main"><span class="m-name">{title}</span>'
            f'<span class="m-sub"><span class="m-bar" aria-hidden="true"><i style="width:{width:.0f}%;background:{color}"></i></span>'
            f'{"" if status else f"<span class=sr>{html.escape(state)}. </span>"}{place}</span></span>'
            f'{_machine_stats(m, now)}'
            f'<span class="m-risk"><span class="m-num"{" style=color:var(--ink-muted)" if not m["online"] else ""}>{num}</span>'
            f'<span class="m-word" style="color:{color}">{word}</span></span>'
            f'{more}</li>'
        )
    label = "Machine status" if status else "SentrAI machines"
    return f'<ul class="machines" aria-label="{label}">{"".join(rows)}</ul>'


def machine_records(records: Iterable[dict], host: str, incident_ids: Iterable[str]) -> list[dict]:
    """The audit records about one machine: those naming it, and those about one of its incidents."""
    ids = {str(i) for i in incident_ids}
    out = []
    for r in records or []:
        data = r.get("data") if isinstance(r, dict) else None
        if isinstance(data, dict) and (data.get("host") == host or str(data.get("incident")) in ids):
            out.append(r)
    return out


def console_html(feed: list[dict], label: str) -> str:
    """A machine's live log in a terminal-style box, like a game panel's console: time, who, what."""
    lines = [
        f'<div class="c-line"><span class="c-time">{html.escape(e["time"])}</span>'
        f'<span class="c-who" style="color:{e["color"]}">{html.escape(e["agent"])}</span>'
        f'<span class="c-msg"><b>{html.escape(e["type"])}</b> {html.escape(e["summary"])}</span></div>'
        for e in feed
    ]
    # Focusable, so keyboard users can scroll it too.
    return f'<div class="console" tabindex="0" role="region" aria-label="{html.escape(label)}">{"".join(lines)}</div>'


def agent_facts(agent: dict | None, now: datetime | None = None) -> list[tuple[str, str]]:
    """One machine's agent for its Agent tab: id, when and by whom it joined, last call-in, time alone."""
    if not agent:
        return []
    off = agent.get("offline") if isinstance(agent.get("offline"), dict) else {}
    alone = (f"{short_time(off.get('from'))} to {short_time(off.get('to'))}, "
             f"{plural(off.get('local_blocks', 0), 'local block')}" if off else "Never")
    joined = parse_ts(agent.get("joined_at"))
    return [("Agent id", str(agent.get("agent_id") or "-")),
            ("Joined", joined.strftime("%d %b %H:%M") if joined else "-"),
            ("Invited by", str(agent.get("invited_by") or "-")),
            ("Last seen", seen_ago(agent.get("last_seen"), now)),
            ("Last time offline", alone),
            ("Blocks made while offline", str(int(agent.get("offline_total") or 0)))]


def history_frame(history: Iterable[dict] | None) -> pd.DataFrame:
    rows = []
    for point in history or []:
        if not isinstance(point, dict):
            continue
        t = parse_ts(point.get("t"))
        v = point.get("risk_index")
        if t is None or not isinstance(v, (int, float)):
            continue
        rows.append({"t": t, "risk_index": float(v)})
    df = pd.DataFrame(rows, columns=["t", "risk_index"])
    if not df.empty:
        df = df.sort_values("t").reset_index(drop=True)
    return df


def history_figure(df: pd.DataFrame, threshold: float = 80) -> go.Figure:
    fig = go.Figure()
    for name, lo, hi in BANDS:
        fig.add_hrect(y0=lo, y1=hi + 1 if hi < 100 else 100, fillcolor=BAND_COLORS[name],
                      opacity=0.06, line_width=0, layer="below")
    if not df.empty:
        last = df["risk_index"].iloc[-1]
        color = band_color(last)
        fig.add_trace(
            go.Scatter(
                x=df["t"], y=df["risk_index"], mode="lines", name="Risk index",
                line={"color": color, "width": 2, "shape": "hv"},
                fill="tozeroy", fillcolor=_fade(color, 0.12),
                hovertemplate="%{x|%H:%M:%S}<br>Risk <b>%{y:.0f}</b>/100<extra></extra>",
            )
        )
        fig.add_trace(
            go.Scatter(
                x=[df["t"].iloc[-1]], y=[last], mode="markers", showlegend=False, hoverinfo="skip",
                marker={"size": 10, "color": color, "line": {"color": SURFACE, "width": 2}},
            )
        )
    fig.add_hline(
        y=float(threshold), line={"color": TEXT_PRIMARY, "width": 1.5, "dash": "dash"},
        annotation_text=f"Autonomous threshold {threshold:.0f}", annotation_position="top left",
        annotation_font={"color": TEXT_SECONDARY, "size": 12},
    )
    fig.update_layout(
        height=230,
        margin={"l": 8, "r": 8, "t": 10, "b": 8},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=False,
        hovermode="x unified",
        font={"color": TEXT_SECONDARY, "family": FONT, "size": 12},
        xaxis={"showgrid": False, "linecolor": GRID, "tickformat": "%H:%M:%S"},
        yaxis={"range": [0, 100], "gridcolor": GRID, "tickvals": [0, 30, 60, 80, 100], "zeroline": False},
    )
    return fig


def _fade(hex_color: str, alpha: float) -> str:
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) for i in (0, 2, 4))
    return f"rgba({r},{g},{b},{alpha})"


def demote_headings(md: str, by: int = 2) -> str:
    """Render report headings smaller so they fit the panel (the download keeps the original)."""
    return re.sub(r"^(#{1,4}) ", lambda m: "#" * min(6, len(m.group(1)) + by) + " ", md or "", flags=re.M)


# ---------------------------------------------------------------- menu bubbles and part views

# Audit record types that put a bubble on a part's menu button until that page is opened.
ALERT_TYPES: dict[str, tuple[str, ...]] = {
    "collector": ("event_classified", "collector_silent"),  # malicious events picked up, silent collectors
    "classifier": ("incident_opened",),  # new attacks identified
    "responder": ("action_applied", "auto_rollback"),  # containment put in place or undone
}


def head_seq(records: list[dict]) -> int:
    return max((int(r.get("seq") or 0) for r in records), default=0)


def unseen_counts(records: list[dict], seen: dict[str, int]) -> dict[str, int]:
    """Alert records newer than the last audit seq each page was viewed at.

    A fresh audit chain starts again at 1, so a remembered seq beyond the head counts as 0.
    """
    head = head_seq(records)
    counts = {}
    for page, types in ALERT_TYPES.items():
        last = seen.get(page, 0)
        last = 0 if last > head else last
        counts[page] = sum(1 for r in records if r.get("type") in types and int(r.get("seq") or 0) > last)
    return counts


def records_of(records: list[dict], *types: str) -> list[dict]:
    """Records of the given types, newest first."""
    return sorted((r for r in records if r.get("type") in types), key=lambda r: -int(r.get("seq") or 0))


def classification_rows(records: list[dict]) -> pd.DataFrame:
    rows = [
        {
            "Time": short_time(r.get("ts")),
            "Event": d.get("event_id", "-"),
            "Category": category_label(d.get("category")),
            "Confidence": d.get("confidence"),
            "Malicious": d.get("malicious"),
            "Classified by": CLASSIFIER_LABELS.get(str(d.get("classified_by")), str(d.get("classified_by") or "-")),
            "Layer agent": d.get("agent", "-"),
            "Incident": d.get("incident", "-"),
            "Raw log line": d.get("raw", ""),
            "Reason": d.get("reason", ""),
        }
        for r in records_of(records, "event_classified")
        for d in [r.get("data") or {}]
    ]
    return pd.DataFrame(rows, columns=["Time", "Event", "Category", "Confidence", "Malicious", "Classified by",
                                       "Layer agent", "Incident", "Raw log line", "Reason"])


def risk_breakdown(incidents: Iterable[dict]) -> pd.DataFrame:
    """How the risk score is built: base x confidence x criticality, plus the inaction penalty."""
    rows = [
        {
            "Incident": inc.get("id", "?"),
            "Category": category_label(inc.get("category")),
            "Status": status_label(inc.get("status")),
            "Base": inc.get("base_points"),
            "Confidence": inc.get("ai_confidence"),
            "Criticality": "-" if inc.get("asset_criticality") is None else str(inc["asset_criticality"]),
            "Points": round(float(inc.get("points") or 0), 1),
            "Inaction penalty": round(float(inc.get("inaction_penalty") or 0), 1),
            "Unanswered for": span_label(float(inc.get("time_unaddressed_hours") or 0) * 3600)
            if inc.get("status") in ACTIVE_STATUSES else "-",
            "Counts now": incident_contribution(inc) if inc.get("status") in ACTIVE_STATUSES else 0.0,
        }
        for inc in incidents or []
    ]
    df = pd.DataFrame(rows, columns=["Incident", "Category", "Status", "Base", "Confidence", "Criticality",
                                     "Points", "Inaction penalty", "Unanswered for", "Counts now"])
    return df.sort_values("Counts now", ascending=False).reset_index(drop=True) if not df.empty else df


def all_action_rows(incidents: Iterable[dict]) -> pd.DataFrame:
    frames = [action_rows(inc).assign(Incident=inc.get("id", "?")) for inc in incidents or []]
    frames = [f for f in frames if not f.empty]
    if not frames:
        return pd.DataFrame(columns=["Incident", *action_rows({}).columns])
    df = pd.concat(frames, ignore_index=True)
    return df[["Incident", *[c for c in df.columns if c != "Incident"]]]


def start_page(incidents: Iterable[dict] | None) -> str:
    """Where the console opens: Approvals when something waits on a person, otherwise Review."""
    return "approvals" if pending_approvals(incidents or []) else "review"


# ------------------------------------------------------------------ incident board

OPEN_STATUSES = ("open", "acknowledged", "contained")  # not closed yet: somebody still owns them
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _age_hours(inc: dict, now: datetime | None = None) -> float:
    opened = parse_ts(inc.get("opened_at"))
    if opened is None:
        return 0.0
    now = now or datetime.now(opened.tzinfo)
    return max(0.0, (now - opened).total_seconds() / 3600)


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
    can = available_actions(inc)
    if can["mine"]:
        why.append("Was this you?")
    elif inc.get("needs_review"):
        why.append("AI unsure, needs review")
    if inc.get("status") == "contained" or can["contain_controls"]:
        why.append("Keep or roll back the block")
    elif can["decide"] and not inc.get("acked"):
        why.append("Waiting for a decision")
    return why


def needs_attention(incidents: Iterable[dict]) -> list[dict]:
    """Open incidents with at least one reason to look, most urgent first."""
    rows = [i for i in incidents or [] if attention(i)]
    return sorted(rows, key=lambda i: (bool(i.get("acked")), SEVERITY_RANK.get(str(i.get("severity")), 9),
                                       -incident_contribution(i)))


def board_counts(incidents: Iterable[dict], me: str = "") -> dict[str, int]:
    incs = [i for i in incidents or [] if i.get("status") in OPEN_STATUSES]
    me = me.strip().lower().lstrip("@")
    return {
        "open": len(incs),
        "attention": sum(1 for i in incs if attention(i)),
        "overdue": sum(1 for i in incs if i.get("sla_breached") and not i.get("acked")),
        "escalated": sum(1 for i in incs if int(i.get("escalation_level") or 0) > 0),
        "unassigned": sum(1 for i in incs if not i.get("owner")),
        "mine": sum(1 for i in incs if me and str(i.get("owner") or "").lower().lstrip("@") == me),
    }


BOARD_COLUMNS = ["Incident", "What", "Host", "Severity", "Status", "Owner", "Backup", "Open for", "Needs"]


def split_waves(incidents: Iterable[dict]) -> tuple[list[dict], dict[str, list[dict]]]:
    """(incidents in no wave, {wave id: its incidents}), each in the order given."""
    singles: list[dict] = []
    waves: dict[str, list[dict]] = {}
    for inc in incidents or []:
        if inc.get("wave"):
            waves.setdefault(str(inc["wave"]), []).append(inc)
        else:
            singles.append(inc)
    return singles, waves


WAVE_DOING = {"port_scan": "scanning", "brute_force": "guessing passwords on"}


def wave_line(members: list[dict]) -> str:
    """'40 addresses scanning game-01 need a person', for the incidents of one wave."""
    first = members[0] if members else {}
    doing = WAVE_DOING.get(str(first.get("category")), f"{category_label(first.get('category')).lower()} on")
    n = len({m.get("src_ip") or m.get("id") for m in members})
    return f"{n} address{'es' if n != 1 else ''} {doing} {first.get('host') or 'a machine'} need a person"


WAVE_COLUMNS = ["Wave", "What", "Machine", "Addresses", "Top networks", "Started", "Last seen", "Now"]


def wave_rows(waves: Iterable[dict]) -> pd.DataFrame:
    rows = [{
        "Wave": w.get("id", "?"),
        "What": category_label(w.get("category")),
        "Machine": w.get("host") or "-",
        "Addresses": int(w.get("addresses") or 0),
        "Top networks": ", ".join(f"{n.get('network')} ({n.get('addresses')})" for n in (w.get("networks") or [])[:3])
        or "spread out",
        "Started": str(w.get("started_at") or "")[11:16] or "-",
        "Last seen": str(w.get("last_seen_at") or "")[11:16] or "-",
        "Now": "Going" if w.get("active") else "Quiet",
    } for w in waves or []]
    return pd.DataFrame(rows, columns=WAVE_COLUMNS)


def _wave_board_row(wid: str, members: list[dict]) -> dict:
    """A wave's incidents as one board row: the worst severity, the oldest age, how many need a person."""
    worst = min(members, key=lambda i: SEVERITY_RANK.get(str(i.get("severity")), 9))
    open_ = [i for i in members if i.get("status") in OPEN_STATUSES]
    needing = [i for i in open_ if attention(i)]
    owners = sorted({str(i.get("owner") or "Nobody") for i in members})
    return {
        "Incident": f"{wid} ({len(members)})",
        "What": category_label(worst.get("category")),
        "Host": worst.get("host") or "-",
        "Severity": str(worst.get("severity") or "-").capitalize(),
        "Status": f"{len(open_)} open" if open_ else "Closed",
        "Owner": owners[0] if len(owners) == 1 else f"{len(owners)} people",
        "Backup": worst.get("backup") or "-",
        "Open for": span_label(max(_age_hours(i) for i in open_) * 3600) if open_ else "-",
        "Needs": f"{len(needing)} need a person: approve together on Approvals" if needing else "In hand",
        "_rank": (not open_, not needing, SEVERITY_RANK.get(str(worst.get("severity")), 9)),
    }


def board_rows(incidents: Iterable[dict], include_closed: bool = False, group_waves: bool = False) -> pd.DataFrame:
    """One row per incident: who has it, how long it has been open, and what it still needs.
    With group_waves, a wave's incidents are one row."""
    rows = []
    incidents = [i for i in incidents or [] if include_closed or i.get("status") in OPEN_STATUSES]
    if group_waves:
        incidents, waves = split_waves(incidents)
        rows += [_wave_board_row(wid, members) for wid, members in waves.items()]
    for inc in incidents:
        closed = inc.get("status") not in OPEN_STATUSES
        needs = attention(inc)
        rows.append({
            "Incident": inc.get("id", "?"),
            "What": category_label(inc.get("category")),
            "Host": inc.get("host") or "-",
            "Severity": str(inc.get("severity") or "-").capitalize(),
            "Status": status_label(inc.get("status")),
            "Owner": inc.get("owner") or "Nobody",
            "Backup": inc.get("backup") or "-",
            "Open for": span_label(_age_hours(inc) * 3600) if not closed else "-",
            "Needs": ("Closed by " + str(inc.get("resolved_by") or inc.get("acked_by") or "-")) if closed
            else ("; ".join(needs) if needs else "In hand"),
            "_rank": (closed, not needs, SEVERITY_RANK.get(str(inc.get("severity")), 9)),
        })
    if not rows:
        return pd.DataFrame(columns=BOARD_COLUMNS)
    rows.sort(key=lambda r: r["_rank"])
    return pd.DataFrame(rows, columns=BOARD_COLUMNS)


def owner_history(inc: dict) -> list[str]:
    """Plain lines: who was given the incident, by whom, and every escalation."""
    out = [f"{t.get('ts', '')[11:19]}  {t.get('text', '')}" for t in inc.get("timeline") or []
           if t.get("kind") in ("assigned", "escalated", "ack", "resolved")]
    return out


def routing_rows(routing: dict | None) -> pd.DataFrame:
    names = {c.get("id"): c.get("name") for c in (routing or {}).get("contacts") or []}
    rows = []
    for r in (routing or {}).get("rules") or []:
        match = r.get("match") or {}
        rows.append({
            "Rule": r.get("name"),
            "When": "; ".join(f"{k} is {' or '.join(v)}" for k, v in match.items()) or "anything else",
            "Owner": names.get(r.get("owner"), r.get("owner")),
            "Also told": ", ".join(names.get(x, x) for x in r.get("notify") or []) or "-",
        })
    return pd.DataFrame(rows, columns=["Rule", "When", "Owner", "Also told"])


def contact_rows(routing: dict | None) -> pd.DataFrame:
    contacts = (routing or {}).get("contacts") or []
    names = {c.get("id"): c.get("name") for c in contacts}
    telegram = any("telegram_linked" in c for c in contacts)  # the core says so only while Telegram is added
    rows = [{"Contact": c.get("name"), "Role": str(c.get("role") or "-").replace("_", " "),
             "Email": c.get("email") or "-", "Telegram": c.get("telegram") or "-",
             # Linked: alerts go to the person's own chat; otherwise they are mentioned in the team group.
             "Alerts in Telegram": "Own chat" if c.get("telegram_linked") else "Team group",
             "Backup": names.get(c.get("backup"), "-") if c.get("backup") else "-"} for c in contacts]
    columns = ["Contact", "Role", "Email", "Telegram", *(["Alerts in Telegram"] if telegram else []), "Backup"]
    return pd.DataFrame([{k: r[k] for k in columns} for r in rows], columns=columns)


# ------------------------------------------------- "Who gets what" editor (routing_editor.mjs)

SEVERITY_CHOICES = ["low", "medium", "high", "critical"]
ROLE_CHOICES = ["", "on_duty", "team_lead", "it_manager", "cxo"]
ROLE_LABELS = {"": "none", "on_duty": "on duty", "team_lead": "team lead", "it_manager": "IT manager", "cxo": "CXO"}


def routing_doc(routing: dict | None) -> dict:
    """GET /routing turned into the file shape POST /routing takes, to edit and send back."""
    routing = routing or {}
    contacts = {str(c.get("id")): {k: str(c.get(k) or "") for k in ("name", "role", "email", "telegram", "backup")}
                for c in routing.get("contacts") or [] if c.get("id")}
    rules = [{"name": str(r.get("name") or ""), "match": {k: list(v) for k, v in (r.get("match") or {}).items()},
              "owner": str(r.get("owner") or ""), "notify": list(r.get("notify") or [])}
             for r in routing.get("rules") or []]
    return {"contacts": contacts, "rules": rules, "follow_up": dict(routing.get("follow_up") or {})}


def routing_version(routing: dict | None) -> str:
    """A short fingerprint of everything the editor can change (not Telegram links), so it can tell
    a save of its own from someone else's."""
    doc = routing_doc(routing) | {"layout": (routing or {}).get("layout") or {}}
    return hashlib.sha256(json.dumps(doc, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def routing_editor_data(routing: dict | None, read_only: bool = False, lock_reason: str = "",
                        result: dict | None = None, focus: str = "") -> dict:
    """What the "Who gets what" editor draws: the routing (people in file order), the choices its panel
    offers, whether this person may change anything, and how their last save went."""
    routing = routing or {}
    doc = routing_doc(routing)
    return {
        "routing": {"contacts": [{"id": cid, **c} for cid, c in doc["contacts"].items()], "rules": doc["rules"],
                    "follow_up": doc["follow_up"], "layout": routing.get("layout") or {}},
        "version": routing_version(routing),
        "linked": {str(c.get("id")): True for c in routing.get("contacts") or [] if c.get("telegram_linked")},
        "categories": [[k, v] for k, v in CATEGORY_LABELS.items()],
        "severities": SEVERITY_CHOICES,
        "roles": [[r, ROLE_LABELS[r]] for r in ROLE_CHOICES],
        "read_only": bool(read_only),
        "lock_reason": lock_reason,
        "result": result,
        "focus": focus,  # a person to mark "you" (a person's own part of the map)
        "numbers": list(routing.get("numbers") or []),  # each rule's place in the full list, when cut down
    }


def routing_from_editor(routing: Any) -> dict:
    """The editor's Save turned into the file POST /routing takes: people keyed by id in the order the
    editor lists them, text trimmed, and where each box sits on the map. The core checks it all again."""
    routing = routing if isinstance(routing, dict) else {}
    part = lambda key, kind: routing.get(key) if isinstance(routing.get(key), kind) else kind()  # noqa: E731
    contacts = {}
    for c in part("contacts", list):
        if isinstance(c, dict) and str(c.get("id") or "").strip():
            contacts[str(c["id"]).strip()] = {k: str(c.get(k) or "").strip()
                                               for k in ("name", "role", "email", "telegram", "backup")}
    rules = []
    for r in part("rules", list):
        if not isinstance(r, dict):
            continue
        match = r.get("match") if isinstance(r.get("match"), dict) else {}
        values = {str(k): [str(x).strip() for x in (v if isinstance(v, list) else [v]) if str(x or "").strip()]
                  for k, v in match.items()}
        rules.append({"name": str(r.get("name") or "").strip(), "match": {k: v for k, v in values.items() if v},
                      "owner": str(r.get("owner") or ""), "notify": [str(x) for x in r.get("notify") if x]
                                                               if isinstance(r.get("notify"), list) else []})
    out = {"contacts": contacts, "rules": rules, "follow_up": dict(part("follow_up", dict))}
    if isinstance(routing.get("layout"), dict):
        out["layout"] = routing["layout"]
    return out


# ------------------------------------------------- each person's own part of "Who gets what"

def _same(a: Any, b: Any) -> bool:
    a, b = str(a or "").strip().lower().lstrip("@"), str(b or "").strip().lower().lstrip("@")
    return bool(a) and a == b


def find_person(routing: dict | None, email: str = "", name: str = "") -> dict | None:
    """The person in "Who gets what" a signed-in account is: same email first, else the same name."""
    contacts = (routing or {}).get("contacts") or []
    return (next((c for c in contacts if email and _same(c.get("email"), email)), None)
            or next((c for c in contacts if name and _same(c.get("name"), name)), None))


def my_part(routing: dict | None, cid: str, incidents: Iterable[dict] = ()) -> dict:
    """What one person does in "Who gets what": the rules they own or hear about, who backs them up,
    whom they back up, and the incidents that reach them (owned, backing up, or told once)."""
    routing = routing or {}
    contacts = {str(c.get("id")): c for c in routing.get("contacts") or [] if c.get("id")}
    me = contacts.get(cid) or {}
    name = str(me.get("name") or "")
    rules = list(routing.get("rules") or [])
    owns = [(i, r) for i, r in enumerate(rules) if r.get("owner") == cid]
    told = [(i, r) for i, r in enumerate(rules) if r.get("owner") != cid and cid in (r.get("notify") or [])]
    backup = contacts.get(str(me.get("backup") or ""))
    covers = [c for c in contacts.values() if c.get("backup") == cid and str(c.get("id")) != cid]
    mine, backing, heard = [], [], []
    for inc in incidents or []:
        if _same(inc.get("owner"), name):
            mine.append(inc)
        elif _same(inc.get("backup"), name):
            backing.append(inc)
        elif any(_same(n, name) for n in inc.get("notify") or []):
            heard.append(inc)
    return {"person": me, "owns": owns, "told": told, "backup": backup, "covers": covers,
            "mine": mine, "backing": backing, "heard": heard}


def my_routing(routing: dict | None, cid: str) -> dict:
    """The same routing cut down to one person's part, to draw read-only: the rules that reach them and
    who owns each, their backup and the people they back up (others those rules tell are left out). Boxes keep the places
    they have on the whole map, and ``numbers`` keeps each rule's place in the full list."""
    routing = routing or {}
    part = my_part(routing, cid)
    picked = sorted(part["owns"] + part["told"], key=lambda x: x[0])
    keep = {cid} | {str(c.get("id")) for c in part["covers"]}
    if part["backup"]:
        keep.add(str(part["backup"].get("id")))
    keep.update(str(r.get("owner")) for _, r in picked)
    contacts = []
    for c in routing.get("contacts") or []:
        if str(c.get("id")) in keep:
            c = dict(c)
            if c.get("backup") not in keep:  # drawn only between people on this map
                c["backup"] = ""
            contacts.append(c)
    layout = routing.get("layout") or {}
    spots = layout.get("rules") or []
    cut = {k: v for k, v in layout.items() if k in ("incident",)}
    if spots:
        cut["rules"] = [spots[i] if i < len(spots) else None for i, _ in picked]
    if layout.get("contacts"):
        cut["contacts"] = {k: v for k, v in layout["contacts"].items() if k in keep}
    rules = [{**r, "notify": [x for x in r.get("notify") or [] if x in keep]} for _, r in picked]
    return {**routing, "contacts": contacts, "rules": rules, "layout": cut,
            "numbers": [i + 1 for i, _ in picked]}


# ------------------------------------------------- the pipeline's steps (flow_canvas.mjs, pipeline ribbon)

# Every kind of action the core takes (core/app/agents.py ACTION_TEXT), in plain words, in a fixed order.
ACTION_WORDS = {"block_ip": "block an address", "rate_limit": "slow an address down", "waf_rule": "add a web firewall rule",
                "lock_user": "lock an account", "kill_process": "stop a program", "revoke_public_acl": "make a public file private"}
ALERT_EXTENSIONS = ("telegram", "slack")


def _ext(extensions: Iterable[dict] | None, name: str) -> dict | None:
    return next((r for r in extensions or [] if r.get("name") == name), None)


def _ext_on(row: dict | None) -> bool:
    return bool(row and row.get("added") and row.get("configured") and not (row.get("error") or row.get("last_error")))


def flow_map_data(risk: dict | None, incidents: Iterable[dict] | None, agents: Iterable[dict] | None,
                  blocklist: dict | None, extensions: Iterable[dict] | None, records: list[dict] | None,
                  settings: dict[str, str] | None, chain_ok: bool | None = None) -> dict:
    """The steps an attack goes through, each with what it is doing right now, for the overview canvas and
    the ribbon on each step's page: logs come in, get sorted, scored, then wait for a person or are acted on,
    blocked, and the owner and alert channels hear about it, all written down. Each step names the page that
    shows it in full."""
    risk, settings = risk or {}, settings or {}
    incidents, agents, records = list(incidents or []), list(agents or []), list(records or [])
    blocklist = blocklist or {}
    open_ = [i for i in incidents if i.get("status") in OPEN_STATUSES]
    layer = [a for a in agents if "analyzed" in a]
    events = sum(int(a.get("analyzed") or 0) for a in layer)
    collectors = (next((a for a in agents if a.get("name") == "Watchdog"), {}) or {}).get("collectors") or []
    silent = records_of(records, "collector_silent")
    attacks = records_of(records, "event_classified")
    jev = next((a for a in agents if a.get("name") == "Jev"), {})
    ai, ai_note = ai_classifier_state(jev.get("status"), _ext(extensions, "typesafe"))
    idx, threshold = risk.get("risk_index"), float(risk.get("threshold") or settings.get("RISK_THRESHOLD") or 80)
    band = resolve_band(risk) if risk else "unknown"
    waiting = pending_approvals(incidents)
    watch_only = bool(risk.get("monitor_only"))
    allowed = [x.strip() for x in str(settings.get("AUTO_ACTIONS") or "").split(",") if x.strip()]
    per_hour = settings.get("MAX_AUTO_ACTIONS_PER_HOUR") or "10"
    ips, users = len(blocklist.get("ips") or []), len(blocklist.get("users") or [])
    hours = settings.get("HOTPATCH_TTL_HOURS") or "2"
    no_owner = sum(1 for i in open_ if not i.get("owner"))
    edge = _ext(extensions, "cloudflare")
    email_on = bool(settings.get("SMTP_HOST") and settings.get("ALERT_EMAIL_TO"))
    channels = (["email"] if email_on else []) + [n.capitalize() for n in ALERT_EXTENSIONS if _ext_on(_ext(extensions, n))]
    broken = [str(r.get("title") or r.get("name")) for r in extensions or []
              if r.get("added") and (r.get("error") or r.get("last_error"))]

    def node(nid, col, row, title, what, value, note, state, page, ico, unit="", badge=None):
        """One box: a live count in big type (value, with its unit), an On/Off badge for a switch, a one-line
        note under the count, and `what`, the step explained in full, for the hover tip."""
        return {"id": nid, "col": col, "row": row, "title": title, "what": what, "value": value, "unit": unit,
                "note": note, "state": state, "page": page, "icon": ico, "badge": badge}

    may = ", ".join(ACTION_WORDS.get(a, a.replace("_", " ")) for a in allowed)
    nodes = [
        node("logs", 0, 1, "Logs come in", "Every line your machines write to their logs is read here, as it is "
             "written.", f"{events:,}", "lines read" +
             (f" · {plural(len(silent), 'source')} went quiet" if silent else
              f" · {plural(len(collectors), 'source')} reporting" if collectors else ""),
             "busy" if silent else "ok" if events or collectors else "idle", "collector", "input"),
        node("sort", 1, 1, "Sorted", "Each line is sorted into attack or normal: fixed rules first, then the AI "
             "for what the rules cannot settle, then keywords.", f"{len(attacks):,}",
             f"looked like attacks · AI {ai.lower()}", "alert" if attacks else "ok", "classifier", "category"),
        node("score", 2, 1, "Danger score", f"How dangerous things are right now, from 0 to 100. From "
             f"{threshold:.0f} up, SentrAI may act on its own; below that it only tells people.",
             "-" if idx is None else f"{idx}", f"acts on its own from {threshold:.0f}", "unknown" if idx is None else
             "alert" if band in ("red", "critical") else "busy" if band == "amber" else "ok", "review", "speed",
             unit="" if idx is None else "/ 100"),
        node("ask", 3, 0, "Waits for a person", "Anything SentrAI is unsure about, or is not allowed to do on its "
             "own, waits here until a person approves or rejects it.", str(len(waiting)),
             "waiting for approval" if waiting else "nothing waiting", "busy" if waiting else "ok", "approvals",
             "pending_actions"),
        node("auto", 3, 1, "Acts on its own", "Watching only: it blocks nothing until protection is switched on."
             if watch_only else f"It may {may} without asking, at most {per_hour} times an hour. Change this on "
             "Automation guardrails." if allowed else "Nothing is allowed on its own, so every action waits for a "
             "person. Change this on Automation guardrails.", str(0 if watch_only else len(allowed)),
             "watching only, blocks nothing" if watch_only else
             (f"{'kind' if len(allowed) == 1 else 'kinds'} of action allowed · {per_hour} an hour at most"
              if allowed else "everything waits for a person"),
             "off" if watch_only or not allowed else "ok", "guardrails", "smart_toy",
             badge="Off" if watch_only or not allowed else "On"),
        node("block", 4, 0.5, "Blocks the attacker", f"Blocks the address or locks the account. Each block undoes "
             f"itself after {hours} h unless a person keeps it.", str(ips + users),
             f"{plural(ips, 'address', 'addresses')}, {plural(users, 'account')} blocked now",
             "busy" if ips + users else "ok", "responder", "block"),
        node("edge", 5, 0.5, "Blocks at the edge", "Sends the same blocks to Cloudflare, so attackers are stopped "
             "before they reach your servers at all.", None,
             "through Cloudflare" if edge else "Cloudflare not set up",
             "ok" if _ext_on(edge) else "alert" if edge and edge.get("added") else "off", "extensions", "public",
             badge="On" if _ext_on(edge) else "Off"),
        node("owner", 3, 2, "Owner gets it", "Every incident gets an owner, picked by the rules under Who gets "
             "what on the Incidents page.", str(len(open_)),
             f"open · {no_owner} with no owner" if no_owner else "open, each with an owner",
             "alert" if no_owner else "busy" if open_ else "ok", "incidents", "assignment_ind"),
        node("alerts", 4, 2, "Alerts go out", "People hear about it by email or chat, with buttons to approve, "
             "reject or roll back.", str(len(channels)),
             ("channels: " + ", ".join(channels) if channels else "no channel set up") +
             (f" · {', '.join(broken)} failing" if broken else ""),
             "alert" if broken else "ok" if channels else "off", "extensions", "send"),
        node("record", 5, 2, "Written down", "Every step is written to the audit trail and sealed, so no one can "
             "change it quietly.", f"{len(records):,}",
             "records · chain intact" if chain_ok else "records · chain broken" if chain_ok is False else "records",
             "alert" if chain_ok is False else "ok", "audit", "link"),
    ]
    # Two lanes after scoring: stopping the attacker (top) and telling people (bottom); all of it is written down.
    edges = [("logs", "sort"), ("sort", "score"), ("score", "ask"), ("score", "auto"), ("ask", "block"),
             ("auto", "block"), ("block", "edge"), ("score", "owner"), ("owner", "alerts"), ("alerts", "record"),
             ("block", "record")]
    live = {n["id"]: n["state"] in ("busy", "alert") for n in nodes}
    return {"nodes": nodes, "edges": [{"from": a, "to": b, "live": live[a] and live[b]} for a, b in edges],
            "colors": {"ok": BAND_COLORS["green"], "busy": BAND_COLORS["amber"], "alert": BAND_COLORS["critical"]}}


def pipeline_ribbon(flow: dict) -> list[dict]:
    """The slim line of live numbers a step's page shows once its "How this step works" panel is put away:
    lines read, sorted as attacks, waiting for a person, blocked now. Taken from flow_map_data's nodes."""
    by_id = {n["id"]: n for n in flow.get("nodes") or []}
    words = (("logs", "lines read"), ("sort", "sorted as attacks"), ("ask", "waiting for a person"),
             ("block", "blocked now"))
    return [{"value": by_id[k]["value"], "label": label, "page": by_id[k]["page"], "state": by_id[k]["state"]}
            for k, label in words if k in by_id]


# ------------------------------------------------- Pipeline overview canvas (flow_canvas.mjs)

# The settings each step's block offers on the canvas: its own, from the same fields as the Configuration
# page and Automation guardrails, so a value saved here shows there too. Never a key or a token.
BLOCK_SETTINGS = {
    "logs": ("SENTRAI_LAB_LOGS", "SENTRAI_LOG_ACCESS", "SENTRAI_LOG_AUTH", "SENTRAI_LOG_DB", "SENTRAI_LOG_OS"),
    "sort": ("BRUTE_FORCE_COUNT", "BRUTE_FORCE_WINDOW_S", "EXPORT_ROWS_THRESHOLD"),
    "score": ("RISK_THRESHOLD",),
    "ask": ("SLA_HOURS",),
    "auto": ("AUTO_ACTIONS", "MAX_AUTO_ACTIONS_PER_HOUR", "NEEDLE_MIN_CONFIDENCE"),
    "block": ("HOTPATCH_TTL_HOURS", "MAX_TTL_HOURS", "PROTECTED_IPS", "PROTECTED_USERS", "SENTRAI_HEALTH_URL"),
    "alerts": ("SMTP_HOST", "SMTP_PORT", "SMTP_SECURITY", "SMTP_USER", "ALERT_EMAIL_FROM", "ALERT_EMAIL_TO",
               "SENTRAI_EMAIL_MODE", "ON_DUTY"),
}
# Which step an extension plugs into, and which way things go: alerts and blocks go out to the service,
# lookups and AI verdicts come in to the sorting step.
EXTENSION_STEPS = {"Alerts": ("alerts", "out"), "Blocking": ("edge", "out"), "Classifier": ("sort", "in"),
                   "Lookups": ("sort", "in"), "Other": ("record", "out")}
EXTENSION_ICONS = {"Alerts": "send", "Blocking": "public", "Classifier": "smart_toy", "Lookups": "travel_explore",
                   "Other": "extension"}
CANVAS_MOST = {"ids": 400, "notes": 100, "note_chars": 2000, "wires": 500, "coord": 100_000, "id_chars": 200}
_NOTE_ID = re.compile(r"note:\d{1,6}")


def setting_specs(envs: Iterable[str], fields: dict, values: dict[str, str]) -> list[dict]:
    """The settings a block's panel shows, from the same fields as the Configuration page (sentrai_config.Field):
    label, saved value, kind (int, float, choice, set or str) and the choices. A key, token or generated value
    never goes to the browser."""
    out = []
    for env in envs:
        f = fields.get(env)
        if f is None or getattr(f, "secret", False) or getattr(f, "generated", False):
            continue
        kind = "int" if f.kind is int else "float" if f.kind is float else "choice" if f.choices else "str"
        choices: list = list(f.choices)
        if env == "AUTO_ACTIONS":  # a set of the actions the core knows, as tick boxes
            kind, choices = "set", [[k, v] for k, v in ACTION_WORDS.items()]
        out.append({"env": env, "label": f.prompt, "value": str(values.get(env, f.default)), "default": str(f.default),
                    "kind": kind, "choices": choices})
    return out


def check_block_settings(changes: Any, specs: Iterable[dict] | None) -> dict[str, str]:
    """A block's Save checked again here: only settings the block offers, each of the right kind. The values,
    cleaned, or ValueError with a reason a person can act on. The guardrail limits get check_limits after."""
    changes = changes if isinstance(changes, dict) else {}
    by_env = {s["env"]: s for s in specs or []}
    out: dict[str, str] = {}
    for env, raw in changes.items():
        s = by_env.get(str(env))
        if s is None:
            raise ValueError(f"{env} is not a setting of this block")
        value = str(raw if raw is not None else "").strip()
        if len(value) > 2000:
            raise ValueError(f"{s['label']} is too long")
        if s["kind"] == "int":
            try:
                int(value)
            except ValueError:
                raise ValueError(f"{s['label']} must be a whole number") from None
        elif s["kind"] == "float":
            try:
                number = float(value)
            except ValueError:
                raise ValueError(f"{s['label']} must be a number") from None
            if not math.isfinite(number):
                raise ValueError(f"{s['label']} must be a number")
        elif s["kind"] == "choice":
            if value not in s["choices"]:
                raise ValueError(f"{s['label']} must be one of: {', '.join(s['choices'])}")
        elif s["kind"] == "set":
            keys = [k for k, _ in s["choices"]]
            picked = [x.strip() for x in value.split(",") if x.strip()]
            if any(p not in keys for p in picked):
                raise ValueError("an action SentrAI does not know was in the list")
            value = ",".join(k for k in keys if k in picked)
        out[str(env)] = value
    if not out:
        raise ValueError("nothing changed")
    return out


def clean_canvas_doc(raw: Any) -> dict:
    """The saved canvas file (overview-canvas.json), in shape: which default blocks are hidden, which others were
    added, the notes, where each block sits and the wires drawn or taken away by hand. Anything else in the
    file is dropped, so a hand-edited or damaged file never breaks the page."""
    raw = raw if isinstance(raw, dict) else {}
    most = CANVAS_MOST

    def an_id(x: Any) -> bool:
        return isinstance(x, str) and 0 < len(x) <= most["id_chars"]

    def ids(v: Any) -> list[str]:
        return list(dict.fromkeys(x for x in (v if isinstance(v, list) else []) if an_id(x)))[:most["ids"]]

    notes = {k: v[:most["note_chars"]] for k, v in (raw.get("notes") or {}).items()
             if isinstance(k, str) and _NOTE_ID.fullmatch(k) and isinstance(v, str)} if isinstance(raw.get("notes"), dict) else {}
    notes = dict(list(notes.items())[:most["notes"]])
    pos: dict[str, list[int]] = {}
    for k, v in (raw.get("pos") or {}).items() if isinstance(raw.get("pos"), dict) else []:
        if an_id(k) and isinstance(v, list) and len(v) == 2 and all(
                isinstance(n, (int, float)) and not isinstance(n, bool) and math.isfinite(n) for n in v):
            pos[k] = [int(max(-most["coord"], min(most["coord"], round(n)))) for n in v]
        if len(pos) >= most["ids"]:
            break

    def pairs(v: Any) -> list[list[str]]:
        out, seen = [], set()
        for w in v if isinstance(v, list) else []:
            if isinstance(w, list) and len(w) == 2 and all(an_id(x) for x in w) and w[0] != w[1] and tuple(w) not in seen:
                seen.add(tuple(w))
                out.append([w[0], w[1]])
            if len(out) >= most["wires"]:
                break
        return out

    wires = raw.get("wires") if isinstance(raw.get("wires"), dict) else {}
    return {"version": 1, "hidden": ids(raw.get("hidden")), "added": ids(raw.get("added")), "notes": notes, "pos": pos,
            "wires": {"added": pairs(wires.get("added")), "removed": pairs(wires.get("removed"))}}


def extension_removal_note(kind: Any, title: str) -> str:
    """What turning an extension off will do, said before the person confirms (Extensions page and canvas)."""
    what = {"Blocking": f"Blocks it added at {title} are taken out there again; SentrAI's own blocks stay.",
            "Alerts": f"Alerts stop going to {title} within 15 seconds; the console and email still get them.",
            "Classifier": f"Events are classified by the rules and the keyword fallback, without {title}.",
            "Lookups": f"New incidents get no {title} lookups; what earlier ones show stays."}.get(kind, "")
    return f"{what} Its settings are kept, so adding it back restores it.".strip()


def _short(text: Any, most: int = 90) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= most else text[:most - 1].rstrip() + "…"


def machine_block(m: dict, panel: bool, now: datetime | None = None) -> dict:
    """One machine as a block on the canvas: its risk number, what state it is in, and its facts for the panel.
    On a central panel the block opens the machine's own page; otherwise the Machines page."""
    host = str(m.get("host") or m.get("name") or "")
    _, state_word, _ = _machine_state(m)
    online, idx = bool(m.get("online")), m.get("index")
    open_, contained, blocked = int(m.get("open") or 0), int(m.get("contained") or 0), int(m.get("blocked") or 0)
    if m.get("waiting"):
        state = "unknown"
    elif not online:
        state = "alert"
    elif open_ or m.get("band") in ("red", "critical"):
        state = "alert"
    elif m.get("monitor_only") or m.get("band") == "amber":
        state = "busy"
    else:
        state = "ok"
    bits = [state_word.lower()]
    if open_:
        bits.append(plural(open_, "open incident"))
    if blocked:
        bits.append(f"{plural(blocked, 'block')} in force")
    if "last_seen" in m and not m.get("waiting"):
        bits.append(f"seen {seen_ago(m.get('last_seen'), now)}")
    facts = [["Status", state_word]]
    if online and idx is not None:
        facts.append(["Risk", f"{idx:.0f} of 100 · acts from {float(m.get('threshold') or 80):.0f}"])
    if "open" in m:
        found = [f"{open_} open" if open_ else "", f"{contained} contained" if contained else ""]
        facts.append(["Incidents", " · ".join(x for x in found if x) or "none open"])
        facts.append(["Blocks", f"{blocked} in force" if blocked else "none"])
    if "last_seen" in m:
        facts.append(["Last seen", seen_ago(m.get("last_seen"), now)])
    if m.get("hardware"):
        facts.append(["Hardware", hardware_text(m.get("hardware"))])
    if m.get("services"):
        facts.append(["Services", services_text(m["services"])])
    if m.get("place"):
        facts.append(["Where", str(m["place"])])
    if panel and m.get("host"):
        what = (f"{m.get('name') or host} reports to this panel: its logs come in here and SentrAI scores and "
                "blocks on it on its own. Click Open for its incidents, blocks, hardware and agent.")
    elif m.get("place") == "Remote":
        what = f"{m.get('name') or host}: another SentrAI core, listed in SENTRAI_PEERS, watched from here."
    else:
        what = "This computer: the logs SentrAI reads here and everything it does about them."
    return {"id": f"machine:{host}", "kind": "machine", "step": "logs", "title": str(m.get("name") or host), "icon": "dns",
            "what": what, "value": "-" if idx is None or not online else f"{float(idx):.0f}",
            "unit": "" if idx is None or not online else "/ 100", "note": _short(" · ".join(bits)), "state": state,
            "badge": None, "page": "machine" if panel and m.get("host") else "machines",
            "host": host if panel and m.get("host") else "", "settings": [], "facts": facts}


def extension_block(r: dict, fields: dict, ext_fields: dict[str, Iterable[str]], values: dict[str, str],
                    managed: bool = False) -> dict:
    """One extension as a block: on or off, set up or not, its settings (never its key) and the step it plugs
    into. The switch turns it on or off like the Extensions page's Add and Remove."""
    name, title = str(r.get("name") or ""), str(r.get("title") or r.get("name") or "")
    kind = str(r.get("kind") or "Other")
    step, direction = EXTENSION_STEPS.get(kind, EXTENSION_STEPS["Other"])
    added, configured = bool(r.get("added")), bool(r.get("configured"))
    trouble = str(r.get("error") or r.get("last_error") or "")
    if added and trouble:
        state, note = "alert", trouble
    elif added and configured:
        state, note = "ok", str(r.get("detail") or "on")
    elif added:
        state, note = "alert", "on, but not set up: it needs its key"
    else:
        state, note = "off", "off · turn it on in the panel"
    facts = [["Kind", kind], ["State", "On" if added else "Off"]]
    if added and r.get("configured") is not None:
        facts.append(["Set up", "yes" if configured else "no, it needs its key"])
    if r.get("last_ok"):
        facts.append(["Last worked", str(r["last_ok"])])
    if trouble:
        facts.append(["Problem", trouble])
    if r.get("changed_by") and r.get("added_by") == "dashboard":
        facts.append(["Changed", f"{'added' if added else 'removed'} by {r['changed_by']}, {day_time(r.get('changed_at'))}"])
    if added and r.get("detail"):
        facts.append(["Detail", str(r["detail"])])
    return {"id": f"ext:{name}", "kind": "ext", "step": step, "direction": direction, "title": title,
            "icon": EXTENSION_ICONS.get(kind, "extension"), "what": str(r.get("what") or ""), "value": None, "unit": "",
            "note": _short(note), "state": state, "badge": "On" if added else "Off", "page": "extensions", "host": "",
            "settings": setting_specs(ext_fields.get(name, ()), fields, values), "facts": facts,
            "switch": {"name": name, "title": title, "on": added, "managed": bool(managed),
                       "off_note": extension_removal_note(kind, title)}}


def flow_canvas_data(flow: dict, machines: Iterable[dict] | None, extensions: Iterable[dict] | None,
                     settings: dict[str, str] | None, fields: dict, ext_fields: dict[str, Iterable[str]] | None,
                     doc: Any, read_only: bool = False, lock_reason: str = "", results: Iterable[dict] | None = None,
                     panel: bool = False, ext_managed: bool = False, now: datetime | None = None) -> dict:
    """What the canvas draws: every block that can be on it (the steps from flow_map_data, each machine, each
    installed extension) with what it is doing now and the settings it offers, the wires between them, which
    blocks are on by default, the saved layout and its version, whether this person may change anything, and
    the answers to the canvas's last requests."""
    settings = settings or {}
    blocks = [{**n, "id": f"step:{n['id']}", "kind": "step", "host": "",
               "settings": setting_specs(BLOCK_SETTINGS.get(n["id"], ()), fields, settings), "facts": []}
              for n in flow.get("nodes") or []]
    wires = [{"from": f"step:{e['from']}", "to": f"step:{e['to']}", "live": bool(e.get("live"))}
             for e in flow.get("edges") or []]
    live = {b["id"]: b["state"] in ("busy", "alert") for b in blocks}
    for m in machines or []:
        if not isinstance(m, dict) or not (m.get("host") or m.get("name")):
            continue
        b = machine_block(m, panel, now)
        blocks.append(b)
        wires.append({"from": b["id"], "to": "step:logs", "live": b["state"] == "alert" and live.get("step:logs", False)})
    defaults = [b["id"] for b in blocks]
    for r in extensions or []:
        if not isinstance(r, dict) or r.get("built_in") or not r.get("name"):
            continue
        b = extension_block(r, fields, ext_fields or {}, settings, ext_managed)
        blocks.append(b)
        step = f"step:{b['step']}"
        a, z = (step, b["id"]) if b["direction"] == "out" else (b["id"], step)
        wires.append({"from": a, "to": z, "live": b["state"] == "ok" and live.get(step, False)})
        if b["switch"]["on"]:
            defaults.append(b["id"])
    doc = clean_canvas_doc(doc)
    return {"blocks": blocks, "wires": wires, "defaults": defaults, "doc": doc,
            "version": hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()[:16],
            "read_only": bool(read_only), "lock_reason": lock_reason, "results": [r for r in results or [] if isinstance(r, dict)],
            "panel": bool(panel)}


# What each step's page says under "How this step works": a few plain sentences, the answer first.
STEP_HELP = {
    "collector": ("Reads every log your machines write, as it is written, and turns each line into an event "
                  "SentrAI can check.",
                  "If a log goes quiet for too long, the Watchdog says so here and on the Review page.",
                  "Which logs it reads is set on the Configuration page; Scout suggests more it finds."),
    "classifier": ("Decides whether each event is an attack: fixed rules first, then the AI for what the rules "
                   "cannot settle, then keywords if the AI is off.",
                   "Something it is 40 to 60 % sure about always goes to a person and is never blocked on its own.",
                   "The rules' numbers (failed logins, export size) are set on the Configuration page."),
    "responder": ("Takes the action: blocks an address, slows it down or locks an account, on its own only where "
                  "Automation guardrails allow it, otherwise after a person approves.",
                  "Every block undoes itself after a while unless a person keeps it, and a second check "
                  "(Countersign) reviews each one before it runs.",
                  "What it may do on its own, and what it never touches, is set on Automation guardrails."),
}


# ------------------------------------------------- Automation guardrails (limits_map.mjs)

LIMIT_FIELDS = ("AUTO_ACTIONS", "NEEDLE_MIN_CONFIDENCE", "RISK_THRESHOLD", "MAX_AUTO_ACTIONS_PER_HOUR",
                "HOTPATCH_TTL_HOURS", "MAX_TTL_HOURS", "PROTECTED_IPS", "PROTECTED_USERS")


def limits_map_data(settings: dict[str, str] | None, read_only: bool = False, lock_reason: str = "",
                    result: dict | None = None) -> dict:
    """What the limits map draws: these settings, the actions it can move between "on its own" and "asks a
    person", whether this person may change them, and how their last save went."""
    settings = {k: str((settings or {}).get(k) or "") for k in LIMIT_FIELDS}
    return {"settings": settings, "actions": [[k, v] for k, v in ACTION_WORDS.items()],
            "version": hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()[:16],
            "read_only": bool(read_only), "lock_reason": lock_reason, "result": result}


def check_limits(sent: Any) -> dict[str, str]:
    """The map's Save checked again here: only these settings, every number in range, the allowed actions
    only ones the core knows. ValueError with a reason a person can act on."""
    sent = sent if isinstance(sent, dict) else {}
    out = {k: str(sent.get(k) or "").strip() for k in LIMIT_FIELDS}
    auto = [a.strip() for a in out["AUTO_ACTIONS"].split(",") if a.strip()]
    if any(a not in ACTION_WORDS for a in auto):
        raise ValueError("an action SentrAI does not know was in the list")
    out["AUTO_ACTIONS"] = ",".join(a for a in ACTION_WORDS if a in auto)

    def number(key: str, kind, lo: float, hi: float | None, what: str) -> None:
        try:
            v = kind(out[key])
        except ValueError:
            raise ValueError(f"{what} must be a {'whole ' if kind is int else ''}number") from None
        if v < lo or (hi is not None and v > hi) or (key.endswith("HOURS") and v <= 0):
            raise ValueError(f"{what} is out of range")
    number("NEEDLE_MIN_CONFIDENCE", float, 0, 1, "How sure it must be")
    number("RISK_THRESHOLD", int, 0, 100, "The danger level")
    number("MAX_AUTO_ACTIONS_PER_HOUR", int, 0, None, "Actions in one hour")
    number("HOTPATCH_TTL_HOURS", float, 0, None, "How long a block lasts")
    number("MAX_TTL_HOURS", float, 0, None, "The longest block")
    if float(out["HOTPATCH_TTL_HOURS"]) > float(out["MAX_TTL_HOURS"]):
        raise ValueError("a block cannot last longer than the longest block allowed")
    for key in ("PROTECTED_IPS", "PROTECTED_USERS"):
        out[key] = ",".join(dict.fromkeys(x.strip() for x in out[key].split(",") if x.strip()))
    bad = [x for x in out["PROTECTED_IPS"].split(",") if x and not protected_address_ok(x)]
    if bad:
        raise ValueError(f"{bad[0]} is not an address, a network or a host name")
    bad = [x for x in out["PROTECTED_USERS"].split(",") if x and re.search(r"\s", x)]
    if bad:
        raise ValueError(f'"{bad[0]}" has a space in it; one account per tag')
    return out


_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def protected_address_ok(text: str) -> bool:
    """One "never touched" entry the core can use: an IPv4 or IPv6 address, a network (10.0.0.0/8) or a host
    name such as localhost. Mirrors addressOk() in limits_map.mjs, which checks the same while you type."""
    text = text.strip()
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except ValueError:
        pass
    return bool(_HOST.match(text)) and not re.fullmatch(r"[\d.]+", text)


def guardrails_changed(meta: dict | None, settings_mtime: float | None, now: datetime | None = None) -> str:
    """The "last changed" chip on Automation guardrails: who saved the guardrails last and when, from the
    small note the page writes on Save; just when, from the settings file, if the note is missing."""
    meta = meta if isinstance(meta, dict) else {}
    at = parse_ts(meta.get("at"))
    if at is None and settings_mtime:
        at = datetime.fromtimestamp(settings_mtime, timezone.utc)
    if at is None:
        return "Never changed"
    who = str(meta.get("by") or "").strip() if parse_ts(meta.get("at")) else ""
    return f"Changed {seen_ago(at, now)}" + (f" by {who}" if who else "")


def approvals_headline(waiting: list[dict], now: datetime | None = None) -> str:
    """The answer first: how many decisions wait, of which kind, and when the first block undoes itself."""
    if not waiting:
        return ""
    decide = sum(1 for i in waiting if available_actions(i)["decide"])
    keep = len(waiting) - decide
    parts = [f"{decide} to approve or reject" if decide else "", f"{keep} block{'s' if keep != 1 else ''} to keep or roll back" if keep else ""]
    text = f"{len(waiting)} waiting on you: " + " and ".join(p for p in parts if p) + "."
    ends = [t for i in waiting for a in i.get("actions") or []
            if isinstance(a, dict) and a.get("status") == "active" and (t := parse_ts(a.get("expires_at")))]
    if ends:
        first = min(ends)
        text += f" The first block undoes itself at {expires_label(first, now)} unless someone keeps it."
    return text


def pending_approvals(incidents: Iterable[dict]) -> list[dict]:
    """Incidents waiting on a person: open ones to approve or reject, contained ones to keep or roll back."""
    waiting = [i for i in incidents or [] if (a := available_actions(i))["decide"] or a["contain_controls"]]
    return sorted(waiting, key=lambda i: (not available_actions(i)["decide"], -incident_contribution(i)))


# Fields that change on every read without anything a person would see change: heartbeats, clocks, and the
# risk history the core appends to every second. fingerprint() leaves them out, so the page only redraws
# when something real moved.
VOLATILE_KEYS = frozenset({"timestamp", "last_seen", "services_at", "history", "demo_hours_elapsed", "now",
                           "uptime", "uptime_s", "checked_at", "generated_at"})


def fingerprint(payload: Any) -> str:
    """A short hash of a core reply, without its volatile fields."""
    def strip(x: Any) -> Any:
        if isinstance(x, dict):
            return {k: strip(v) for k, v in x.items() if k not in VOLATILE_KEYS}
        if isinstance(x, list):
            return [strip(v) for v in x]
        return x
    text = json.dumps(strip(payload), sort_keys=True, default=str)
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]


def changed_reads(seen: dict[str, str], now: dict[str, str]) -> list[str]:
    """Which watched reads differ from what the page last drew. A read seen for the first time is no change."""
    return [w for w, fp in now.items() if w in seen and seen[w] != fp]


APPROVAL_GROUPS = {"Attacker": "attacker", "Machine": "machine", "Type": "type"}


def approval_group(inc: dict, by: str) -> str:
    """The heading an approval sits under when the page groups by attacker, machine or type of attack."""
    if by == "attacker":
        acts = [a for a in inc.get("actions") or [] if isinstance(a, dict) and a.get("target")]
        return str(inc.get("src_ip") or (acts[-1]["target"] if acts else "") or "Unknown source")
    if by == "machine":
        return str(inc.get("host") or "Unknown machine")
    if by == "type":
        return category_label(inc.get("category"))
    return ""


def group_approvals(waiting: list[dict], by: str | None) -> list[tuple[str, list[dict]]]:
    """Waiting incidents in groups, biggest group first; one unnamed group when not grouping."""
    if not by:
        return [("", list(waiting))]
    groups: dict[str, list[dict]] = {}
    for inc in waiting:
        groups.setdefault(approval_group(inc, by), []).append(inc)
    return sorted(groups.items(), key=lambda kv: -len(kv[1]))  # stable: equal sizes keep the page's order


def saved_groups(waiting: list[dict], saved: dict[str, list[str]]) -> tuple[list[tuple[str, list[dict]]], list[dict]]:
    """Split the waiting incidents into the groups a person saved (in the order they were made) and the rest.
    An incident that no longer waits drops out of its group, and a group with none left is not shown."""
    by_id = {str(i.get("id")): i for i in waiting}
    groups, used = [], set()
    for name, ids in saved.items():
        members = [by_id[i] for i in dict.fromkeys(ids) if i in by_id and i not in used]
        used.update(str(m.get("id")) for m in members)
        if members:
            groups.append((name, members))
    return groups, [i for i in waiting if str(i.get("id")) not in used]


def add_to_group(saved: dict[str, list[str]], name: str, ids: list[str], waiting_ids: set[str]) -> dict[str, list[str]]:
    """The saved groups after putting ids into the group called name (made if new). An incident is in one group
    only, so it leaves any other; ids that no longer wait are dropped, and so are groups left empty."""
    out = {g: [i for i in members if i in waiting_ids and i not in ids] for g, members in saved.items()}
    out[name] = list(dict.fromkeys([*out.get(name, []), *ids]))
    return {g: m for g, m in out.items() if m}


def suggest_group_name(picked: list[dict], saved: dict[str, list[str]]) -> str:
    """A starting name for a new group: the attacker or machine they share, else Group N."""
    for by in ("attacker", "machine", "type"):
        names = {approval_group(i, by) for i in picked}
        if len(names) == 1:
            name = names.pop()
            if name not in saved and not name.startswith("Unknown"):
                return name
    n = len(saved) + 1
    while f"Group {n}" in saved:
        n += 1
    return f"Group {n}"


def bulk_split(picked: list[dict]) -> dict[str, list[dict]]:
    """Which of the picked incidents each bulk button acts on: open ones are decided, contained ones kept or undone."""
    split: dict[str, list[dict]] = {"decide": [], "contain": []}
    for inc in picked:
        can = available_actions(inc)
        if can["decide"]:
            split["decide"].append(inc)
        elif can["contain_controls"]:
            split["contain"].append(inc)
    return split


def bulk_result(verb: str, done: list[str], failed: list[tuple[str, str]]) -> str:
    """One line for the toast after a bulk action: how many went through, and which did not."""
    n = len(done) + len(failed)
    text = f"{verb} {len(done)} of {n} incident{'s' if n != 1 else ''}"
    if failed:
        text += ". Not done: " + "; ".join(f"{i} ({why})" for i, why in failed)
    return text


# ---------------------------------------------------------------- the administrators (core admins.py)

TRUST_WORDS = {"trusted": "Known administrator", "unknown": "Not known as an administrator", "suspect": "Suspect"}
VIA_WORDS = {"ssh": "SSH", "windows": "Windows", "console": "console", "who": "terminal", "logind": "terminal"}
ADMIN_KINDS = {"address": "Address or network", "key": "SSH key fingerprint", "account": "Account"}
SESSION_COLUMNS = ["User", "How", "From", "Trust", "Since", "Root commands", "Why"]  # the long words last
ACTIVITY_COLUMNS = ["When", "Who", "How", "What", "Would have been", "Why"]


def short_key(fingerprint: Any) -> str:
    """A key fingerprint cut for a sentence: 'SHA256:Q7w3cZk2u5Yd9bJm1Lx…'."""
    text = str(fingerprint or "")
    return text if len(text) <= 20 else text[:19] + "…"


def signin_how(via: Any, method: Any = None, key: Any = None, address: Any = None) -> str:
    """How someone got in, in a few words: SSH key, SSH password, console, remote desktop."""
    via, method = str(via or ""), str(method or "")
    if via == "ssh":
        if key or method == "publickey":
            return "SSH key"
        return "SSH password" if method in ("", "password", "keyboard-interactive") else f"SSH ({method})"
    if via == "windows":
        return "remote desktop" if method == "remote_desktop" else "Windows sign-in"
    if via in ("console", "who", "logind"):
        return "terminal session" if address else "console"
    return "no sign-in seen"


def trust_words(trust: Any) -> str:
    return TRUST_WORDS.get(str(trust or ""), "Unknown")


def actor_facts(actor: dict | None) -> list[tuple[str, str]]:
    """The person behind an incident, for the card's grid: who, how they got in, from where, since when."""
    if not isinstance(actor, dict) or not actor:
        return []
    key = actor.get("key")
    how = signin_how(actor.get("via"), None, key, actor.get("address"))
    if key:
        how += f" {short_key(key)}"
    where = str(actor.get("address") or ("the machine itself" if how == "console" else "no address seen"))
    return [("Who", f"{actor.get('user') or '?'} on {actor.get('host') or '?'}"), ("How", how), ("From", where),
            ("Since", day_time(actor.get("since")) if actor.get("since") else "-")]


def actor_sentence(actor: dict | None) -> str:
    """Why SentrAI did or did not know this sign-in, as one plain sentence."""
    if not isinstance(actor, dict) or not actor:
        return ""
    head = {"trusted": "SentrAI knew this sign-in", "suspect": "SentrAI distrusts this sign-in"}.get(
        str(actor.get("trust") or ""), "SentrAI did not know this sign-in as an administrator's")
    why = str(actor.get("why") or "").strip().rstrip(".")
    return f"{head}: {why}." if why else f"{head}."


def learned_text(inc_id: str, out: dict | None) -> str:
    """After "This was me": that the alert closed, and what SentrAI learned, in one plain line."""
    out = out if isinstance(out, dict) else {}
    learned = [str(x) for x in out.get("learned") or []]
    text = f"{inc_id} closed: this was you. " + (
        f"SentrAI now knows {', '.join(learned)} as an administrator's." if learned
        else "SentrAI already knew this sign-in; there was nothing new to learn.")
    also = [str(x) for x in out.get("also_closed") or []]
    return text + (f" Also closed, the same person's: {', '.join(also)}." if also else "")


def session_rows(sessions: Iterable[dict] | None) -> pd.DataFrame:
    """Who is signed in on a machine now: how they got in, from where, and whether SentrAI knows them."""
    rows = []
    for s in sessions or []:
        if not isinstance(s, dict):
            continue
        how = signin_how(s.get("via"), s.get("method"), s.get("key"), s.get("address"))
        if s.get("key"):
            how += f" {short_key(s['key'])}"
        since = day_time(s.get("since")) if s.get("since") else "-"
        if s.get("preexisting"):
            since += " (before SentrAI started watching)"
        rows.append({"User": s.get("user") or "-", "How": how, "From": s.get("address") or s.get("tty") or "-",
                     "Trust": trust_words(s.get("trust")), "Since": since, "Root commands": int(s.get("actions") or 0),
                     "Why": s.get("why") or "-"})
    return pd.DataFrame(rows, columns=SESSION_COLUMNS)


def admin_activity_rows(activity: Iterable[dict] | None) -> pd.DataFrame:
    """Root work by known administrators, newest first, and what the rules would have called it from a stranger."""
    rows = []
    for a in activity or []:
        if not isinstance(a, dict):
            continue
        how = VIA_WORDS.get(str(a.get("via") or ""), str(a.get("via") or "-"))
        rows.append({"When": day_time(a.get("at")), "Who": a.get("user") or "-",
                     "How": how + (f" from {a['address']}" if a.get("address") else ""),
                     "What": a.get("what") or "-",
                     "Would have been": category_label(a.get("flagged_as")) if a.get("flagged_as") else "-",
                     "Why": a.get("reason") or "-"})
    return pd.DataFrame(rows, columns=ACTIVITY_COLUMNS)


def how_known(entry: dict) -> str:
    """'from the settings (ADMIN_IPS)', 'taught by Erick on 28 Oct 10:21', 'learned from key SHA256:… on 28 Oct 10:21'."""
    how, by, at = str(entry.get("how") or ""), str(entry.get("by") or ""), entry.get("at")
    when = f" on {day_time(at)}" if at else ""
    if how == "setting":
        return f"from the settings ({by})" if by else "from the settings"
    if how == "taught":
        return f"taught by {by}{when}" if by else f"taught{when}"
    if how == "learned":
        return f"learned from {by if by and by != 'a trusted sign-in' else 'a trusted sign-in'}{when}"
    return f"{how or 'known'}{when}"


def _last_seen(entry: dict) -> str:
    return f" · last seen {day_time(entry['last_seen'])}" if entry.get("last_seen") else ""


def admin_entries(data: dict | None, host: str | None = None) -> list[dict]:
    """The known administrators as rows for the Admins tab: kind, value, headline, detail, and whether Forget
    applies (never to a setting). Accounts for this machine and for every machine (host "*"); addresses and keys
    count everywhere; a dashboard sign-in that vouches for an address is listed with the addresses."""
    data = data if isinstance(data, dict) else {}
    out = []
    for a in data.get("accounts") or []:
        if not isinstance(a, dict) or not a.get("account") or (host and a.get("host") not in (None, "*", host)):
            continue
        where = "every machine" if a.get("host") in (None, "*") else str(a["host"])
        out.append({"kind": "account", "value": str(a["account"]), "host": str(a.get("host") or "*"),
                    "headline": f"{a['account']} on {where}", "detail": how_known(a) + _last_seen(a),
                    "forget": a.get("how") != "setting"})
    for x in data.get("addresses") or []:
        if not isinstance(x, dict) or not x.get("address"):
            continue
        out.append({"kind": "address", "value": str(x["address"]), "host": None,
                    "headline": str(x["address"]) + (f" · {x['label']}" if x.get("label") else ""),
                    "detail": how_known(x) + _last_seen(x), "forget": x.get("how") != "setting"})
    for s in data.get("sign_ins") or []:
        if not isinstance(s, dict) or not s.get("address"):
            continue
        out.append({"kind": "address", "value": str(s["address"]), "host": None, "headline": str(s["address"]),
                    "detail": f"vouched for by the dashboard sign-in of {s.get('email') or 'an administrator'} "
                              f"({s.get('role') or 'Owner'}) until {day_time(s.get('until'))}", "forget": True})
    for k in data.get("keys") or []:
        if not isinstance(k, dict) or not k.get("fingerprint"):
            continue
        users = ", ".join(str(u) for u in k.get("users") or [] if u)
        parts = [str(k["type"]) if k.get("type") else "", f"used by {users}" if users else "", how_known(k)]
        out.append({"kind": "key", "value": str(k["fingerprint"]), "host": None,
                    "headline": str(k["fingerprint"]) + (f" · {k['label']}" if k.get("label") else ""),
                    "detail": " · ".join(p for p in parts if p) + _last_seen(k), "forget": k.get("how") != "setting"})
    return out


# ---------------------------------------------------------------- updates

def _key_values(path) -> dict[str, str]:
    try:
        with open(path, encoding="utf-8") as f:
            return dict(line.rstrip("\r\n").split("=", 1) for line in f if "=" in line)
    except OSError:
        return {}


def update_status(version_file, check_file) -> dict[str, Any]:
    """What the sidebar says about this install's version.

    version_file is mvp/VERSION (written by the installers); check_file is the update-check.json the
    daily `sentrai-update --check` writes. An update counts as available only while the check was made
    against the code installed now, so the notice goes away as soon as the update is installed."""
    installed = _key_values(version_file).get("commit", "")
    try:
        with open(check_file, encoding="utf-8") as f:
            check = json.load(f)
    except (OSError, ValueError):
        check = {}
    if not isinstance(check, dict):
        check = {}
    latest = str(check.get("latest") or "")
    known = installed not in ("", "unknown", "local")
    available = bool(known and check.get("available") and latest and latest != installed
                     and check.get("installed") == installed)
    return {
        "version": installed[:7] if known else "",
        "available": available,
        "latest": latest[:7],
        "ref": str(check.get("ref") or ""),
        "checked": str(check.get("checked") or ""),
    }
