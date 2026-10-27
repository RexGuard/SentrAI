"""Pure data-shaping helpers for the SentrAI dashboard.

Everything here is free of Streamlit so it can be unit tested.
"""
from __future__ import annotations

import html
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
    "prompt_injection": "Prompt injection",
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


def ai_classifier_state(status: Any) -> tuple[str, str]:
    """The AI classifier's tile: ("On" | "Off" | "Unknown", why). Never claims "On" when the core said nothing."""
    text = str(status or "").strip()
    if text.startswith("enabled"):
        return "On", "asked when the rules are unsure"
    if text.startswith("disabled"):
        why = text.split(":", 1)[1].split("(")[0].strip() if ":" in text else ""
        return "Off", why or "keyword fallback in use"
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


def available_actions(inc: dict) -> dict[str, bool]:
    """Which operator buttons are meaningful for this incident."""
    status = str(inc.get("status") or "")
    actions = inc.get("actions") or []
    has_active = any(a.get("status") == "active" for a in actions if isinstance(a, dict))
    return {
        "decide": status in ACTIVE_STATUSES,
        "ack": status == "open" and not inc.get("acked"),
        "contain_controls": status == "contained" or has_active,
    }


CHAT_DECISION_NEEDS = {"approve": "decide", "reject": "decide", "ack": "ack",
                       "rollback": "contain_controls", "make_permanent": "contain_controls"}


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
RECORD_TYPE_LABELS = {"needle_review": "countersign review"}


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


def summarize_record(record: dict) -> str:
    data = record.get("data") if isinstance(record.get("data"), dict) else {}
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
                     "services": [x for x in m.get("services") or [] if isinstance(x, dict)]})
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
    """Incidents, blocks and last call-in for a machine on a central panel: what a game panel's server
    row shows as CPU, memory and disk. Hidden when the list is narrow (console.css)."""
    if "open" not in m:
        return ""
    found = [f"{m['open']} open" if m.get("open") else "", f"{m['contained']} contained" if m.get("contained") else ""]
    cells = [("Incidents", " · ".join(x for x in found if x) or "None", bool(m.get("open"))),
             ("Blocks", f"{m['blocked']} in force" if m.get("blocked") else "None", False),
             ("Last seen", seen_ago(m.get("last_seen"), now), False)]
    return '<span class="m-stats">' + "".join(
        f'<span class="m-stat"><span class="m-stat-label">{label}</span>'
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
    if inc.get("needs_review"):
        why.append("AI unsure, needs review")
    can = available_actions(inc)
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


def board_rows(incidents: Iterable[dict], include_closed: bool = False) -> pd.DataFrame:
    """One row per incident: who has it, how long it has been open, and what it still needs."""
    rows = []
    for inc in incidents or []:
        closed = inc.get("status") not in OPEN_STATUSES
        if closed and not include_closed:
            continue
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
    rows = [{"Contact": c.get("name"), "Role": str(c.get("role") or "-").replace("_", " "),
             "Email": c.get("email") or "-", "Telegram": c.get("telegram") or "-",
             # Linked: alerts go to the person's own chat; otherwise they are mentioned in the team group.
             "Alerts in Telegram": "Own chat" if c.get("telegram_linked") else "Team group",
             "Backup": names.get(c.get("backup"), "-") if c.get("backup") else "-"} for c in contacts]
    return pd.DataFrame(rows, columns=["Contact", "Role", "Email", "Telegram", "Alerts in Telegram", "Backup"])


# ------------------------------------------------- "Who gets what" map and editing

SEVERITY_CHOICES = ["low", "medium", "high", "critical"]
ROLE_CHOICES = ["", "on_duty", "team_lead", "it_manager", "cxo"]


def rule_when(match: dict | None) -> str:
    """A rule's match in plain words: "Malware found or Log tampering; critical"."""
    parts = []
    for key, values in (match or {}).items():
        if key == "category":
            parts.append(" or ".join(category_label(v) for v in values))
        elif key == "host":
            parts.append("machine " + " or ".join(values))
        elif key == "layer":
            parts.append("layer " + " or ".join(values))
        else:
            parts.append(" or ".join(values))
    return "; ".join(parts) or "anything else"


def routing_doc(routing: dict | None) -> dict:
    """GET /routing turned into the file shape POST /routing takes, to edit and send back."""
    routing = routing or {}
    contacts = {str(c.get("id")): {k: str(c.get(k) or "") for k in ("name", "role", "email", "telegram", "backup")}
                for c in routing.get("contacts") or [] if c.get("id")}
    rules = [{"name": str(r.get("name") or ""), "match": {k: list(v) for k, v in (r.get("match") or {}).items()},
              "owner": str(r.get("owner") or ""), "notify": list(r.get("notify") or [])}
             for r in routing.get("rules") or []]
    return {"contacts": contacts, "rules": rules, "follow_up": dict(routing.get("follow_up") or {})}


def new_contact_id(doc: dict, name: str) -> str:
    """A short id from the name (lee, lee-2, ...) that no one in the routing has yet."""
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:30] or "person"
    cid, n = base, 1
    while cid in doc["contacts"]:
        n += 1
        cid = f"{base}-{n}"
    return cid


def remove_contact(doc: dict, cid: str) -> list[str]:
    """Take someone out of the routing. Whoever they backed up gets their backup instead, and they
    drop off every "also told" list. Refuses (ValueError) while they own a rule. Returns what changed."""
    gone = doc["contacts"].get(cid)
    if gone is None:
        raise ValueError("that person is not in the routing")
    if len(doc["contacts"]) == 1:
        raise ValueError("keep at least one person")
    owns = [r["name"] for r in doc["rules"] if r.get("owner") == cid]
    if owns:
        raise ValueError(f"{gone['name']} owns {', '.join(owns)}. Give "
                         f"{'that rule' if len(owns) == 1 else 'those rules'} to someone else first.")
    del doc["contacts"][cid]
    notes = []
    nxt = gone.get("backup") if gone.get("backup") in doc["contacts"] else ""
    for other, c in doc["contacts"].items():
        if c.get("backup") == cid:
            c["backup"] = nxt if nxt != other else ""
            notes.append(f"{c['name']}'s backup is now {doc['contacts'][c['backup']]['name'] if c['backup'] else 'nobody'}")
    for r in doc["rules"]:
        if cid in (r.get("notify") or []):
            r["notify"] = [x for x in r["notify"] if x != cid]
            notes.append(f"{r['name']} no longer tells {gone['name']}")
    return notes


def _dot(text: Any) -> str:
    return str(text).replace("\\", "\\\\").replace('"', '\\"')


def _wrap(text: str, width: int = 26) -> str:
    """Break a long label into lines at commas and spaces (DOT has no automatic wrapping)."""
    out, line = [], ""
    for word in text.split(" "):
        if line and len(line) + len(word) + 1 > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    out.append(line)
    return "\\n".join(_dot(x) for x in out)


def routing_dot(routing: dict | None, colors: dict[str, str] | None = None) -> str:
    """The routing as a left-to-right mind map in Graphviz DOT: incident -> rules -> owner / told -> backup."""
    c = {"ink": "#f5f5f5", "ink-muted": "#8c8c8c", "surface": "#141414", "surface-3": "#262626",
         "line": "#2e2e2e", "brand": "#f5f5f5", "amber": "#e8b34a"} | (colors or {})
    font = "IBM Plex Sans, Segoe UI, Arial, sans-serif"
    routing = routing or {}
    contacts = {str(x.get("id")): x for x in routing.get("contacts") or []}
    out = ["digraph routing {",
           f'  graph [rankdir=LR, bgcolor="transparent", nodesep=0.3, ranksep=0.9, fontname="{font}"];',
           f'  node [fontname="{font}", fontsize=15, fontcolor="{c["ink"]}", color="{c["line"]}", '
           f'style="rounded,filled", fillcolor="{c["surface"]}", shape=box, margin="0.14,0.07"];',
           f'  edge [fontname="{font}", fontsize=11, fontcolor="{c["ink-muted"]}", arrowsize=0.6];',
           f'  incident [label="New incident", shape=ellipse, style=filled, fillcolor="{c["brand"]}", '
           f'fontcolor="{c["surface"]}", color="{c["brand"]}", fontsize=14, ordering=out];']
    for n, r in enumerate(routing.get("rules") or [], 1):
        rid = f"rule{n}"
        when = rule_when(r.get("match"))
        label = f"{n}. {_dot(r.get('name') or '')}" + \
            ("" if when.lower() == str(r.get("name") or "").lower() or not r.get("match") else f"\\n{_wrap(when)}")
        out.append(f'  {rid} [label="{label}", fillcolor="{c["surface-3"]}"];')
        out.append(f'  incident -> {rid} [color="{c["line"]}", arrowhead=none];')
        if r.get("owner") in contacts:
            out.append(f'  {rid} -> "p_{_dot(r["owner"])}" [label="owns", color="{c["brand"]}", penwidth=2];')
        for x in r.get("notify") or []:
            if x in contacts:
                out.append(f'  {rid} -> "p_{_dot(x)}" [color="{c["ink-muted"]}", style=dashed];')
    used = {r.get("owner") for r in routing.get("rules") or []} | \
        {x for r in routing.get("rules") or [] for x in r.get("notify") or []} | \
        {p.get("backup") for p in contacts.values()}
    for cid, p in contacts.items():
        role = str(p.get("role") or "").replace("_", " ")
        bits = [role if role.lower() != str(p.get("name") or "").lower() else ""]
        if cid not in used and not p.get("backup"):
            bits.append("in no rule yet")
        if p.get("telegram_linked"):
            bits.append("own Telegram chat")
        sub = " · ".join(b for b in bits if b)
        label = _dot(p.get("name") or cid) + (f"\\n{_dot(sub)}" if sub else "")
        loose = ', style="rounded,dashed"' if "in no rule yet" in bits else ""
        out.append(f'  "p_{_dot(cid)}" [label="{label}"{loose}];')
        b = p.get("backup")
        if b and b in contacts and b != cid:
            out.append(f'  "p_{_dot(cid)}" -> "p_{_dot(b)}" [label="backup", color="{c["amber"]}", '
                       f'fontcolor="{c["amber"]}", style=dotted, penwidth=1.5];')
    out.append("}")
    return "\n".join(out)


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
