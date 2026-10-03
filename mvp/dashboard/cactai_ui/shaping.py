"""Pure data-shaping helpers for the SentrAI dashboard.

Everything here is free of Streamlit so it can be unit tested.
"""
from __future__ import annotations

import re
from datetime import datetime
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
FONT = "system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif"
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
}

STATUS_ICONS = {
    "open": "🔴 open",
    "acknowledged": "🟡 acknowledged",
    "contained": "🛡️ contained",
    "resolved": "✅ resolved",
    "rejected": "⛔ rejected",
}

CLASSIFIER_LABELS = {"rules": "Rules", "jev": "Jev (AI)", "fallback": "Fallback"}


def category_label(category: str | None) -> str:
    if not category:
        return "Unknown"
    return CATEGORY_LABELS.get(category, category.replace("_", " ").capitalize())


def status_label(status: str | None) -> str:
    return STATUS_ICONS.get(str(status or ""), str(status or "unknown"))


def parse_ts(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value))
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def short_time(value: Any) -> str:
    ts = parse_ts(value)
    return ts.strftime("%H:%M:%S") if ts else (str(value) if value else "-")


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


def action_rows(inc: dict) -> pd.DataFrame:
    rows = [
        {
            "Action": a.get("action_id", "-"),
            "Type": str(a.get("type", "-")).replace("_", " "),
            "Target": a.get("target", "-"),
            "Mode": a.get("mode", "-"),
            "Approved by": agent_label(a.get("approved_by", "-")),
            "Status": a.get("status", "-"),
            "Expires": short_time(a.get("expires_at")),
            "Snapshot": short_hash(a.get("snapshot_hash")),
        }
        for a in (inc.get("actions") or [])
        if isinstance(a, dict)
    ]
    return pd.DataFrame(
        rows, columns=["Action", "Type", "Target", "Mode", "Approved by", "Status", "Expires", "Snapshot"]
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
                    "Action": str(a.get("type", "block_ip" if kind == "IP" else "lock_user")).replace("_", " "),
                    "Incident": a.get("incident", "-"),
                    "Mode": a.get("mode", "-"),
                    "Approved by": agent_label(a.get("approved_by", "-")),
                    "Expires": "permanent" if a.get("status") == "permanent" else short_time(a.get("expires_at")),
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
                "Action": str(a.get("type", "-")).replace("_", " "),
                "Incident": a.get("incident", "-"),
                "Mode": a.get("mode", "-"),
                "Approved by": agent_label(a.get("approved_by", "-")),
                "Expires": short_time(a.get("expires_at")),
            }
        )
    return pd.DataFrame(rows, columns=["Kind", "Target", "Action", "Incident", "Mode", "Approved by", "Expires"])


# ---------------------------------------------------------------- audit / agents

AGENTS = {
    "Warden": ("🛡️", "#6fcf97"),
    "Cyanide": ("🧪", "#6fcf97"),
    "Planner": ("✳️", "#d97757"),
    "Countersign": ("🔑", "#e0a526"),
    "Scribe": ("📜", "#8fa7ff"),
    "Gatehouse": ("🌐", "#4fb3d9"),
    "Watchtower": ("📡", "#b88cf0"),
    "Vault": ("🗄️", "#5bc0be"),
    "Garrison-Linux": ("🐧", "#e88a5a"),
    "Garrison-Win": ("🪟", "#e88a5a"),
    "Watchdog": ("🐕", "#a0a39b"),
    "Help Desk": ("💬", "#d98bb5"),
    "Jev": ("🧠", "#c79bf2"),
    "Operator": ("👤", "#e7edf6"),
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
        icon, color = AGENTS.get(base, ("🤖", TEXT_SECONDARY))
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


def verify_chain_links(records: list[dict]) -> bool:
    """Client-side sanity check: each prev_hash equals the previous record's hash."""
    ordered = sorted(records, key=lambda r: r.get("seq") or 0)
    for prev, cur in zip(ordered, ordered[1:]):
        if cur.get("prev_hash") != prev.get("hash"):
            return False
    return True


# ---------------------------------------------------------------- charts

def gauge_figure(risk_index: float | None, threshold: float = 80, band: str | None = None) -> go.Figure:
    value = 0 if risk_index is None else max(0, min(100, float(risk_index)))
    band = band or band_for(value)
    color = band_color(band)
    steps = [
        {"range": [lo, hi + (1 if hi < 100 else 0)], "color": _fade(BAND_COLORS[name], 0.16)}
        for name, lo, hi in BANDS
    ]
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=value,
            number={"font": {"size": 72, "color": color}, "valueformat": ".0f"},
            gauge={
                "shape": "angular",
                "axis": {
                    "range": [0, 100],
                    "tickvals": [0, 30, 60, 80, 100],
                    "tickcolor": TEXT_MUTED,
                    "tickfont": {"color": TEXT_SECONDARY, "size": 12},
                },
                "bar": {"color": color, "thickness": 0.32},
                "bgcolor": "rgba(0,0,0,0)",
                "borderwidth": 0,
                "steps": steps,
                "threshold": {
                    "line": {"color": TEXT_PRIMARY, "width": 4},
                    "thickness": 0.9,
                    "value": float(threshold),
                },
            },
            domain={"x": [0, 1], "y": [0, 1]},
        )
    )
    fig.update_layout(
        height=290,
        margin={"l": 28, "r": 28, "t": 18, "b": 0},
        paper_bgcolor="rgba(0,0,0,0)",
        font={"color": TEXT_PRIMARY, "family": FONT},
    )
    return fig


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
        annotation_font={"color": TEXT_SECONDARY, "size": 11},
    )
    fig.update_layout(
        height=290,
        margin={"l": 8, "r": 8, "t": 10, "b": 8},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=False,
        hovermode="x unified",
        font={"color": TEXT_SECONDARY, "family": FONT, "size": 11},
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

    A demo reset restarts the chain, so a remembered seq beyond the head counts as 0.
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
            "Criticality": inc.get("asset_criticality"),
            "Points": round(float(inc.get("points") or 0), 1),
            "Inaction penalty": round(float(inc.get("inaction_penalty") or 0), 1),
            "Unaddressed (demo h)": round(float(inc.get("time_unaddressed_hours") or 0), 1),
            "Counts now": incident_contribution(inc) if inc.get("status") in ACTIVE_STATUSES else 0.0,
        }
        for inc in incidents or []
    ]
    df = pd.DataFrame(rows, columns=["Incident", "Category", "Status", "Base", "Confidence", "Criticality",
                                     "Points", "Inaction penalty", "Unaddressed (demo h)", "Counts now"])
    return df.sort_values("Counts now", ascending=False).reset_index(drop=True) if not df.empty else df


def all_action_rows(incidents: Iterable[dict]) -> pd.DataFrame:
    frames = [action_rows(inc).assign(Incident=inc.get("id", "?")) for inc in incidents or []]
    frames = [f for f in frames if not f.empty]
    if not frames:
        return pd.DataFrame(columns=["Incident", *action_rows({}).columns])
    df = pd.concat(frames, ignore_index=True)
    return df[["Incident", *[c for c in df.columns if c != "Incident"]]]


def pending_approvals(incidents: Iterable[dict]) -> list[dict]:
    """Incidents waiting on a person: open ones to approve or reject, contained ones to keep or roll back."""
    waiting = [i for i in incidents or [] if (a := available_actions(i))["decide"] or a["contain_controls"]]
    return sorted(waiting, key=lambda i: (not available_actions(i)["decide"], -incident_contribution(i)))
