"""The overview canvas's model: what every block shows, its settings, the wires and the saved layout.

GENERATED from dashboard/sentrai_ui/shaping.py (the Streamlit console's functions, unchanged) by taking the
functions and constants the canvas needs, so the core can serve the canvas without pandas or plotly. When
shaping.py changes one of them, regenerate this file the same way.
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


UNKNOWN_COLOR = "#8b96a8"


def band_for(index: float | int | None) -> str:
    """Map a 0-100 risk index to its band name."""
    if index is None:
        return "unknown"
    value = max(0, min(100, round(float(index))))
    for name, lo, hi in BANDS:
        if lo <= value <= hi:
            return name
    return "critical"


def resolve_band(risk: dict) -> str:
    """Prefer the band the core reports; fall back to computing it."""
    band = str(risk.get("band") or "").lower()
    return band if band in BAND_COLORS else band_for(risk.get("risk_index"))


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


def day_time(value: Any) -> str:
    """"27 Oct 15:04", for a change that may be days old."""
    ts = parse_ts(value)
    return f"{ts.day} {ts.strftime('%b %H:%M')}" if ts else (str(value) if value else "-")


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


ACTIVE_STATUSES = ("open", "acknowledged")


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


def bytes_label(n: Any) -> str:
    """1536 -> '1.5 KB', 8 GiB -> '8.0 GB' (powers of 1024, the way an OS shows memory and disks)."""
    if not isinstance(n, (int, float)) or n < 0:
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return "-"


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


def records_of(records: list[dict], *types: str) -> list[dict]:
    """Records of the given types, newest first."""
    return sorted((r for r in records if r.get("type") in types), key=lambda r: -int(r.get("seq") or 0))


OPEN_STATUSES = ("open", "acknowledged", "contained")  # not closed yet: somebody still owns them


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


def pending_approvals(incidents: Iterable[dict]) -> list[dict]:
    """Incidents waiting on a person: open ones to approve or reject, contained ones to keep or roll back."""
    waiting = [i for i in incidents or [] if (a := available_actions(i))["decide"] or a["contain_controls"]]
    return sorted(waiting, key=lambda i: (not available_actions(i)["decide"], -incident_contribution(i)))

