"""Pure formatting helpers for SentrAI operator alerts (Telegram HTML + console)."""
from __future__ import annotations

import html
from typing import Any

CATEGORY_LABELS = {
    "benign": "Benign activity",
    "brute_force": "Brute force",
    "sql_injection": "SQL injection",
    "xss": "Cross-site scripting",
    "port_scan": "Port or web scan",
    "privilege_escalation": "Privilege escalation",
    "data_exfiltration": "Data exfiltration",
    "misconfiguration": "Misconfiguration",
    "log_tampering": "Log tampering",
}

KIND_HEADERS = {
    "incident_opened": ("⚠️", "New incident"),
    "reminder": ("⏰", "Reminder: still unacknowledged"),
    "sla_breach": ("⏰", "SLA breached"),
    "escalation": ("📣", "Escalation"),
    "autonomous_action": ("🛡️", "Autonomous containment applied"),
    "containment": ("🛡️", "Containment applied"),
    "report": ("📄", "Evidence report ready"),
}

# Callback data: "<verb>:<incident_id>" (Telegram limits callback_data to 64 bytes).
APPROVE = "approve"
REJECT = "reject"
ROLLBACK = "rollback"
PERMANENT = "permanent"


def band_for(index: Any) -> str:
    try:
        v = float(index)
    except (TypeError, ValueError):
        return "unknown"
    return "green" if v < 30 else "amber" if v < 60 else "red" if v < 80 else "critical"


BAND_EMOJI = {"green": "🟢", "amber": "🟠", "red": "🔴", "critical": "🚨", "unknown": "⚪"}

# SentrAI brand kit (assets/brand/tokens.json): navy-950, light brand (buttons) and steel-300 (the "AI" on navy).
BRAND = "SentrAI"
TAGLINE = "A sentry doesn't chase you. It just guards the gate."
BRAND_NAVY, BRAND_BLUE, BRAND_BLUE_SOFT = "#0b111d", "#1f4fb8", "#7fb2ff"
# Green, amber and red mean risk and nothing else (light-theme safe/warn/danger; critical is a deeper red).
BAND_COLORS = {"green": "#1a7447", "amber": "#8f5d00", "red": "#c0282e", "critical": "#8a1c22", "unknown": "#626f86"}


def risk_meter(index: Any, cells: int = 10, full: str = "▰", empty: str = "▱") -> str:
    """'▰▰▰▰▱▱▱▱▱▱' for 44/100; empty string when the risk is unknown."""
    try:
        v = max(0.0, min(100.0, float(index)))
    except (TypeError, ValueError):
        return ""
    n = int(round(v * cells / 100))
    return full * n + empty * (cells - n)


def incident_id_of(notification: dict) -> str | None:
    return notification.get("incident_id") or notification.get("incident") or (
        (notification.get("data") or {}).get("incident_id") if isinstance(notification.get("data"), dict) else None
    )


def notification_kind(notification: dict) -> str:
    return str(notification.get("kind") or notification.get("type") or "incident_opened")


def _merged(notification: dict, incident: dict | None) -> dict:
    """Notification fields win; incident fills gaps."""
    merged = dict(incident or {})
    merged.update({k: v for k, v in notification.items() if v not in (None, "")})
    return merged


def alert_fields(notification: dict, incident: dict | None = None, risk: dict | None = None) -> dict:
    m = _merged(notification, incident)
    kind = notification_kind(notification)
    icon, header = KIND_HEADERS.get(kind, ("⚠️", kind.replace("_", " ").capitalize()))
    risk_index = notification.get("risk_index")
    if risk_index is None and risk:
        risk_index = risk.get("risk_index")
    category = (incident or {}).get("category") or m.get("category")
    host = m.get("host") or "-"
    title = f"{CATEGORY_LABELS.get(str(category), str(category or 'Incident').replace('_', ' ').capitalize())} ({host})"
    conf = (incident or {}).get("ai_confidence")
    return {
        "icon": icon,
        "header": header,
        "kind": kind,
        "incident_id": incident_id_of(notification) or m.get("id") or "?",
        "title": title,
        "risk_index": risk_index,
        "band": band_for(risk_index),
        "severity": str(m.get("severity") or "-").upper(),
        "confidence": f"{float(conf):.2f}" if isinstance(conf, (int, float)) else "-",
        "classified_by": (incident or {}).get("classified_by") or "-",
        "src_ip": m.get("src_ip") or "-",
        "user": m.get("user") or "-",
        "text": notification.get("text") or notification.get("message") or "",
        "recommended": m.get("recommended_action") or "-",
        "penalty": (incident or {}).get("inaction_penalty"),
        "sla_breached": bool((incident or {}).get("sla_breached")),
        "status": (incident or {}).get("status") or "open",
    }


def format_telegram(notification: dict, incident: dict | None = None, risk: dict | None = None) -> str:
    """Telegram message body in HTML parse mode."""
    f = alert_fields(notification, incident, risk)
    e = html.escape
    risk_txt = f"{f['risk_index']}/100" if f["risk_index"] is not None else "-"
    meter = risk_meter(f["risk_index"])
    lines = [
        f"{f['icon']} <b>{e(f['header'])}</b>  ·  <i>🛡️ {BRAND}</i>",
        f"<b>{e(str(f['incident_id']))}</b> · {e(f['title'])}",
        f"Risk <b>{e(risk_txt)}</b> {BAND_EMOJI[f['band']]}" + (f" <code>{meter}</code>" if meter else ""),
    ]
    if f["text"]:
        lines.append(e(f["text"]))
    lines += [
        "",
        f"Severity: <b>{e(f['severity'])}</b> · AI confidence: {e(f['confidence'])} ({e(str(f['classified_by']))})",
        f"Source: <code>{e(str(f['src_ip']))}</code> · User: <code>{e(str(f['user']))}</code>",
    ]
    if f["penalty"]:
        lines.append(f"Inaction penalty: +{e(str(f['penalty']))} pts" + (" · <b>SLA BREACHED</b>" if f["sla_breached"] else ""))
    lines += ["", f"<b>Recommended:</b> {e(str(f['recommended']))}"]
    if notification.get("report_url"):  # signed by the core, so it opens without the API token
        lines.append(f'<a href="{e(notification["report_url"], quote=True)}">Open the report</a>')
    if f["kind"] in ("autonomous_action", "containment"):
        lines.append("<i>Temporary, reversible fix with TTL. Choose Rollback or Make Permanent.</i>")
    else:
        lines.append("<i>Your button press is recorded as an acknowledgement in the hash-chained audit log.</i>")
    return "\n".join(lines)


def button_specs(notification: dict, incident: dict | None = None) -> list[tuple[str, str]]:
    """[(label, callback_data)] for the inline keyboard."""
    iid = str(incident_id_of(notification) or (incident or {}).get("id") or "")
    if not iid:
        return []
    status = str((incident or {}).get("status") or "")
    kind = notification_kind(notification)
    if status == "contained" or kind in ("autonomous_action", "containment"):
        return [("↩️ Rollback", f"{ROLLBACK}:{iid}"), ("📌 Make Permanent", f"{PERMANENT}:{iid}")]
    if status in ("resolved", "rejected"):
        return []
    return [("✅ Approve & Patch", f"{APPROVE}:{iid}"), ("⛔ Reject with Justification", f"{REJECT}:{iid}")]


def parse_callback(data: str) -> tuple[str, str] | None:
    verb, sep, iid = (data or "").partition(":")
    if not sep or not iid or verb not in (APPROVE, REJECT, ROLLBACK, PERMANENT):
        return None
    return verb, iid


# ------------------------------------------------------------------ console

_ANSI = {"green": "\033[92m", "amber": "\033[93m", "red": "\033[91m", "critical": "\033[1;97;41m",
         "unknown": "\033[37m", "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m"}


def format_console(notification: dict, incident: dict | None = None, risk: dict | None = None,
                   color: bool = True, width: int = 72) -> str:
    """Boxed plain-text alert for CONSOLE mode."""
    f = alert_fields(notification, incident, risk)
    c = _ANSI if color else {k: "" for k in _ANSI}
    risk_txt = f"{f['risk_index']}/100 {f['band'].upper()}" if f["risk_index"] is not None else "-"
    if f["risk_index"] is not None:
        risk_txt += " " + risk_meter(f["risk_index"], full="■", empty="·")
    body = [
        f"{f['incident_id']} · {f['title']}",
        f"Risk {risk_txt} · severity {f['severity']} · confidence {f['confidence']} ({f['classified_by']})",
        f"Source {f['src_ip']} · user {f['user']}",
    ]
    if f["text"]:
        body.insert(1, f["text"])
    if f["penalty"]:
        body.append(f"Inaction penalty +{f['penalty']} pts" + (" · SLA BREACHED" if f["sla_breached"] else ""))
    body.append(f"Recommended: {f['recommended']}")
    specs = button_specs(notification, incident)
    if specs:
        body.append("Actions: " + "  ".join(f"[{label.split(' ', 1)[-1]}]" for label, _ in specs)
                    + "  (use the dashboard in console mode)")

    inner = width - 4
    top = f"┌─ SentrAI · {f['header']} "
    lines = [c[f["band"]] + top + "─" * max(0, width - len(top) - 1) + "┐" + c["reset"]]
    for text in body:
        for chunk in _wrap(text, inner):
            lines.append(f"{c[f['band']]}│{c['reset']} {chunk.ljust(inner)} {c[f['band']]}│{c['reset']}")
    lines.append(c[f["band"]] + "└" + "─" * (width - 2) + "┘" + c["reset"])
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words, out, cur = str(text).split(), [], ""
    for w in words:
        if len(cur) + len(w) + (1 if cur else 0) > width:
            if cur:
                out.append(cur)
            while len(w) > width:
                out.append(w[:width])
                w = w[width:]
            cur = w
        else:
            cur = f"{cur} {w}" if cur else w
    out.append(cur)
    return out
