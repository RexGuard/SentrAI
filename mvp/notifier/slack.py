"""Slack: a copy of every alert in a channel, through an incoming webhook.

Env:
  SLACK_WEBHOOK_URL   https://hooks.slack.com/services/... (Slack > Apps > Incoming Webhooks), blank = off

Slack is a read-only copy next to Telegram, email or the console: decisions stay in Telegram and the
dashboard, so a Slack message has a link to the report but no buttons. A Slack failure is logged and
never holds up the main alert.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Callable

from formatting import BAND_EMOJI, BRAND, alert_fields, is_notice, notice_lines

log = logging.getLogger("sentrai.notifier.slack")

# poster(url, body bytes, headers) -> HTTP status; raises on network errors
Poster = Callable[[str, bytes, dict], int]


def _requests_poster(timeout_s: float = 5.0) -> Poster:
    import requests

    def post(url: str, body: bytes, headers: dict) -> int:
        return requests.post(url, data=body, headers=headers, timeout=timeout_s, allow_redirects=False).status_code

    return post


def _e(text: object) -> str:
    """Slack mrkdwn escaping: only &, < and > are special."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def format_slack(notification: dict, incident: dict | None = None, risk: dict | None = None) -> str:
    if is_notice(notification):
        icon, header, lines = notice_lines(notification)
        return "\n".join([f"{icon} *{_e(header)}*  ·  _{BRAND}_", *(_e(ln) for ln in lines)])
    f = alert_fields(notification, incident, risk)
    risk_txt = f"{f['risk_index']}/100" if f["risk_index"] is not None else "-"
    lines = [
        f"{f['icon']} *{_e(f['header'])}*  ·  _{BRAND}_",
        f"*{_e(f['incident_id'])}* · {_e(f['title'])} · risk *{_e(risk_txt)}* {BAND_EMOJI[f['band']]}",
    ]
    if f["text"]:
        lines.append(_e(f["text"]))
    lines.append(f"Severity *{_e(f['severity'])}* · source `{_e(f['src_ip'])}` · user `{_e(f['user'])}`")
    rep = (incident or {}).get("reputation") or {}
    if rep and not rep.get("error"):
        lines.append(f"AbuseIPDB: {_e(rep.get('score', 0))}% abuse confidence, reported {_e(rep.get('reports', 0))} time(s)")
    lines.append(f"*Recommended:* {_e(f['recommended'])}")
    if notification.get("report_url"):
        lines.append(f"<{_e(notification['report_url'])}|Open the report> · decide in Telegram or the dashboard")
    return "\n".join(lines)


def slack_sender(url: str, poster: Poster | None = None) -> Callable[[dict, "dict | None", "dict | None"], str]:
    if not url.lower().startswith("https://"):
        raise ValueError("SLACK_WEBHOOK_URL must start with https://")
    post = poster or _requests_poster()

    def send(n: dict, incident: dict | None, risk: dict | None) -> str:
        body = json.dumps({"text": format_slack(n, incident, risk), "unfurl_links": False}).encode()
        status = post(url, body, {"Content-Type": "application/json"})
        if not 200 <= status < 300:
            raise RuntimeError(f"Slack answered HTTP {status}")
        return f"slack-{n.get('id')}"

    return send


def slack_from_env():
    url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if not url:
        return None
    try:
        return slack_sender(url)
    except ValueError as exc:
        log.warning("Slack is off: %s", exc)
        return None


def with_slack(primary: Callable, slack: Callable | None) -> Callable:
    """Send by `primary`, then post a copy to Slack. A Slack failure is only logged."""
    if slack is None:
        return primary

    def send(n: dict, incident: dict | None, risk: dict | None):
        result = primary(n, incident, risk)
        try:
            copy = slack(n, incident, risk)
        except Exception as exc:
            log.warning("Slack copy of %s failed: %s", n.get("id"), exc)
            return result
        if isinstance(result, list):  # one receipt per person (direct Telegram messages): Slack is one more
            return [*result, ("slack", str(copy), None)]
        used, message_id = result if isinstance(result, tuple) else (None, result)
        return (f"{used}+slack", message_id) if used else result

    return send
