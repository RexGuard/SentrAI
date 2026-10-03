"""Email alerts over SMTP: the backup channel next to Telegram (plan section 9).

Env (all optional; with no SMTP_HOST or ALERT_EMAIL_TO, email stays off and alerts go to
Telegram or the console as before):
  SMTP_HOST            mail server, e.g. smtp.gmail.com
  SMTP_PORT            587 (STARTTLS), 465 (SSL) or 25 (plain)
  SMTP_SECURITY        starttls | ssl | none           (default starttls)
  SMTP_USER            login name, blank for servers without login
  SMTP_PASSWORD        login password or app password  (never hardcode it)
  ALERT_EMAIL_FROM     sender address (default SMTP_USER)
  ALERT_EMAIL_TO       recipients, comma-separated
  CACTAI_EMAIL_MODE    backup: only when Telegram fails (default) | always: next to Telegram

Email has no buttons, so each message points the operator to the dashboard to act.
"""
from __future__ import annotations

import html
import logging
import os
import smtplib
import ssl
import time
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import make_msgid
from typing import Callable

from formatting import (BAND_COLORS, BAND_EMOJI, BRAND_BUTTON, BRAND_ON_DARK, BRAND_DARK, TAGLINE, alert_fields,
                        button_specs, is_notice, notice_lines, risk_meter)

log = logging.getLogger("cactai.notifier.email")

SECURITY = ("starttls", "ssl", "none")
MODES = ("backup", "always")
DEFAULT_DASHBOARD = "http://127.0.0.1:8501"


@dataclass(frozen=True)
class EmailConfig:
    host: str
    port: int
    security: str
    user: str
    password: str
    sender: str
    recipients: tuple[str, ...]
    mode: str = "backup"
    dashboard_url: str = DEFAULT_DASHBOARD
    timeout: float = 15.0

    @classmethod
    def from_env(cls, env: "dict[str, str] | None" = None) -> "EmailConfig | None":
        """The SMTP settings, or None when email is not set up (console mode for email)."""
        e = os.environ if env is None else env
        host = e.get("SMTP_HOST", "").strip()
        recipients = tuple(a.strip() for a in e.get("ALERT_EMAIL_TO", "").split(",") if a.strip())
        if not host or not recipients:
            return None
        security = e.get("SMTP_SECURITY", "starttls").strip().lower() or "starttls"
        if security not in SECURITY:
            log.warning("SMTP_SECURITY=%r is not one of %s; using starttls", security, "/".join(SECURITY))
            security = "starttls"
        mode = e.get("CACTAI_EMAIL_MODE", "backup").strip().lower() or "backup"
        if mode not in MODES:
            log.warning("CACTAI_EMAIL_MODE=%r is not one of %s; using backup", mode, "/".join(MODES))
            mode = "backup"
        try:
            port = int(e.get("SMTP_PORT", "").strip() or (465 if security == "ssl" else 587))
        except ValueError:
            port = 465 if security == "ssl" else 587
        user = e.get("SMTP_USER", "").strip()
        return cls(host=host, port=port, security=security, user=user, password=e.get("SMTP_PASSWORD", ""),
                   sender=e.get("ALERT_EMAIL_FROM", "").strip() or user or f"cactai@{host}",
                   recipients=recipients, mode=mode,
                   dashboard_url=e.get("CACTAI_DASHBOARD_URL", "").strip() or DEFAULT_DASHBOARD)

    def describe(self) -> str:
        return (f"{', '.join(self.recipients)} via {self.host}:{self.port} ({self.security}), "
                + ("next to Telegram" if self.mode == "always" else "when Telegram fails"))


# ------------------------------------------------------------------ content

def format_email(notification: dict, incident: dict | None = None, risk: dict | None = None,
                 dashboard_url: str = DEFAULT_DASHBOARD) -> tuple[str, str, str]:
    """(subject, plain text, HTML) with the same content as the Telegram alert."""
    if is_notice(notification):
        icon, header, lines = notice_lines(notification)
        subject = f"[SentrAI] {lines[0] if lines else header}"
        text = "\n".join([f"{icon} {header}", *lines, "", f"-- SentrAI · {TAGLINE}"])
        body = "".join(f"<p style=\"margin:0 0 8px 0;font-family:{'monospace' if ln.startswith('SENTRAI-FP') else 'Arial,sans-serif'};"
                       f"font-size:14px;word-break:break-all\">{html.escape(ln)}</p>" for ln in lines)
        html_body = (f"<div style=\"max-width:640px\"><div style=\"background:{BRAND_DARK};color:#fff;padding:12px 16px;"
                     f"font-family:Arial,sans-serif;font-weight:bold\">{icon} {html.escape(header)} · SentrAI</div>"
                     f"<div style=\"padding:16px\">{body}</div></div>")
        return subject, text, html_body
    f = alert_fields(notification, incident, risk)
    risk_txt = f"{f['risk_index']}/100 {f['band'].upper()}" if f["risk_index"] is not None else "-"
    subject = f"[SentrAI] {f['header']}: {f['incident_id']} {f['title']}"
    if f["risk_index"] is not None:
        subject += f" · risk {f['risk_index']}"

    rows = [
        ("Incident", f"{f['incident_id']} · {f['title']}"),
        ("Risk", f"{risk_txt} {BAND_EMOJI[f['band']]}"),
        ("Severity", f"{f['severity']} · AI confidence {f['confidence']} ({f['classified_by']})"),
        ("Source", f"{f['src_ip']} · user {f['user']}"),
    ]
    if f["penalty"]:
        rows.append(("Inaction penalty", f"+{f['penalty']} pts" + (" · SLA BREACHED" if f["sla_breached"] else "")))
    rows.append(("Recommended", str(f["recommended"])))
    actions = [label.split(" ", 1)[-1] for label, _ in button_specs(notification, incident)]
    act = (f"To {' or '.join(actions)}, open the SentrAI dashboard: {dashboard_url}" if actions
           else f"Details on the SentrAI dashboard: {dashboard_url}")
    if f["kind"] in ("autonomous_action", "containment"):
        note = "Temporary, reversible fix with TTL. Choose Rollback or Make Permanent."
    else:
        note = "Acknowledge on the dashboard or in Telegram; that is what the audit log records. Delivery of this email is logged too."

    text = "\n".join([f"{f['icon']} {f['header']}", *([f["text"]] if f["text"] else []), "",
                      *(f"{k}: {v}" for k, v in rows), "", act, note, "", f"-- SentrAI · {TAGLINE}"])
    html_body = _email_html(f, rows, act, note, dashboard_url)
    return subject, text, html_body


def _email_html(f: dict, rows: list[tuple[str, str]], act: str, note: str, dashboard_url: str) -> str:
    """The branded HTML part: a navy SentrAI header, a risk gauge and a button to the dashboard.

    Email clients drop <style> blocks and SVG, so everything is inline styles on tables.
    """
    e = html.escape
    band = BAND_COLORS[f["band"]]
    font = "font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif"  # unquoted: the attributes use single quotes
    score = "" if f["risk_index"] is None else str(f["risk_index"])
    filled = risk_meter(f["risk_index"]).count("▰") * 10  # the same 10-step gauge as Telegram
    gauge = ""
    if score:
        gauge = (
            "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' style='margin:18px 0 6px'><tr>"
            f"<td style='{font};width:92px;vertical-align:bottom'><span style='font-size:40px;font-weight:700;"
            f"color:{band};line-height:1'>{e(score)}</span><span style='font-size:14px;color:#626f86'>/100</span></td>"
            "<td style='vertical-align:bottom;padding-bottom:6px'>"
            f"<span style='{font};display:inline-block;background:{band};color:#fff;font-size:11px;font-weight:700;"
            f"letter-spacing:.8px;padding:3px 9px;border-radius:10px'>{e(f['band'].upper())}</span>"
            "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' style='margin-top:8px'><tr>"
            + (f"<td width='{filled}%' style='background:{band};height:8px;border-radius:4px 0 0 4px'></td>" if filled else "")
            + (f"<td style='background:#e4e9f1;height:8px'></td>" if filled < 100 else "")
            + "</tr></table></td></tr></table>")
    body_rows = "".join(
        f"<tr><td style='{font};padding:9px 14px 9px 0;color:#626f86;font-size:13px;white-space:nowrap;"
        f"vertical-align:top;border-top:1px solid #e4e9f1'>{e(k)}</td>"
        f"<td style='{font};padding:9px 0;color:#0f1a2c;font-size:14px;border-top:1px solid #e4e9f1'>{e(v)}</td></tr>"
        for k, v in rows)
    return (
        f"<div style='margin:0;padding:24px 12px;background:#f5f7fb'>"
        "<table role='presentation' align='center' width='100%' cellpadding='0' cellspacing='0' "
        "style='max-width:580px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;"
        "border:1px solid #d5dce8'>"
        # header band
        f"<tr><td style='background:{BRAND_DARK};padding:18px 24px'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0'><tr>"
        f"<td style='{font};font-size:20px;font-weight:700;color:#e7edf6'>&#128737;&#65039; Sentr"
        f"<span style='color:{BRAND_ON_DARK}'>AI</span></td>"
        f"<td align='right' style='{font};font-size:11px;letter-spacing:1.2px;color:#a5b2c6;text-transform:uppercase'>"
        f"{e(f['header'])}</td></tr></table></td></tr>"
        f"<tr><td style='background:{band};height:4px;line-height:4px;font-size:0'>&nbsp;</td></tr>"
        # body
        "<tr><td style='padding:22px 24px 8px'>"
        f"<div style='{font};font-size:12px;color:#626f86;letter-spacing:.6px'>{e(str(f['incident_id']))}</div>"
        f"<div style='{font};font-size:21px;font-weight:700;color:#0f1a2c;margin-top:2px'>"
        f"{e(f['icon'])} {e(f['title'])}</div>"
        + (f"<p style='{font};font-size:14px;color:#44536b;margin:10px 0 0'>{e(f['text'])}</p>" if f["text"] else "")
        + gauge
        + f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' style='margin-top:10px'>{body_rows}</table>"
        # call to action
        + "<table role='presentation' cellpadding='0' cellspacing='0' style='margin:22px 0 6px'><tr>"
        f"<td style='background:{BRAND_BUTTON};border-radius:8px'><a href='{e(dashboard_url, quote=True)}' "
        f"style='{font};display:inline-block;padding:11px 20px;color:#ffffff;font-size:14px;font-weight:600;"
        "text-decoration:none'>Open the SentrAI dashboard</a></td></tr></table>"
        f"<p style='{font};font-size:13px;color:#44536b;margin:8px 0 0'>{e(act)}</p>"
        f"<p style='{font};font-size:12px;color:#626f86;font-style:italic;margin:6px 0 18px'>{e(note)}</p>"
        "</td></tr>"
        # footer
        f"<tr><td style='{font};background:#eef2f8;border-top:1px solid #e4e9f1;padding:12px 24px;font-size:11px;"
        f"color:#626f86'>&#128737;&#65039; SentrAI &middot; {e(TAGLINE)}</td></tr>"
        "</table></div>")


def build_message(cfg: EmailConfig, notification: dict, incident: dict | None, risk: dict | None) -> EmailMessage:
    subject, text, html_body = format_email(notification, incident, risk, cfg.dashboard_url)
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.sender
    msg["To"] = ", ".join(cfg.recipients)
    msg["Message-ID"] = make_msgid(domain="cactai.local")
    msg.set_content(text)
    msg.add_alternative(html_body, subtype="html")
    return msg


# ------------------------------------------------------------------ delivery

SmtpFactory = Callable[..., smtplib.SMTP]


def send_email(cfg: EmailConfig, msg: EmailMessage, smtp: SmtpFactory | None = None,
               smtp_ssl: SmtpFactory | None = None) -> str:
    """Send one message; returns its Message-ID. Raises smtplib.SMTPException / OSError on failure."""
    if cfg.security == "ssl":
        conn = (smtp_ssl or smtplib.SMTP_SSL)(cfg.host, cfg.port, timeout=cfg.timeout,
                                             context=ssl.create_default_context())
    else:
        conn = (smtp or smtplib.SMTP)(cfg.host, cfg.port, timeout=cfg.timeout)
    with conn:
        if cfg.security == "starttls":
            conn.starttls(context=ssl.create_default_context())
        if cfg.user:
            conn.login(cfg.user, cfg.password)
        conn.send_message(msg)
    return str(msg["Message-ID"])


def email_sender(cfg: EmailConfig, **factories) -> Callable[[dict, "dict | None", "dict | None"], str]:
    """A SendFn that emails the alert and returns an 'email-...' message id."""
    counter = {"n": 0}

    def send(n: dict, incident: dict | None, risk: dict | None) -> str:
        counter["n"] += 1
        msg_id = send_email(cfg, build_message(cfg, n, incident, risk), **factories)
        log.info("delivered %s by email to %s (%s)", n.get("id"), ", ".join(cfg.recipients), msg_id)
        return f"email-{int(time.time())}-{counter['n']}"

    return send
