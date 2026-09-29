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

from formatting import BAND_EMOJI, alert_fields, button_specs

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
                      *(f"{k}: {v}" for k, v in rows), "", act, note])
    e = html.escape
    body_rows = "".join(f"<tr><td style='padding:2px 12px 2px 0;color:#666'>{e(k)}</td><td>{e(v)}</td></tr>"
                        for k, v in rows)
    html_body = (f"<div style='font-family:sans-serif'><h3>{e(f['icon'])} {e(f['header'])}</h3>"
                 + (f"<p>{e(f['text'])}</p>" if f["text"] else "")
                 + f"<table>{body_rows}</table>"
                 + f"<p><a href='{e(dashboard_url)}'>{e(act)}</a></p><p><i>{e(note)}</i></p></div>")
    return subject, text, html_body


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
