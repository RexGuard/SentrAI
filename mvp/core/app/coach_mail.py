"""Email the Security Coach's notes to staff (the coach writes them, coach.py; this only delivers).

Off until the owner ticks "Email coaching notes" on the Coach page. Then every 15 minutes (and on
`sudo sentrai coach send`) each person reached by email who confirmed the staff notice gets one email with their
notes that are ready, at most MAX_NOTES of them, oldest first; the rest wait for the next round. Sample notes and
notes held for the notice are never emailed. The email has no links on purpose: staff are taught not to trust
links in unexpected security emails, so the coach does not send any.

The same mail server as the alerts: the company's own SMTP_* settings, or SentrAI's mail relay
(SENTRAI_RELAY_SMTP_*) when the company has none. Without either nothing is sent and the notes stay ready (the
phone app still shows them). A failed send keeps the notes ready for the next round.
"""
from __future__ import annotations

import logging
import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import make_msgid
from typing import Any, Callable

log = logging.getLogger("sentrai.coach_mail")

MAX_NOTES = 3  # per person per email
KEYS = ("SMTP_HOST", "SMTP_PORT", "SMTP_SECURITY", "SMTP_USER", "SMTP_PASSWORD", "ALERT_EMAIL_FROM",
        "SENTRAI_RELAY_SMTP_HOST", "SENTRAI_RELAY_SMTP_PORT", "SENTRAI_RELAY_SMTP_SECURITY",
        "SENTRAI_RELAY_SMTP_USER", "SENTRAI_RELAY_SMTP_PASSWORD", "SENTRAI_RELAY_FROM")


def mail_settings(env: dict[str, str] | None = None) -> dict[str, str] | None:
    """{host, port, security, user, password, sender, relay} or None when no mail server is set. The relay's login
    is used only when the company has no SMTP_HOST of its own, so it is never sent to the company's server."""
    if env is None:
        try:
            from .config import sentrai_config as cfg
            saved = cfg.read()
        except Exception:  # noqa: BLE001  no settings file: the environment alone
            saved = {}
        env = {k: str(saved.get(k) or os.environ.get(k) or "") for k in KEYS}
    own = (env.get("SMTP_HOST") or "").strip()
    relay = not own and bool((env.get("SENTRAI_RELAY_SMTP_HOST") or "").strip())
    p = "SENTRAI_RELAY_SMTP_" if relay else "SMTP_"
    host = (env.get(p + "HOST") or "").strip()
    if not host:
        return None
    security = (env.get(p + "SECURITY") or "starttls").strip().lower()
    if security not in ("starttls", "ssl", "none"):
        security = "starttls"
    try:
        port = int((env.get(p + "PORT") or "").strip() or (465 if security == "ssl" else 587))
    except ValueError:
        port = 465 if security == "ssl" else 587
    user = (env.get(p + "USER") or "").strip()
    sender = (env.get("SENTRAI_RELAY_FROM" if relay else "ALERT_EMAIL_FROM") or "").strip()
    return {"host": host, "port": str(port), "security": security, "user": user,
            "password": env.get(p + "PASSWORD") or "", "sender": sender or user or f"sentrai@{host}",
            "relay": "yes" if relay else ""}


def send(msg: EmailMessage, m: dict[str, str]) -> None:
    port = int(m["port"])
    if m["security"] == "ssl":
        conn = smtplib.SMTP_SSL(m["host"], port, timeout=15, context=ssl.create_default_context())
    else:
        conn = smtplib.SMTP(m["host"], port, timeout=15)
    with conn:
        if m["security"] == "starttls":
            conn.starttls(context=ssl.create_default_context())
        if m["user"]:
            conn.login(m["user"], m["password"])
        conn.send_message(msg)


def build(person: dict[str, Any], notes: list[dict[str, Any]], org: str, contact: str, it_contact: str,
          sender: str) -> EmailMessage:
    """One email with this person's notes. Plain text, no links."""
    many = len(notes) > 1
    msg = EmailMessage()
    subject = f"{len(notes)} quick security tips" if many else "A quick security tip"
    msg["Subject"] = subject + (f" from {org}" if org else "")
    msg["From"] = sender
    msg["To"] = person["email"]
    msg["Message-ID"] = make_msgid(domain="sentrai")
    help_from = it_contact or contact
    parts = []
    for n in notes:
        text = n["text"]
        if "No, that wasn't me" in (n.get("buttons") or []):
            text += ("\n\nIf this wasn't you, tell " + (help_from or "your IT contact") +
                     " straight away, and change your password from the app's own sign-in page.")
        parts.append(text)
    lines = ["\n\n----\n\n".join(parts), "",
             "You can answer and take the one-minute lesson in the SentrAI app, or ask "
             + (help_from or "your IT contact") + " if anything is unclear.",
             "",
             "This email has no links on purpose. A real security message never needs you to click one.",
             f"Why you're getting this: {org or 'your company'} uses SentrAI's Security Coach. It only sees what "
             "kind of action happened in your work apps, never what your emails, chats or files say."
             + (f" Questions about your data: {contact}." if contact else "")]
    msg.set_content("\n".join(lines))
    return msg


def send_due(coach: Any, org: Callable[[], tuple[str, str]], mail: dict[str, str] | None = None,
             sender: Callable[[EmailMessage, dict[str, str]], None] = send,
             record: Callable[[str, dict[str, Any]], Any] | None = None, by: str = "schedule") -> dict[str, Any]:
    """Email every person their notes that are ready. Returns {sent, notes, failed, skipped?}."""
    out: dict[str, Any] = {"sent": 0, "notes": 0, "failed": 0}
    if not coach.settings().get("email_notes"):
        return {**out, "skipped": "Email coaching notes is switched off on the Coach page."}
    box = coach.outbox()
    if not box:
        return out
    m = mail if mail is not None else mail_settings()
    if m is None:
        return {**out, "skipped": "No mail server is set up (SMTP_HOST), so the notes wait in the app."}
    name, contact = org()
    it_contact = ""
    knowledge = getattr(coach, "knowledge", None)
    if knowledge is not None:
        try:
            it_contact = str(knowledge.facts().get("it_contact") or "")
        except Exception:  # noqa: BLE001
            it_contact = ""
    errors = []
    for person in box:
        notes = person["notes"][:MAX_NOTES]
        try:
            sender(build(person, notes, name, contact, it_contact, m["sender"]), m)
        except (smtplib.SMTPException, OSError) as exc:
            out["failed"] += 1
            errors.append(str(exc)[:200])
            continue
        out["sent"] += 1
        out["notes"] += coach.mark_sent([n["id"] for n in notes], "email")
    if errors:
        out["error"] = errors[0]
        log.warning("coach notes: %d email(s) failed, first: %s", len(errors), errors[0])
    if record is not None and (out["sent"] or out["failed"]):
        record("coach_notes_emailed", {"by": by, "people": out["sent"], "notes": out["notes"],
                                       "failed": out["failed"], "relay": bool(m.get("relay"))})
    return out
