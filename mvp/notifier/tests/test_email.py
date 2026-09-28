"""Email backup channel. A fake SMTP class stands in for the server: no real email is sent."""
import io
import smtplib

import pytest
import requests

import emailer
import notifier
from core import Core
from emailer import EmailConfig, build_message, email_sender, format_email, send_email
from notifier import console_sender, process_pending, with_email

NOTE = {"id": "N-1", "incident_id": "INC-7", "kind": "reminder", "risk_index": 72,
        "text": "Still unacknowledged after 2 h.", "src_ip": "203.0.113.9", "user": "admin"}
INCIDENT = {"id": "INC-7", "category": "brute_force", "host": "portal", "status": "open",
            "severity": "high", "ai_confidence": 0.91, "classified_by": "rules",
            "recommended_action": "block_ip 203.0.113.9", "inaction_penalty": 10, "sla_breached": True}
ENV = {"SMTP_HOST": "smtp.example.test", "ALERT_EMAIL_TO": "soc@example.test, lead@example.test",
       "SMTP_USER": "cactai@example.test", "SMTP_PASSWORD": "pw"}


class FakeSMTP:
    """Records what would have been sent."""
    sent: list = []
    fail = False

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.calls = host, port, []
        if FakeSMTP.fail:
            raise smtplib.SMTPConnectError(421, b"service not available")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context=None):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(("login", user))

    def send_message(self, msg):
        FakeSMTP.sent.append((self, msg))


@pytest.fixture(autouse=True)
def fake_smtp(monkeypatch):
    FakeSMTP.sent, FakeSMTP.fail = [], False
    monkeypatch.setattr(emailer.smtplib, "SMTP", FakeSMTP)  # belt and braces: nothing reaches a real server
    monkeypatch.setattr(emailer.smtplib, "SMTP_SSL", FakeSMTP)
    return FakeSMTP


def test_no_smtp_settings_means_email_off():
    assert EmailConfig.from_env({}) is None
    assert EmailConfig.from_env({"SMTP_HOST": "smtp.example.test"}) is None  # no recipients
    assert EmailConfig.from_env({"ALERT_EMAIL_TO": "soc@example.test"}) is None  # no server


def test_config_defaults_from_env():
    cfg = EmailConfig.from_env(ENV)
    assert cfg.port == 587 and cfg.security == "starttls" and cfg.mode == "backup"
    assert cfg.recipients == ("soc@example.test", "lead@example.test")
    assert cfg.sender == "cactai@example.test"
    ssl_cfg = EmailConfig.from_env(ENV | {"SMTP_SECURITY": "ssl", "SMTP_PORT": "", "CACTAI_EMAIL_MODE": "bogus"})
    assert ssl_cfg.port == 465 and ssl_cfg.mode == "backup"


def test_email_has_the_telegram_alert_content():
    subject, text, html = format_email(NOTE, INCIDENT, None, "http://dash.test")
    assert subject.startswith("[CactAI] Reminder") and "INC-7" in subject and "risk 72" in subject
    for part in ("Still unacknowledged", "Brute force (portal)", "72/100", "203.0.113.9", "admin",
                 "block_ip 203.0.113.9", "+10 pts", "SLA BREACHED", "Approve & Patch", "http://dash.test"):
        assert part in text, part
    assert "SLA BREACHED" in html and "&amp; Patch" in html


def test_send_uses_starttls_login_and_both_parts():
    cfg = EmailConfig.from_env(ENV)
    send_email(cfg, build_message(cfg, NOTE, INCIDENT, None))
    conn, msg = FakeSMTP.sent[0]
    assert (conn.host, conn.port) == ("smtp.example.test", 587)
    assert conn.calls == ["starttls", ("login", "cactai@example.test")]
    assert msg["To"] == "soc@example.test, lead@example.test"
    assert [p.get_content_type() for p in msg.iter_parts()] == ["text/plain", "text/html"]


def test_no_login_without_user():
    cfg = EmailConfig.from_env({"SMTP_HOST": "relay.test", "ALERT_EMAIL_TO": "a@b.test", "SMTP_SECURITY": "none"})
    email_sender(cfg)(NOTE, INCIDENT, None)
    assert FakeSMTP.sent[0][0].calls == []


# ------------------------------------------------------------------ fallback and "always"

def ok_telegram(n, incident, risk):
    return "4242"


def broken_telegram(n, incident, risk):
    raise TimeoutError("telegram unreachable")


def test_backup_mode_emails_only_when_telegram_fails():
    email = email_sender(EmailConfig.from_env(ENV))
    assert with_email(ok_telegram, "telegram", email, always=False)(NOTE, INCIDENT, None) == ("telegram", "4242")
    assert FakeSMTP.sent == []
    channel, mid = with_email(broken_telegram, "telegram", email, always=False)(NOTE, INCIDENT, None)
    assert channel == "email" and mid.startswith("email-") and len(FakeSMTP.sent) == 1


def test_always_mode_sends_both_and_survives_email_failure():
    email = email_sender(EmailConfig.from_env(ENV | {"CACTAI_EMAIL_MODE": "always"}))
    channel, mid = with_email(ok_telegram, "telegram", email, always=True)(NOTE, INCIDENT, None)
    assert channel == "telegram+email" and mid.startswith("4242 email-")
    FakeSMTP.fail = True
    assert with_email(ok_telegram, "telegram", email, always=True)(NOTE, INCIDENT, None) == ("telegram", "4242")


def test_both_channels_down_raises_so_the_alert_is_retried():
    FakeSMTP.fail = True
    send = with_email(broken_telegram, "telegram", email_sender(EmailConfig.from_env(ENV)), always=False)
    with pytest.raises(smtplib.SMTPException):
        send(NOTE, INCIDENT, None)


def test_without_email_telegram_errors_pass_through():
    assert with_email(ok_telegram, "telegram", None, always=True) is ok_telegram


# ------------------------------------------------------------------ against the fake core

def test_console_mode_also_emails_and_records_the_channel(fake_core):
    requests.post(f"{fake_core}/demo/reset", timeout=3)
    requests.post(f"{fake_core}/dev/trigger/brute_force", timeout=3)
    core = Core(fake_core)
    buf = io.StringIO()
    send = with_email(console_sender(buf, color=False), "console", email_sender(EmailConfig.from_env(ENV)), True)
    assert len(process_pending(core, send, "console", set())) == 1
    assert "Brute force" in buf.getvalue() and len(FakeSMTP.sent) == 1
    assert "Brute force" in FakeSMTP.sent[0][1]["Subject"]
    rec = [r for r in requests.get(f"{fake_core}/audit", timeout=3).json()["records"]
           if r["type"] == "notification_delivered"][-1]
    assert rec["data"]["channel"] == "console+email"


def test_main_console_mode_reports_email_off(fake_core, monkeypatch, capsys):
    for name in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "SMTP_HOST", "ALERT_EMAIL_TO"):
        monkeypatch.delenv(name, raising=False)
    assert notifier.main(["--core", fake_core, "--once"]) == 0
    assert "email alerts off" in capsys.readouterr().out
    assert FakeSMTP.sent == []
