"""A record fingerprint is a short note to keep, not an incident alert."""

from emailer import format_email
from formatting import button_specs, format_console, format_telegram

LINE = "SENTRAI-FP v1 seq=42 head=" + "ab" * 32 + " at=2026-10-02T10:00:00Z sig=" + "cd" * 16
FP = {"id": "ntf-0007", "incident": None, "kind": "audit_anchor", "title": "Record fingerprint #42 abababababababab",
      "text": "Fingerprint of audit records 1 to 42. Keep this message.\n" + LINE, "risk_index": 12, "buttons": []}


def test_telegram_shows_the_line_whole_and_no_incident_fields():
    msg = format_telegram(FP, None, {"risk_index": 12})
    assert "Record fingerprint" in msg and f"<code>{LINE}</code>" in msg
    assert "Recommended" not in msg and "Severity" not in msg and "Risk" not in msg
    assert button_specs(FP, None) == []


def test_console_and_email():
    box = format_console(FP, None, None, color=False)
    assert "Record fingerprint" in box and "seq=42" in box
    subject, text, html_body = format_email(FP)
    assert subject == "[SentrAI] Record fingerprint #42 abababababababab"
    assert LINE in text and LINE in html_body
