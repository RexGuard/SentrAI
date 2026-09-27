from formatting import (button_specs, format_console, format_telegram, parse_callback)

NOTIF = {"id": "ntf-0001", "incident_id": "RSK-2026-081", "kind": "incident_opened", "risk_index": 44,
         "text": "Brute force on admin login <from 203.0.113.45>"}
INC = {"id": "RSK-2026-081", "category": "brute_force", "severity": "high", "ai_confidence": 0.94,
       "classified_by": "jev", "src_ip": "203.0.113.45", "user": "admin", "host": "web-01",
       "status": "open", "inaction_penalty": 15, "sla_breached": True,
       "recommended_action": "Block 203.0.113.45 for 2 h & rate-limit /login"}


def test_telegram_message_contents_and_escaping():
    msg = format_telegram(NOTIF, INC)
    assert "RSK-2026-081" in msg
    assert "Brute force (web-01)" in msg
    assert "44/100" in msg
    assert "0.94" in msg
    assert "&lt;from 203.0.113.45&gt;" in msg  # HTML-escaped
    assert "&amp; rate-limit" in msg
    assert "SLA BREACHED" in msg
    assert "<b>Recommended:</b>" in msg


def test_telegram_message_without_incident_uses_risk_fallback():
    msg = format_telegram({"id": "n", "incident_id": "RSK-9"}, None, {"risk_index": 85})
    assert "RSK-9" in msg and "85/100" in msg and "🚨" in msg


def test_buttons_depend_on_state():
    labels = [l for l, _ in button_specs(NOTIF, INC)]
    assert labels == ["✅ Approve & Patch", "⛔ Reject with Justification"]
    assert button_specs(NOTIF, INC)[0][1] == "approve:RSK-2026-081"
    contained = button_specs({**NOTIF, "kind": "autonomous_action"}, {**INC, "status": "contained"})
    assert [d.split(":")[0] for _, d in contained] == ["rollback", "permanent"]
    assert button_specs(NOTIF, {**INC, "status": "resolved"}) == []
    assert all(len(d.encode()) <= 64 for _, d in button_specs(NOTIF, INC))  # Telegram limit


def test_parse_callback():
    assert parse_callback("approve:RSK-1") == ("approve", "RSK-1")
    assert parse_callback("reject:RSK-1") == ("reject", "RSK-1")
    assert parse_callback("delete:RSK-1") is None
    assert parse_callback("approve") is None


def test_console_box_is_aligned_without_color():
    out = format_console(NOTIF, INC, color=False, width=60)
    lines = out.splitlines()
    assert lines[-1].startswith("└") and lines[-1].endswith("┘")
    assert len(lines[0]) == 60 and len(lines[-1]) == 60
    body = [l for l in lines[1:-1]]
    assert body and all(len(l) == 60 for l in body)
    assert "\033[" not in out
    assert "[Approve & Patch]" in out
