"""Root access from a sign-in SentrAI does not recognise: the alert asks "was this you?", and its buttons come
from the notification itself (the core's labels and actions), as every alert's do."""
import json

import pytest

from core import Core, CoreError
from emailer import format_email
from formatting import button_specs, format_console, format_telegram, parse_callback

KEY = "SHA256:Q7w3cZk2u5Yd9bJm1LxkfA0Hn6Rr8PtEoSvNqGiCz4U"
WAS_THIS_YOU = [{"label": "This was me", "action": "mine"}, {"label": "Not me: block it", "action": "approve"},
                {"label": "Acknowledge", "action": "ack"}]
DECIDE = [{"label": "Approve & Patch", "action": "approve"}, {"label": "Reject with Justification", "action": "reject"},
          {"label": "Acknowledge", "action": "ack"}]
AFTER_ACTION = [{"label": "Rollback", "action": "rollback"}, {"label": "Make Permanent", "action": "permanent"},
                {"label": "Acknowledge", "action": "ack"}]
ASK = {"id": "ntf-0012", "incident": "RSK-2026-012", "kind": "was_this_you", "risk_index": 41,
       "title": "⚠️ RSK-2026-012 · Root access from an unrecognised sign-in (web-01, account 'erick') · Risk 41/100",
       "text": "sudo on web-01 from 203.0.113.5 by erick, a sign-in SentrAI does not recognise.\n"
               "Was this you? 'This was me' teaches SentrAI this sign-in and closes the alert. 'Not me' blocks the address.",
       "buttons": WAS_THIS_YOU}
INC = {"id": "RSK-2026-012", "category": "unauthorised_admin", "severity": "critical", "host": "web-01",
       "user": "erick", "src_ip": "203.0.113.5", "status": "open", "needs_review": True,
       "recommended_action": "Confirm it was you, or block 203.0.113.5",
       "actor": {"host": "web-01", "user": "erick", "via": "ssh", "address": "203.0.113.5", "key": KEY,
                 "session": "s3", "trust": "unknown", "why": "no known administrator address or key"}}


def test_the_keyboard_is_the_notifications_own_buttons():
    specs = button_specs(ASK, INC)
    assert specs == [("✋ This was me", "mine:RSK-2026-012"), ("🚫 Not me: block it", "approve:RSK-2026-012"),
                     ("🙋 Take it", "take:RSK-2026-012")]
    assert all(len(d.encode()) <= 64 for _, d in specs)  # Telegram limit
    # Reminders and escalations about it carry the same list from the core, so they show the same buttons.
    for kind in ("sla_reminder", "escalated", "assigned"):
        assert button_specs({**ASK, "id": "ntf-0013", "kind": kind}, INC) == specs
    assert button_specs(ASK, {**INC, "status": "resolved"}) == []  # answered already


def test_every_kind_follows_the_cores_list_and_existing_kinds_look_the_same():
    opened = {"id": "ntf-1", "incident": "RSK-1", "kind": "incident_opened", "buttons": DECIDE}
    assert [l for l, _ in button_specs(opened, {"id": "RSK-1", "status": "open"})] == \
        ["✅ Approve & Patch", "⛔ Reject with Justification", "🙋 Take it"]
    auto = {"id": "ntf-2", "incident": "RSK-1", "kind": "autonomous_action", "buttons": AFTER_ACTION}
    assert [d for _, d in button_specs(auto, {"id": "RSK-1", "status": "contained"})] == ["rollback:RSK-1", "permanent:RSK-1"]
    # A button this notifier cannot press is left out; the core's words are kept for the rest.
    odd = {**opened, "buttons": [{"label": "Call the police", "action": "police"}, {"label": "Hold it", "action": "approve"},
                                 {"label": "Hold it again", "action": "approve"}, "junk"]}
    assert button_specs(odd, {"id": "RSK-1", "status": "open"}) == [("✅ Hold it", "approve:RSK-1")]
    # No list (an older core) or an empty one: the usual set for the incident's state.
    for buttons in ({}, {"buttons": []}, {"buttons": "junk"}):
        assert [d.split(":")[0] for _, d in button_specs({**opened, **buttons}, {"id": "RSK-1", "status": "open"})] == \
            ["approve", "reject", "take"]


def test_parse_callback_knows_mine():
    assert parse_callback("mine:RSK-2026-012") == ("mine", "RSK-2026-012")
    assert parse_callback("ack:RSK-1") is None  # the core's Acknowledge is shown as Take it, never sent back


def test_telegram_console_and_email_words():
    msg = format_telegram(ASK, INC)
    assert "🔑 <b>Was this you?</b>" in msg
    assert "<b>RSK-2026-012</b> · Root access from an unrecognised sign-in (web-01)" in msg
    assert "This was me" in msg and "203.0.113.5" in msg
    box = format_console(ASK, INC, color=False, width=100)
    assert "[This was me]" in box and "[Not me: block it]" in box and "[Take it]" in box
    _, text, html_body = format_email(ASK, INC, None, "http://dash.test")
    assert "Was this you? Answer on the SentrAI dashboard (This was me / Not me: block it): http://dash.test" in text
    assert "Root access from an unrecognised sign-in" in html_body


# ------------------------------------------------------------------ the core client

class FakeResponse:
    def __init__(self, status, body):
        self.status_code, self._body = status, body
        self.text = json.dumps(body)

    def json(self):
        return self._body


class FakeSession:
    """Stands in for requests.Session: answers each call from a script and records it."""

    def __init__(self, answers):
        self.answers, self.calls, self.headers = list(answers), [], {}

    def request(self, method, url, json=None, timeout=None):
        self.calls.append((method, url, json))
        return FakeResponse(*self.answers.pop(0))


def test_the_client_posts_mine_and_passes_the_cores_reasons_on():
    core = Core("http://core.test/", token="t")
    core.session = FakeSession([
        (200, {"id": "RSK-2026-012", "status": "resolved", "learned": ["address 203.0.113.5"], "also_closed": []}),
        (409, {"detail": "RSK-2026-012 is already resolved"}),
        (400, {"detail": "ADMIN_SESSIONS is off: SentrAI is not keeping track of the administrators"}),
    ])
    out = core.mine("RSK-2026-012", "erick", "telegram")
    assert out["learned"] == ["address 203.0.113.5"] and out["status"] == "resolved"
    assert core.session.calls == [("POST", "http://core.test/incidents/RSK-2026-012/mine",
                                   {"operator": "erick", "channel": "telegram"})]
    with pytest.raises(CoreError) as closed:
        core.mine("RSK-2026-012", "erick", "telegram")
    assert closed.value.status == 409 and closed.value.detail == "RSK-2026-012 is already resolved"
    with pytest.raises(CoreError) as off:
        core.mine("RSK-2026-012", "erick", "telegram")
    assert off.value.status == 400 and off.value.detail.startswith("ADMIN_SESSIONS is off")
