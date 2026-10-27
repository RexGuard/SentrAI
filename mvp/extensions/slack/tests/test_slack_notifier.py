"""Slack extension, notifier side: a copy of each alert. A fake poster stands in for Slack: nothing is
really posted."""
import json
from types import SimpleNamespace

import pytest

import sentrai_extensions as se
from notifier import with_copies

sl = se.load_part(se.installed()["slack"], "notifier")
format_slack, slack_sender = sl.format_slack, sl.slack_sender

NOTE = {"id": "N-1", "incident_id": "INC-7", "kind": "reminder", "risk_index": 72,
        "text": "Still <unacknowledged> after 2 h & counting.", "src_ip": "203.0.113.9", "user": "admin",
        "report_url": "https://sentrai.example/reports/INC-7?sig=abc"}
INCIDENT = {"id": "INC-7", "category": "brute_force", "host": "portal", "status": "open", "severity": "high",
            "recommended_action": "block_ip 203.0.113.9",
            "reputation": {"score": 100, "reports": 312}}


def test_format_escapes_and_links_the_report():
    text = format_slack(NOTE, INCIDENT, None)
    assert "*INC-7*" in text and "risk *72/100*" in text
    assert "&lt;unacknowledged&gt;" in text and "&amp; counting" in text
    assert "100% abuse confidence, reported 312 time(s)" in text
    assert "<https://sentrai.example/reports/INC-7?sig=abc|Open the report>" in text


def test_sender_posts_json_and_raises_on_errors():
    sent = []
    send = slack_sender("https://hooks.slack.com/services/T/B/x", lambda u, b, h: sent.append(json.loads(b)) or 200)
    assert send(NOTE, INCIDENT, None) == "slack-N-1" and "INC-7" in sent[0]["text"]
    with pytest.raises(RuntimeError):
        slack_sender("https://hooks.slack.com/x", lambda *a: 404)(NOTE, INCIDENT, None)
    with pytest.raises(ValueError):
        slack_sender("http://hooks.slack.com/x")


def test_slack_is_a_copy_and_never_blocks_the_main_alert():
    def telegram(n, i, r):
        return "telegram", "4242"

    def broken_slack(n, i, r):
        raise RuntimeError("Slack answered HTTP 500")

    assert with_copies(telegram, [("slack", lambda n, i, r: "slack-1")])(NOTE, INCIDENT, None) == ("telegram+slack", "4242")
    assert with_copies(telegram, [("slack", broken_slack)])(NOTE, INCIDENT, None) == ("telegram", "4242")
    assert with_copies(telegram, []) is telegram


def test_copy_channel_needs_an_https_url():
    def ctx(url):
        return SimpleNamespace(setting=lambda env: url if env == "SLACK_WEBHOOK_URL" else "")

    assert sl.copy_channel(ctx("")) is None
    assert sl.copy_channel(ctx("http://hooks.slack.com/x")) is None  # logged, never posted in the clear
    assert callable(sl.copy_channel(ctx("https://hooks.slack.com/services/T/B/x")))
