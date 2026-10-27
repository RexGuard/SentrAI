"""Slack extension, core side: whether the webhook is set, and the Test button."""

import sentrai_extensions as se

sl = se.load_part(se.installed()["slack"], "core")
URL = "https://hooks.slack.com/services/T000/B000/xyz"


def test_slack_test_message():
    sent = []
    assert sl.slack_test(URL, lambda u, b, h: sent.append(b) or 200)["ok"] is True
    assert b"SentrAI test message" in sent[0]
    assert sl.slack_test("http://insecure", lambda *a: 200)["ok"] is False
    assert sl.slack_test(URL, lambda *a: 404)["ok"] is False


def test_row_and_test_button_never_show_the_url(make_core):
    c = make_core(SLACK_WEBHOOK_URL=URL)
    row = next(r for r in c.get("/extensions").json() if r["name"] == "slack")
    assert row["added"] and row["configured"] and row["testable"] and "hooks.slack.com" not in str(row)
    c.core.extensions.running["slack"].ext.poster = lambda u, b, h: 200
    assert c.post("/extensions/slack/test").json()["ok"] is True


def test_a_plain_http_url_is_not_set_up(make_core):
    c = make_core(SLACK_WEBHOOK_URL="http://hooks.example.test/x")
    row = next(r for r in c.get("/extensions").json() if r["name"] == "slack")
    assert row["configured"] is False and "https://" in row["detail"]
