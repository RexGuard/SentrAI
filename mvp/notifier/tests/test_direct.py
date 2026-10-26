"""Personal Telegram alerts: who gets each message, fallbacks, and delivery receipts per person."""

import pytest

from direct import Target, deliver, group_mode, plan, receipts
from formatting import format_telegram
from notifier import process_pending, with_email

GROUP = "-100500"
AMIR = {"id": "amir", "name": "Amir", "telegram": "@amir", "telegram_chat": "111"}
LEE = {"id": "lee", "name": "Lee", "telegram": "@lee", "telegram_chat": ""}
ALERT = {"id": "ntf-0001", "incident": "RSK-1", "kind": "incident_opened", "title": "Brute force",
         "deliver_to": [AMIR, LEE]}


def test_linked_people_get_it_directly_and_the_group_covers_the_rest():
    assert plan(ALERT, GROUP) == [Target("111", "Amir"), Target(GROUP, None)]
    only_amir = {**ALERT, "deliver_to": [AMIR]}
    assert plan(only_amir, GROUP) == [Target("111", "Amir")]  # nobody left out: the group stays quiet
    assert plan(only_amir, GROUP, "always") == [Target("111", "Amir"), Target(GROUP, None)]
    assert plan(ALERT, GROUP, "off") == [Target("111", "Amir")]


def test_notices_and_unlinked_alerts_still_go_to_the_group():
    assert plan({"id": "n", "kind": "audit_anchor"}, GROUP, "off") == [Target(GROUP, None)]
    assert plan({**ALERT, "deliver_to": [LEE]}, GROUP, "off") == [Target(GROUP, None)]
    twice = {**ALERT, "deliver_to": [AMIR, {**AMIR, "name": "Amir again"}]}
    assert plan(twice, GROUP) == [Target("111", "Amir")]
    assert group_mode("ALWAYS") == "always" and group_mode("nonsense") == "fallback" and group_mode(None) == "fallback"


def test_a_blocked_direct_message_falls_back_to_the_group_once():
    sent = []

    def send_one(t):
        if t.chat_id in ("111", "222"):
            raise PermissionError("Forbidden: bot was blocked by the user")
        sent.append(t.chat_id)
        return f"m{len(sent)}"

    targets = [Target("111", "Amir"), Target("222", "Ika"), Target(GROUP, None)]
    assert deliver(targets, send_one, GROUP) == [("telegram", "m1", None)]
    assert sent == [GROUP]


def test_nothing_sent_raises_so_the_alert_stays_pending():
    def broken(t):
        raise ConnectionError("telegram down")

    with pytest.raises(ConnectionError):
        deliver([Target("111", "Amir")], broken, GROUP)


def test_each_person_gets_their_own_receipt():
    class Core:
        marked = []

        def risk(self):
            return None

        def pending(self):
            return [ALERT]

        def incident(self, iid):
            return {"id": iid, "status": "open"}

        def delivered(self, nid, channel, message_id, to=None):
            self.marked.append((nid, channel, message_id, to))

    def send(n, inc, risk):
        return deliver(plan(n, GROUP), lambda t: f"msg-{t.chat_id}", GROUP)

    def email(n, inc, risk):
        return "email-1"

    core = Core()
    assert process_pending(core, with_email(send, "telegram", email, always=True), "telegram") == ["ntf-0001"]
    assert core.marked == [("ntf-0001", "telegram-direct", "msg-111", "Amir"),
                           ("ntf-0001", "telegram", f"msg-{GROUP}", None),
                           ("ntf-0001", "email", "email-1", None)]
    assert receipts("42", "console") == [("console", "42", None)]
    assert receipts(("email", "9"), "telegram") == [("email", "9", None)]


def test_a_direct_message_does_not_mention_people():
    group = format_telegram(ALERT, {"id": "RSK-1", "status": "open"})
    mine = format_telegram(ALERT, {"id": "RSK-1", "status": "open"}, personal=True)
    assert "For: @amir @lee" in group and "For:" not in mine


def test_a_slack_copy_adds_one_receipt_to_the_direct_ones():
    from slack import with_slack
    send = with_slack(lambda n, i, r: deliver(plan(n, GROUP), lambda t: f"msg-{t.chat_id}", GROUP),
                      lambda n, i, r: f"slack-{n['id']}")
    assert send(ALERT, None, None)[-1] == ("slack", "slack-ntf-0001", None)
