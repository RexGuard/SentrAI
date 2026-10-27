"""/report in Telegram: who may send it, and what the reporter is told back."""

import sentrai_extensions as se
from core import CoreError

tg = se.load_part(se.installed()["telegram"], "notifier")
report_allowed, staff_report_reply = tg.report_allowed, tg.staff_report_reply


class FakeCore:
    def __init__(self, answer=None, down=False):
        self.answer, self.down, self.sent = answer, down, []

    def staff_report(self, text, reporter, sender, channel="telegram"):
        if self.down:
            raise CoreError("core unreachable")
        self.sent.append((text, reporter, sender))
        return self.answer


def test_who_may_report():
    assert report_allowed("100", "100", None)
    assert not report_allowed("200", "100", None)
    assert report_allowed("200", "100", "any")
    assert report_allowed("200", "100", "200, 300") and report_allowed("100", "100", "200")
    assert not report_allowed("400", "100", "200,300")


def test_reply_gives_the_advice():
    core = FakeCore({"id": "SR-2026-004", "kind_label": "Suspicious email, message or link", "urgency": "high",
                     "advice": ["Do not click any link.", "Change your password now."]})
    reply = staff_report_reply(core, "  I clicked a link in an odd email ", "mei", "555")
    assert core.sent == [("I clicked a link in an odd email", "mei", "telegram:555")]
    assert "SR-2026-004" in reply and "urgent" in reply and "1. Do not click any link." in reply


def test_reply_on_empty_refused_or_down():
    assert "/report I got an email" in staff_report_reply(FakeCore(), "", "mei", "1")
    assert staff_report_reply(FakeCore({"error": "Too many reports"}), "x" * 20, "mei", "1") == "⚠️ Too many reports"
    assert "tell your IT contact" in staff_report_reply(FakeCore(down=True), "x" * 20, "mei", "1")
