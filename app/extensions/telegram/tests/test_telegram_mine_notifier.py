""""This was me" in Telegram: what the core is told when the button is pressed, and what the chat is told back.
A fake core stands in for the real one: nothing is sent anywhere."""

import pytest

import sentrai_extensions as se
from core import CoreError

tg = se.load_part(se.installed()["telegram"], "notifier")
button_reply, error_reply, mine_reply = tg.button_reply, tg.error_reply, tg.mine_reply

KEY = "SHA256:Q7w3cZk2u5Yd9bJm1LxkfA0Hn6Rr8PtEoSvNqGiCz4U"
LEARNED = ["address 203.0.113.5", f"SSH key {KEY[:19]}…", "account erick on web-01"]


class FakeCore:
    """Records the verbs the bot sends and answers each with `answer`, or refuses with `refuse` (a CoreError)."""

    def __init__(self, answer=None, refuse=None):
        self.answer, self.refuse, self.calls = answer, refuse, []

    def _call(self, name, *args):
        self.calls.append((name, *args))
        if self.refuse is not None:
            raise self.refuse
        return self.answer

    def mine(self, iid, operator, channel):
        return self._call("mine", iid, operator, channel)

    def decision(self, iid, operator, decision, justification):
        return self._call("decision", iid, operator, decision, justification)

    def assign(self, iid, assignee, operator, note=None):
        return self._call("assign", iid, assignee, operator, note)

    def rollback(self, iid, operator, justification):
        return self._call("rollback", iid, operator, justification)

    def permanent(self, iid, operator, justification):
        return self._call("permanent", iid, operator, justification)


def test_this_was_me_teaches_the_core_as_the_telegram_user():
    core = FakeCore({"id": "RSK-2026-012", "status": "resolved", "resolved_by": "erick", "learned": LEARNED,
                     "also_closed": ["RSK-2026-013"]})
    reply = button_reply(core, "mine", "RSK-2026-012", "erick", "10:21:00", "unauthorised_admin")
    assert core.calls == [("mine", "RSK-2026-012", "erick", "telegram")]
    assert reply == ("✋ RSK-2026-012: erick said this was them at 10:21:00.\n"
                     f"SentrAI now knows: address 203.0.113.5, SSH key {KEY[:19]}…, account erick on web-01. "
                     "Alert closed.\n"
                     "Also closed with it: RSK-2026-013.")
    nothing_new = mine_reply("RSK-2026-012", "erick", "10:21:00", {"learned": [], "also_closed": []})
    assert "already knew this sign-in" in nothing_new and "Alert closed" in nothing_new
    assert "Also closed" not in nothing_new


def test_the_cores_reasons_are_passed_on_in_plain_words():
    closed = CoreError("POST /incidents/RSK-2026-012/mine -> HTTP 409: {...}", "RSK-2026-012 is already resolved", 409)
    with pytest.raises(CoreError):
        button_reply(FakeCore(refuse=closed), "mine", "RSK-2026-012", "erick", "10:21:00")
    assert error_reply("RSK-2026-012", closed) == "❌ RSK-2026-012: RSK-2026-012 is already resolved"
    off = CoreError("POST /incidents/RSK-2026-012/mine -> HTTP 400: {...}",
                    "ADMIN_SESSIONS is off: SentrAI is not keeping track of the administrators", 400)
    assert error_reply("RSK-2026-012", off) == ("❌ RSK-2026-012: ADMIN_SESSIONS is off: SentrAI is not keeping "
                                                "track of the administrators")
    down = CoreError("core unreachable at http://core.test: ConnectionError")
    assert error_reply("RSK-2026-012", down) == "❌ RSK-2026-012: core unreachable at http://core.test: ConnectionError"


def test_not_me_is_the_approve_verb_with_its_own_words():
    core = FakeCore({"id": "RSK-2026-012", "status": "contained", "category": "unauthorised_admin",
                     "actions": [{"type": "block_ip", "target": "203.0.113.8", "status": "active"},
                                 {"type": "lock_user", "target": "erick", "status": "active"},
                                 {"type": "block_ip", "target": "203.0.113.7", "status": "rolled_back"}]})
    reply = button_reply(core, "approve", "RSK-2026-012", "amir", "10:22:00", "unauthorised_admin")
    assert core.calls == [("decision", "RSK-2026-012", "amir", "approve", "Not me: block it (via Telegram)")]
    assert reply == ("🚫 RSK-2026-012: amir said this was not them at 10:22:00. That sign-in is no longer trusted; "
                     "applied: block_ip 203.0.113.8, lock_user erick.")
    # On any other incident the approve verb is Approve & Patch, as before.
    core = FakeCore({"id": "RSK-1", "status": "contained"})
    reply = button_reply(core, "approve", "RSK-1", "amir", "10:23:00", "brute_force")
    assert reply == "✅ RSK-1 approved & patch applied by amir at 10:23:00"
    assert core.calls == [("decision", "RSK-1", "amir", "approve", "Approved via Telegram")]


def test_the_other_verbs_are_unchanged():
    core = FakeCore({})
    assert "RSK-1 taken by amir" in button_reply(core, "take", "RSK-1", "amir", "10:00:00")
    assert "RSK-1 rolled back by amir" in button_reply(core, "rollback", "RSK-1", "amir", "10:00:00")
    assert "RSK-1 made permanent by amir" in button_reply(core, "permanent", "RSK-1", "amir", "10:00:00")
    assert core.calls == [("assign", "RSK-1", "amir", "amir", "Taken via Telegram"),
                          ("rollback", "RSK-1", "amir", "Rolled back via Telegram"),
                          ("permanent", "RSK-1", "amir", "Made permanent via Telegram")]
    with pytest.raises(ValueError):
        button_reply(core, "reject", "RSK-1", "amir", "10:00:00")  # Reject asks for a justification in the chat first
