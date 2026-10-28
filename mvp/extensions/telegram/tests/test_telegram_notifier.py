"""Telegram extension, notifier side: who gets each message, fallbacks, delivery receipts per person, and
when the bot runs at all."""

import json
import os
import signal
from types import SimpleNamespace

import pytest

import sentrai_extensions as se
from core import CoreError
from notifier import process_pending, receipts, with_copies, with_email

tg = se.load_part(se.installed()["telegram"], "notifier")
Target, deliver, group_mode, plan = tg.Target, tg.deliver, tg.group_mode, tg.plan

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


def test_a_slack_copy_adds_one_receipt_to_the_direct_ones():
    send = with_copies(lambda n, i, r: deliver(plan(n, GROUP), lambda t: f"msg-{t.chat_id}", GROUP),
                       [("slack", lambda n, i, r: f"slack-{n['id']}")])
    assert send(ALERT, None, None)[-1] == ("slack", "slack-ntf-0001", None)


def _ctx(**settings):
    return SimpleNamespace(setting=lambda env: settings.get(env, ""))


def test_the_bot_needs_both_the_token_and_the_group_chat():
    assert tg.main_channel(_ctx()) is None
    assert tg.main_channel(_ctx(TELEGRAM_BOT_TOKEN="123:abc")) is None  # no group chat: console, as before
    assert callable(tg.main_channel(_ctx(TELEGRAM_BOT_TOKEN="123:abc", TELEGRAM_CHAT_ID="-1001")))


def test_links_are_empty_while_the_core_has_telegram_removed():
    class Core:
        def request(self, method, path, body=None):
            raise CoreError("GET /telegram/links -> HTTP 404", "Telegram is not added.", 404)

    assert tg.telegram_links(Core()) == []

    class Linked:
        def request(self, method, path, body=None):
            return [{"chat_id": "111", "name": "Amir"}, "junk"]

    assert tg.telegram_links(Linked()) == [{"chat_id": "111", "name": "Amir"}]


# ------------------------------------------------------------------ the real bot against a fake Bot API

class FakeBotAPI:
    """Answers the few Bot API calls the bot makes, on 127.0.0.1. Nothing reaches Telegram."""

    def __init__(self):
        import http.server
        import threading

        self.sent: list[dict] = []
        self.updates: list[dict] = []  # what the next getUpdates hands the bot (a button press, say)
        api = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                import json as _json
                import time as _time
                import urllib.parse

                size = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(size).decode("utf-8") if size else ""
                kind = self.headers.get("Content-Type", "")
                body = _json.loads(raw) if "json" in kind and raw else dict(urllib.parse.parse_qsl(raw))
                method = self.path.rsplit("/", 1)[-1]
                if method == "getMe":
                    result = {"id": 42, "is_bot": True, "first_name": "SentrAI", "username": "sentrai_test_bot"}
                elif method == "getUpdates":
                    _time.sleep(0.05)
                    result = [api.updates.pop(0)] if api.updates else []
                elif method == "sendMessage":
                    api.sent.append(body)
                    result = {"message_id": len(api.sent), "date": 1761550000,
                              "chat": {"id": int(body.get("chat_id", 0)), "type": "supergroup", "title": "Team"},
                              "text": str(body.get("text", ""))}
                else:
                    result = True
                out = _json.dumps({"ok": True, "result": result}).encode()
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(out)))
                    self.end_headers()
                    self.wfile.write(out)
                except OSError:  # the bot stopped waiting for its long poll
                    pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/bot"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class StoryCore:
    """A core whose `steps` run one per poll, to script what happens while the notifier runs."""
    base_url = "http://core.test"

    def __init__(self, rows, steps):
        self.rows, self.steps = rows, list(steps)
        self.alerts, self.marked, self.calls = [], [], 0
        self.acked, self.mined = [], []

    def extensions(self):
        return [dict(r) for r in self.rows]

    def request(self, method, path, body=None):
        return []  # no personal chats linked

    def pending(self):
        self.calls += 1
        if self.calls > 400:
            raise KeyboardInterrupt  # a story that never ends: stop as Ctrl+C would
        if self.steps:
            self.steps.pop(0)()
        done = {nid for nid, _ in self.marked}
        return [a for a in self.alerts if a["id"] not in done]

    def risk(self):
        return None

    def incident(self, iid):
        return None

    def delivered(self, nid, channel, message_id, to=None):
        self.marked.append((nid, channel))

    def ack(self, iid, operator, channel):
        self.acked.append((iid, operator, channel))
        return {"id": iid, "status": "open", "category": "unauthorised_admin"}

    def mine(self, iid, operator, channel):
        self.mined.append((iid, operator, channel))
        return {"id": iid, "status": "resolved", "resolved_by": operator,
                "learned": ["address 203.0.113.5", "account erick on web-01"], "also_closed": ["RSK-2"]}


def test_removing_telegram_stops_the_bot_and_the_console_takes_over(monkeypatch, tmp_path):
    pytest.importorskip("telegram")
    from telegram.ext import Application, ApplicationBuilder

    from notifier import Channels, run

    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    monkeypatch.setenv("NOTIFIER_WITNESS_FILE", str(tmp_path / "witness.txt"))
    api = FakeBotAPI()
    monkeypatch.setattr(Application, "builder", staticmethod(lambda: ApplicationBuilder().base_url(api.url)))
    clock = [0.0]
    env = {"TELEGRAM_BOT_TOKEN": "123:abc", "TELEGRAM_CHAT_ID": "-1001"}
    core = StoryCore([{"name": "telegram", "added": True}], [])
    seen_in_console = {}

    def alert(nid):
        return lambda: core.alerts.append({"id": nid, "kind": "notice", "title": f"Alert {nid}", "text": "test"})

    def remove():
        if not core.marked:  # wait until the bot has sent the first alert
            core.steps.insert(0, remove)
            return
        core.rows, clock[0] = [{"name": "telegram", "added": False}], 15.0

    def in_console():
        seen_in_console["sigint"] = signal.getsignal(signal.SIGINT)
        alert("ntf-2")()

    def ctrl_c():
        if len(core.marked) < 2:
            core.steps.insert(0, ctrl_c)
            return
        raise KeyboardInterrupt

    core.steps = [alert("ntf-1"), remove, in_console, ctrl_c]
    channels = Channels(core, environ=env, clock=lambda: clock[0])
    try:
        with pytest.raises(KeyboardInterrupt):
            run(core, 0.01, "operator", channels=channels)
    finally:
        api.close()
    assert core.marked == [("ntf-1", "telegram"), ("ntf-2", "console")]
    assert [m["chat_id"] for m in api.sent] == ["-1001"] and "<b>ntf-1</b>" in api.sent[0]["text"]
    if os.name == "posix":  # the bot's stop signal handlers went with its event loop: Ctrl+C works again
        assert seen_in_console["sigint"] is signal.default_int_handler


@pytest.mark.skipif(os.name != "posix", reason="sends itself a real Ctrl+C (SIGINT)")
def test_pressing_this_was_me_teaches_the_core_and_confirms_in_the_chat(monkeypatch, tmp_path):
    pytest.importorskip("telegram")
    from telegram.ext import Application, ApplicationBuilder

    from notifier import Channels, run

    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    monkeypatch.setenv("NOTIFIER_WITNESS_FILE", str(tmp_path / "witness.txt"))
    api = FakeBotAPI()
    monkeypatch.setattr(Application, "builder", staticmethod(lambda: ApplicationBuilder().base_url(api.url)))
    env = {"TELEGRAM_BOT_TOKEN": "123:abc", "TELEGRAM_CHAT_ID": "-1001"}
    core = StoryCore([{"name": "telegram", "added": True}], [])
    ask = {"id": "ntf-1", "incident": "RSK-1", "kind": "was_this_you", "risk_index": 41,
           "title": "Root access from an unrecognised sign-in", "text": "Was this you?",
           "buttons": [{"label": "This was me", "action": "mine"}, {"label": "Not me: block it", "action": "approve"},
                       {"label": "Acknowledge", "action": "ack"}]}

    def press():
        if not api.sent:  # wait until the alert, with its keyboard, is in the chat
            core.steps.insert(0, press)
            return
        api.updates.append({"update_id": 1, "callback_query": {
            "id": "cq-1", "chat_instance": "ci-1", "data": "mine:RSK-1",
            "from": {"id": 7, "is_bot": False, "first_name": "Erick", "username": "erick"},
            "message": {"message_id": 1, "date": 1761550000, "text": api.sent[0]["text"],
                        "chat": {"id": -1001, "type": "supergroup", "title": "Team"}}}})

    def ctrl_c():
        if not core.mined or len(api.sent) < 2:
            core.steps.insert(0, ctrl_c)
            return
        os.kill(os.getpid(), signal.SIGINT)

    core.steps = [lambda: core.alerts.append(ask), press, ctrl_c]
    try:
        # While the bot runs, Ctrl+C is the bot's own stop signal: the bot shuts down and run() returns
        # (the notifier's main() then prints "notifier stopped."), so nothing is raised here.
        run(core, 0.01, "operator", channels=Channels(core, environ=env, clock=lambda: 0.0))
    finally:
        api.close()
    keyboard = json.loads(api.sent[0]["reply_markup"])["inline_keyboard"]
    assert [(b["text"], b["callback_data"]) for b in keyboard[0]] == [
        ("✋ This was me", "mine:RSK-1"), ("🚫 Not me: block it", "approve:RSK-1"), ("🙋 Take it", "take:RSK-1")]
    assert core.acked == [("RSK-1", "erick", "telegram")] and core.mined == [("RSK-1", "erick", "telegram")]
    assert "SentrAI now knows: address 203.0.113.5, account erick on web-01. Alert closed." in api.sent[1]["text"]
    assert "Also closed with it: RSK-2." in api.sent[1]["text"]
