"""Which alert extensions run, and switching between them without a restart. A fake core stands in for the
real one and a "pager" extension in its own folder stands in for Telegram: nothing is sent anywhere."""
from __future__ import annotations

import json
import logging

import pytest

import sentrai_extensions as se
from core import CoreError
from notifier import Channels, run

UNREACHABLE = CoreError("core unreachable at http://core.test: ConnectionError")

PAGER = '''
EVENTS = []


def main_channel(ctx):
    token = ctx.setting("PAGER_TOKEN")
    if not token:
        return None
    if token == "wrong":
        def broken():
            raise RuntimeError("the pager service said: bad token")
        return broken

    def run():
        EVENTS.append(("start", token))
        seen = set()
        send = ctx.with_copies(lambda n, i, r: ("pager", "pg-" + n["id"]))
        for _ in range(50):
            ctx.process_pending(send, "pager", seen)
            if ctx.changed():
                EVENTS.append(("switch", token))
                return
            if ctx.setting("PAGER_STOP"):  # stands in for Ctrl+C
                EVENTS.append(("stopped", token))
                return
        raise AssertionError("the pager never stopped")
    return run
'''

MIRROR = '''
def copy_channel(ctx):
    sent = ctx.manifest.path / "sent.txt"

    def send(n, incident, risk):
        with sent.open("a", encoding="utf-8") as f:
            f.write(n["id"] + "\\n")
        return "mirror-" + n["id"]
    return send
'''


def extension(base, name, code, settings=(), on_when=()):
    folder = base / name
    folder.mkdir(parents=True)
    (folder / "extension.json").write_text(json.dumps({
        "name": name, "title": name.title(), "kind": "Alerts", "what": f"{name} alerts for the tests.",
        "settings": [{"env": env, "prompt": env} for env in settings], "on_when": list(on_when)}), encoding="utf-8")
    (folder / "notifier.py").write_text(code, encoding="utf-8")
    return folder


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


class FakeCore:
    """Serves the alerts and the extension rows; `steps` run one per pending() call to script a story."""
    base_url = "http://core.test"

    def __init__(self, rows=None, error=None, steps=()):
        self.rows = list(rows or [])
        self.error = error
        self.alerts: list[dict] = []
        self.marked: list[tuple[str, str]] = []
        self.steps = list(steps)
        self.calls = 0

    def extensions(self):
        if self.error is not None:
            raise self.error
        return [dict(r) for r in self.rows]

    def pending(self):
        self.calls += 1
        if self.calls > 40:
            raise AssertionError("the notifier kept running after the story ended")
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

    def alert(self, nid):
        self.alerts.append({"id": nid, "kind": "notice", "title": f"Alert {nid}", "text": "test"})


@pytest.fixture(autouse=True)
def _no_witness_file(tmp_path, monkeypatch):
    monkeypatch.setenv("NOTIFIER_WITNESS_FILE", str(tmp_path / "witness.txt"))


def test_the_core_decides_which_alert_extensions_run():
    core = FakeCore([{"name": "telegram", "added": True}, {"name": "slack", "added": False},
                     {"name": "cloudflare", "added": True}])
    ch = Channels(core, environ={})
    assert ch.names == ["telegram"] and ch.source == "core"  # Cloudflare has nothing to run in the notifier


def test_an_older_core_leaves_it_to_the_settings():
    core = FakeCore(error=CoreError("GET /extensions -> HTTP 404", "Not Found", 404))
    slack = {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T/B/x"}
    ch = Channels(core, environ=slack)
    assert ch.names == ["slack"] and ch.source == "settings"
    assert Channels(core, environ={**slack, "SENTRAI_EXTENSIONS": "none"}).names == []


def test_while_the_core_is_away_its_last_answer_holds():
    clock = Clock()
    core = FakeCore(error=UNREACHABLE)
    ch = Channels(core, environ={"TELEGRAM_BOT_TOKEN": "123:abc"}, clock=clock)
    assert ch.names == ["telegram"] and ch.source == "settings"  # never reached yet: the settings decide
    core.error, core.rows = None, [{"name": "telegram", "added": False}, {"name": "slack", "added": True}]
    clock.t = 15
    assert ch.changed() and ch.names == ["slack"] and ch.source == "core"
    ch.settle()
    core.error = UNREACHABLE
    clock.t = 30
    assert not ch.changed() and ch.names == ["slack"] and ch.source == "last"


def test_it_asks_at_most_every_15_seconds_and_a_new_token_is_a_change():
    env = {"TELEGRAM_BOT_TOKEN": "123:abc", "TELEGRAM_CHAT_ID": "-1001"}
    clock, reloads = Clock(), []
    ch = Channels(FakeCore([{"name": "telegram", "added": True}]), environ=env, clock=clock,
                  reload=lambda: reloads.append(clock.t))
    env["TELEGRAM_BOT_TOKEN"] = "456:def"
    clock.t = 14
    assert not ch.changed() and reloads == []
    clock.t = 15
    assert ch.changed() and reloads == [15] and ch.names == ["telegram"]
    assert ch.changed()  # until the runner has started again
    ch.settle()
    clock.t = 30
    assert not ch.changed()


def test_a_half_written_settings_file_is_read_again_later(caplog):
    def reload():
        raise ValueError("Expecting value: line 1 column 1")

    clock = Clock()
    ch = Channels(FakeCore([]), environ={}, clock=clock, reload=reload)
    clock.t = 15
    with caplog.at_level(logging.WARNING, logger="sentrai.notifier"):
        assert not ch.changed()
    assert "could not re-read the settings" in caplog.text


def test_adding_and_removing_switches_the_channel_without_a_restart(tmp_path, capsys):
    base = tmp_path / "ext"
    extension(base, "pager", PAGER, settings=["PAGER_TOKEN"], on_when=["PAGER_TOKEN"])
    env = {"SENTRAI_EXTENSIONS_DIR": str(base), "PAGER_TOKEN": "t1"}
    clock = Clock()
    core = FakeCore([{"name": "pager", "added": True}])

    def remove():
        core.rows, clock.t = [{"name": "pager", "added": False}], 15

    def add_with_new_token():
        core.rows, clock.t = [{"name": "pager", "added": True}], 30
        env["PAGER_TOKEN"] = "t2"

    def stop():
        env["PAGER_STOP"] = "1"

    core.steps = [lambda: core.alert("ntf-1"),  # the pager sends it
                  remove,  # removed on the dashboard: the pager stops
                  lambda: core.alert("ntf-2"),  # the console prints it
                  add_with_new_token,  # added back with a new token: the pager starts again with it
                  lambda: core.alert("ntf-3"),
                  stop]
    channels = Channels(core, environ=env, clock=clock)
    run(core, 0, "operator", channels=channels)

    pager = se.load_part(se.installed(env)["pager"], "notifier")
    assert pager.EVENTS == [("start", "t1"), ("switch", "t1"), ("start", "t2"), ("stopped", "t2")]
    assert core.marked == [("ntf-1", "pager"), ("ntf-2", "console"), ("ntf-3", "pager")]
    assert "CONSOLE mode" in capsys.readouterr().out


def test_a_channel_that_cannot_start_hands_over_to_the_console(tmp_path, caplog):
    base = tmp_path / "ext"
    extension(base, "pager", PAGER, settings=["PAGER_TOKEN"], on_when=["PAGER_TOKEN"])
    env = {"SENTRAI_EXTENSIONS_DIR": str(base), "PAGER_TOKEN": "wrong"}
    clock = Clock()
    core = FakeCore([{"name": "pager", "added": True}])

    def fix_token():
        env["PAGER_TOKEN"], clock.t = "t1", 15

    core.steps = [lambda: core.alert("ntf-1"), fix_token, lambda: env.setdefault("PAGER_STOP", "1")]
    with caplog.at_level(logging.ERROR, logger="sentrai.notifier"):
        run(core, 0, "operator", channels=Channels(core, environ=env, clock=clock))

    pager = se.load_part(se.installed(env)["pager"], "notifier")
    assert "alerts go to the console until the settings change" in caplog.text
    assert core.marked == [("ntf-1", "console")]  # not lost while the token was wrong
    assert pager.EVENTS == [("start", "t1"), ("stopped", "t1")]


def test_copies_go_out_next_to_the_console_and_a_broken_extension_is_skipped(tmp_path, caplog, capsys):
    base = tmp_path / "ext"
    mirror = extension(base, "mirror", MIRROR)
    extension(base, "broken", "import a_package_that_is_not_installed\n")
    env = {"SENTRAI_EXTENSIONS_DIR": str(base), "SENTRAI_EXTENSIONS": "mirror,broken"}
    core = FakeCore(error=CoreError("GET /extensions -> HTTP 404", "Not Found", 404), steps=[lambda: core.alert("ntf-1")])
    channels = Channels(core, environ=env)
    assert channels.names == ["broken", "mirror"]
    with caplog.at_level(logging.ERROR, logger="sentrai.notifier"):
        run(core, 0, "operator", once=True, channels=channels)
    assert "broken extension's notifier part could not load" in caplog.text
    assert core.marked == [("ntf-1", "console")]
    assert (mirror / "sent.txt").read_text(encoding="utf-8") == "ntf-1\n"
    assert "a copy of each alert goes to mirror" in capsys.readouterr().out
