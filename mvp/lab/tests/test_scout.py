"""Scout: read-only folder tools, trails, the Claude loop (with a scripted fake) and the collector hook."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from collector.collector import DiscoveredLogSource, default_sources
from scout import sources
from scout.__main__ import main
import cactai_llm
from scout.agent import Scout
from scout.tools import SafeFS
from scout.trails import lessons, record


@pytest.fixture
def box(tmp_path):
    root = tmp_path / "server"
    (root / "var/log/nginx").mkdir(parents=True)
    (root / "var/log/auth.log").write_text(
        "Sep 28 10:00:01 web sshd[1]: Failed password for admin from 203.0.113.45 port 22\n"
        "Sep 28 10:00:02 web sshd[1]: Accepted password=hunter2 for erick from 10.0.0.5\n")
    (root / "var/log/nginx/access.log").write_text('203.0.113.45 - - "GET /search?q=1 HTTP/1.1" 200\n')
    (root / "var/log/nginx/access.log.1").write_text("old\n")
    (root / "etc").mkdir()
    return root


def test_fs_is_read_only_and_confined(box, tmp_path):
    fs = SafeFS([box])
    assert "[dir]  nginx/" in fs.list_dir("var/log")
    with pytest.raises(PermissionError):
        fs.list_dir(str(tmp_path))
    with pytest.raises(PermissionError):
        fs.peek_file("var/log/../../../outside.txt")
    peek = fs.peek_file("var/log/auth.log", 5)
    assert "Failed password for admin" in peek and "hunter2" not in peek
    assert fs.find_files("*.log").count("\n") == 1  # auth.log and access.log, not access.log.1


def test_record_trail_becomes_a_lesson(box, tmp_path):
    fs = SafeFS([box])
    cmds = iter(["cd var/log", "ls", "peek auth.log 3", "pick auth.log os ssh logins with IPs",
                 "note skip rotated .1 files", "quit"])
    path = record(fs, "find login logs", actor="expert", ask=lambda _: next(cmds), say=lambda _: None,
                  trails_dir=tmp_path / "trails")
    steps = [json.loads(l) for l in path.read_text().splitlines()]
    assert [s["action"] for s in steps] == ["goal", "cd", "ls", "peek", "pick", "note"]
    text = lessons(tmp_path / "trails")
    assert "chose" in text and "auth.log as os because ssh logins with IPs" in text
    assert "skip rotated" in text


def tool_use(i, name, **inp):
    return NS(type="tool_use", id=f"tu{i}", name=name, input=inp)


class FakeClaude:
    """Replays a scripted conversation and records what Scout sent."""

    def __init__(self, turns):
        self.turns = list(turns)
        self.calls = []
        self.messages = self

    def create(self, **kw):
        self.calls.append(kw)
        content, stop = self.turns.pop(0)
        return NS(content=content, stop_reason=stop)


def test_scout_browses_asks_and_proposes(box, tmp_path):
    fs = SafeFS([box])
    auth = str(box / "var/log/auth.log")
    fake = FakeClaude([
        ([NS(type="text", text="Linux keeps logs in /var/log, so I'll start there."),
          tool_use(1, "list_dir", path=str(box / "var/log"))], "tool_use"),
        ([tool_use(2, "peek_file", path=auth, lines=5, from_end=True),
          tool_use(3, "ask_technician", question="Is this the portal server?")], "tool_use"),
        ([tool_use(4, "propose_source", path=auth, layer="os", format="text", why="shows password guessing"),
          tool_use(5, "propose_source", path="/etc/shadow", layer="os", format="text", why="x")], "tool_use"),
        ([NS(type="text", text="Done: I proposed auth.log.")], "end_turn"),
    ])
    said = []
    scout = Scout(fs, provider=cactai_llm.AnthropicProvider(client=fake), trails_dir=tmp_path / "trails", ask=lambda q: "yes", say=said.append)
    found = scout.run("where are the login logs?")
    assert found == [{"path": auth, "layer": "os", "format": "text", "why": "shows password guessing"}]
    assert said[0].startswith("Linux keeps logs")
    # Tool results went back in one user message per turn; the path outside the roots came back as an error.
    msgs = fake.calls[-1]["messages"]  # user, then (assistant, tool results) per turn
    assert msgs[6]["content"][0]["content"].startswith("Proposed") and msgs[6]["content"][1]["is_error"]
    assert msgs[4]["content"][1]["content"] == "yes"
    assert "(no trails recorded yet)" in fake.calls[0]["system"]
    assert [s["action"] for s in scout.steps] == ["ls", "peek", "note"]


def test_find_command_saves_confirmed_sources_and_trail(box, tmp_path, monkeypatch):
    auth = str(box / "var/log/auth.log")
    access = str(box / "var/log/nginx/access.log")
    fake = FakeClaude([
        ([tool_use(1, "propose_source", path=auth, layer="os", format="text", why="logins"),
          tool_use(2, "propose_source", path=access, layer="web", format="text", why="web requests")], "tool_use"),
        ([NS(type="text", text="Done.")], "end_turn"),
    ])
    trails = tmp_path / "trails"
    monkeypatch.setattr("scout.agent.TRAILS_DIR", trails)
    monkeypatch.setattr("scout.trails.TRAILS_DIR", trails)
    monkeypatch.setattr("scout.agent.cactai_llm.from_env", lambda **_: cactai_llm.AnthropicProvider(client=fake))
    monkeypatch.setattr("scout.trails.Trail.__init__.__defaults__", (trails,))
    answers = iter(["y", "n", "that is a test server"])
    monkeypatch.setattr("builtins.input", lambda *_: next(answers))
    main(["find", "--root", str(box), "--who", "novice", "where are the logs?"])
    saved = sources.load()
    assert [s["path"] for s in saved] == [auth] and saved[0]["confirmed_by"] == "novice"
    text = lessons(trails)
    assert "chose" in text and "auth.log" in text and "not " + access in text


def test_collector_watches_approved_files(box):
    sources.add({"path": str(box / "var/log/auth.log"), "layer": "os", "format": "text", "why": "logins"}, "t")
    src = next(s for s in default_sources(box) if isinstance(s, DiscoveredLogSource))
    events = src.poll()
    assert len(events) == 2
    assert events[0]["src_ip"] == "203.0.113.45" and events[0]["user"] == "admin"
    assert events[0]["layer"] == "os" and events[0]["source"] == "scout:auth.log"
    with open(box / "var/log/auth.log", "a") as fh:
        fh.write('Sep 28 10:05:00 web sshd[1]: Failed password for root from 198.51.100.7\n')
    assert src.poll()[0]["src_ip"] == "198.51.100.7"


def test_jsonl_fields_win_over_text_guesses(tmp_path):
    f = tmp_path / "app.jsonl"
    f.write_text(json.dumps({"client_ip": "198.51.100.9", "username": "amy", "msg": "login 10.0.0.1"}) + "\n")
    ev = DiscoveredLogSource(f, "web", "jsonl").poll()[0]
    assert ev["src_ip"] == "198.51.100.9" and ev["user"] == "amy"


@pytest.fixture(autouse=True)
def _clean_sources():
    yield
    Path(sources.sources_file()).unlink(missing_ok=True)


def test_running_collector_picks_up_newly_approved_files_from_their_end(box, tmp_path):
    from collector.collector import Collector

    c = Collector("http://127.0.0.1:9", tmp_path / "logs")
    c.collect()
    assert not any(isinstance(s, DiscoveredLogSource) for s in c.sources)
    import time
    time.sleep(0.01)
    sources.add({"path": str(box / "var/log/auth.log"), "layer": "os", "format": "text"}, "process scan")
    c.pending.clear()
    c.collect()  # the two old lines are history, not new events
    assert [s.name for s in c.sources if isinstance(s, DiscoveredLogSource)] == ["auth.log"]
    assert not [e for e in c.pending if e["source"] == "scout:auth.log"]
    with open(box / "var/log/auth.log", "a") as fh:
        fh.write("Sep 28 10:06:00 web sshd[1]: Failed password for root from 198.51.100.9\n")
    c.collect()
    assert [e["src_ip"] for e in c.pending if e["source"] == "scout:auth.log"] == ["198.51.100.9"]
    assert type(c.sources[-1]).__name__ == "HeartbeatSource"
