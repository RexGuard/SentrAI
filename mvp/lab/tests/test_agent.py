"""The agent on each machine: joining a panel, and keeping the firewall equal to its block list."""
from __future__ import annotations

import json
import os

import pytest

from agent import agent


class FakeResponse:
    def __init__(self, status: int, body: dict):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


@pytest.fixture(autouse=True)
def agent_file(tmp_path, monkeypatch):
    monkeypatch.setenv("CACTAI_AGENT_FILE", str(tmp_path / "agent.json"))
    return tmp_path / "agent.json"


def test_panel_must_be_https():
    assert agent.check_panel_url("https://panel.example.com:8000/") == "https://panel.example.com:8000"
    assert agent.check_panel_url("http://127.0.0.1:8000") == "http://127.0.0.1:8000"
    with pytest.raises(agent.AgentError):
        agent.check_panel_url("http://panel.example.com:8000")
    assert agent.check_panel_url("http://10.0.0.5:8000", allow_http=True)
    with pytest.raises(agent.AgentError):
        agent.check_panel_url("panel.example.com")


def test_join_saves_the_key_privately(agent_file):
    sent = {}

    def post(url, json, timeout, verify):
        sent.update(url=url, body=json, verify=verify)
        return FakeResponse(200, {"agent_id": "abc123", "host": "web-01", "key": "sa_abc123.secret"})

    data = agent.join("https://panel.example.com", "ABCD-EFGH-JKLM", name="web-01", post=post)
    assert sent["url"] == "https://panel.example.com/fleet/enrol" and sent["body"]["host"] == "web-01"
    assert sent["verify"] is True
    saved = json.loads(agent_file.read_text())
    assert saved["key"] == "sa_abc123.secret" and saved["host"] == data["host"] == "web-01"
    if os.name == "posix":
        assert agent_file.stat().st_mode & 0o777 == 0o600


def test_join_refused_says_why(agent_file):
    def post(url, json, timeout, verify):
        return FakeResponse(403, {"detail": "join code is wrong, used or expired"})

    with pytest.raises(agent.AgentError, match="wrong, used or expired"):
        agent.join("https://panel.example.com", "NOPE", post=post)
    assert not agent_file.exists()


def recorder(rc=0):
    calls = []

    def run(args):
        calls.append(args)
        if args[:2] == ["iptables", "-C"]:
            return (0 if any(c[:2] == ["iptables", "-I"] and c[2:] == args[2:] for c in calls) else 1), ""
        return rc, ""

    return calls, run


def test_enforcer_adds_and_removes():
    calls, run = recorder()
    e = agent.Enforcer("iptables", True, {"127.0.0.1"}, runner=run)
    assert e.sync({"203.0.113.45"}) == {"added": ["203.0.113.45"], "removed": []}
    assert ["iptables", "-I", "INPUT", "-s", "203.0.113.45", "-m", "comment", "--comment", "cactai", "-j", "DROP"] in calls
    assert e.sync({"203.0.113.45"}) == {"added": [], "removed": []}  # nothing new: no commands
    assert e.sync(set()) == {"added": [], "removed": ["203.0.113.45"]}
    assert calls[-1][:2] == ["iptables", "-D"] and e.applied == set()


def test_enforcer_never_blocks_protected_or_the_panel():
    calls, run = recorder()
    e = agent.Enforcer("iptables", True, {"198.51.100.1"} | agent.panel_ips("https://192.0.2.10:8000"), runner=run)
    out = e.sync({"198.51.100.1", "192.0.2.10", "127.0.0.1", "203.0.113.9"})
    assert out["added"] == ["203.0.113.9"] and not any("192.0.2.10" in c for c in calls)
    assert any("protected" in line for line in e.log)


def test_enforcer_dry_run_runs_nothing():
    calls, run = recorder()
    e = agent.Enforcer("nftables", False, set(), runner=run)
    assert e.sync({"203.0.113.45"})["added"] == ["203.0.113.45"]
    assert calls == [] and any(line.startswith("dry run: nft add element") for line in e.log)


def test_offline_keeps_blocks_then_lets_go():
    now = [1000.0]
    calls, run = recorder()
    e = agent.Enforcer("iptables", True, set(), runner=run, hold_s=3600, clock=lambda: now[0])
    e.sync({"203.0.113.45"})
    now[0] += 1800
    assert e.sync(None) == {"added": [], "removed": []} and e.applied == {"203.0.113.45"}
    now[0] += 3600
    assert e.sync(None)["removed"] == ["203.0.113.45"] and e.applied == set()


def test_failed_block_is_not_counted():
    calls, run = recorder(rc=1)
    e = agent.Enforcer("iptables", True, set(), runner=run)
    assert e.sync({"203.0.113.45"})["added"] == [] and e.applied == set()
    assert any(line.startswith("failed") for line in e.log)


class FakeSession:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response, error, []

    def get(self, url, headers, timeout, verify):
        self.calls.append((url, headers))
        if self.error:
            raise self.error
        return self.response


def test_fetch_blocklist_uses_the_machine_key():
    data = {"panel": "https://panel.example.com", "key": "sa_x.y"}
    s = FakeSession(FakeResponse(200, {"ips": ["203.0.113.45"], "users": []}))
    assert agent.fetch_blocklist(data, s) == {"203.0.113.45"}
    assert s.calls[0] == ("https://panel.example.com/blocklist", {"Authorization": "Bearer sa_x.y"})
    assert agent.fetch_blocklist(data, FakeSession(error=agent.requests.ConnectionError())) is None
    assert agent.fetch_blocklist(data, FakeSession(FakeResponse(503, {}))) is None
    with pytest.raises(agent.AgentError, match="revoked"):
        agent.fetch_blocklist(data, FakeSession(FakeResponse(401, {})))


def test_cli_without_a_join(capsys):
    assert agent.main(["status"]) == 1
    assert "has not joined" in capsys.readouterr().out
