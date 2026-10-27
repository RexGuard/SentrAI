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
    monkeypatch.setenv("SENTRAI_AGENT_FILE", str(tmp_path / "agent.json"))
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
    assert ["iptables", "-I", "INPUT", "-s", "203.0.113.45", "-m", "comment", "--comment", "sentrai", "-j", "DROP"] in calls
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


class Conn:
    def __init__(self, laddr, status="LISTEN", kind="tcp", pid=1, raddr=()):
        import socket as so
        self.laddr, self.status, self.pid, self.raddr = laddr, status, pid, raddr
        self.type = so.SOCK_STREAM if kind == "tcp" else so.SOCK_DGRAM


def test_listening_services_are_named_and_kept_private():
    from agent import services

    conns = [Conn(("0.0.0.0", 443), pid=10), Conn(("::", 443), pid=10), Conn(("0.0.0.0", 22), pid=11),
             Conn(("127.0.0.1", 6379), pid=12),                       # loopback only: not reported
             Conn(("0.0.0.0", 25565), pid=13), Conn(("0.0.0.0", 5000), pid=None),
             Conn(("10.0.0.5", 51000), status="ESTABLISHED", pid=14),  # a client connection
             Conn(("0.0.0.0", 53), kind="udp", status="NONE", pid=15), Conn(("0.0.0.0", 41234), kind="udp", status="NONE")]
    names = {10: "nginx", 11: "sshd", 12: "redis-server", 13: "java", 15: "systemd-resolved"}
    found = services.listening(lambda: conns, names.get)
    assert [(s["name"], s["port"], s["proto"]) for s in found] == [
        ("sshd", 22, "tcp"), ("systemd-resolved", 53, "udp"), ("nginx", 443, "tcp"),
        ("port-5000", 5000, "tcp"), ("minecraft", 25565, "tcp")]
    assert found[-1]["process"] == "java"  # the port named it; the process is still shown
    assert services.listening(lambda: conns, names.get, include_local=True)[4]["name"] == "redis"


def test_report_services_posts_names_only():
    sent = {}

    class S:
        def post(self, url, json, headers, timeout, verify):
            sent.update(url=url, body=json, headers=headers)
            return FakeResponse(200, {"ok": True})

    data = {"panel": "https://panel.example.com", "key": "sa_x.y"}
    assert agent.report_services(data, S(), lambda: [{"name": "nginx", "port": 443, "proto": "tcp", "process": "nginx"}])
    assert sent["url"] == "https://panel.example.com/fleet/services"
    assert sent["body"]["services"][0]["name"] == "nginx" and sent["headers"]["Authorization"] == "Bearer sa_x.y"


# ---------------------------------------------------------------- jobs from the panel (tasks.py)
def test_threat_scan_job_reads_only_local_folders(tmp_path, monkeypatch):
    from agent import tasks

    site = tmp_path / "site"
    site.mkdir()
    (site / "shell.php").write_text("<?php eval($_POST['c']); ?>")
    monkeypatch.setenv("SENTRAI_THREAT_PATHS", str(site))
    ok, result, err = tasks.run_job({"id": "j-1", "kind": "threat_scan"}, tmp_path)
    assert ok and err is None and result["files_checked"] == 1
    assert result["findings"] and all("real_path" not in f for f in result["findings"])
    monkeypatch.delenv("SENTRAI_THREAT_PATHS")
    ok, result, _ = tasks.run_job({"id": "j-2", "kind": "threat_scan"}, tmp_path)
    assert ok and result["files_checked"] == 0 and "SENTRAI_THREAT_PATHS" in result["note"]


def test_backup_job_stays_on_this_machine(tmp_path, monkeypatch):
    from agent import tasks

    data = tmp_path / "data"
    data.mkdir()
    (data / "a.txt").write_text("hello")
    monkeypatch.setenv("SENTRAI_BACKUP_PATHS", str(data))
    monkeypatch.delenv("SENTRAI_BACKUP_DIR", raising=False)
    ok, result, err = tasks.run_job({"id": "j-1", "kind": "backup"}, tmp_path / "agent")
    assert ok, err
    assert result["files"] == 1 and len(result["sha256"]) == 64
    assert (tmp_path / "agent" / "backups" / f"{result['id']}.tar.gz").is_file()
    monkeypatch.delenv("SENTRAI_BACKUP_PATHS")
    ok, _, err = tasks.run_job({"id": "j-2", "kind": "backup"}, tmp_path / "agent")
    assert not ok and "SENTRAI_BACKUP_PATHS" in err
    ok, _, err = tasks.run_job({"id": "j-3", "kind": "format_disk"}, tmp_path)
    assert not ok and "does not know" in err


def test_job_loop_picks_up_runs_and_reports(tmp_path, monkeypatch):
    import threading

    from agent import tasks

    monkeypatch.delenv("SENTRAI_THREAT_PATHS", raising=False)
    stop = threading.Event()
    queue = [{"id": "j-1", "kind": "threat_scan"}]
    sent = []

    class Session:
        def get(self, url, headers, timeout, verify):
            assert url.endswith("/fleet/jobs/next") and headers["Authorization"] == "Bearer sa_x.k"
            if not queue:
                stop.set()
            return FakeResponse(200, {"job": queue.pop(0) if queue else None})

        def post(self, url, json, timeout, verify, headers):
            sent.append(json)
            return FakeResponse(200, {"ok": True})

    monkeypatch.setattr(tasks.requests, "Session", Session)
    tasks.job_loop({"panel": "https://p", "key": "sa_x.k"}, True, tmp_path, stop, every_s=0, log=lambda s: None)
    assert sent and sent[0]["id"] == "j-1" and sent[0]["ok"] is True
