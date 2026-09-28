"""Real firewall blocking (app/firewall.py), tested with a fake command runner only."""

import pytest
from fastapi.testclient import TestClient

from app import firewall
from app.config import Settings
from app.firewall import FirewallResponder, block_commands, from_settings, unsafe_reason
from app.main import create_app
from app.responders import BlocklistResponder

from .conftest import brute_force

IP = "203.0.113.45"


class FakeRunner:
    """A pretend firewall that remembers its rules, so check commands answer truthfully.
    Commands whose argv contains `fail_on` return exit code 1 and change nothing."""

    def __init__(self, fail_on: str | None = None) -> None:
        self.calls: list[list[str]] = []
        self.fail_on = fail_on
        self.rules: set[tuple[str, ...]] = set()

    def __call__(self, args):
        self.calls.append(list(args))
        if self.fail_on and self.fail_on in args:
            return 1, "boom"
        at = 3 if args[0] == "netsh" else 1  # position of the verb
        verb = args[at]
        if args[0] == "nft" and args[2] != "element":
            return 0, ""  # table/set/chain setup
        key = tuple(args[:at] + args[at + 1:at + 3]) if args[0] == "netsh" else tuple(args[:at] + args[at + 1:])
        if verb in ("-C", "get", "show"):
            return (0, "") if key in self.rules else (1, "no such rule")
        if verb in ("-I", "add"):
            self.rules.add(key)
        elif verb in ("-D", "delete"):
            self.rules.discard(key)
        return 0, ""

    def verbs(self, tool):
        return [c[1] for c in self.calls if c[0] == tool]


def block(ip=IP):
    return {"action_id": "act-0001", "type": "block_ip", "target": ip}


def test_off_by_default_keeps_portal_only_blocking(monkeypatch):
    monkeypatch.delenv("CACTAI_FIREWALL", raising=False)
    monkeypatch.delenv("CACTAI_FIREWALL_ENFORCE", raising=False)
    s = Settings()
    assert s.firewall == "off" and s.firewall_enforce is False
    r = from_settings(s.firewall, s.firewall_enforce, s.protected_ips)
    assert type(r) is BlocklistResponder and r.enforcement == "blocklist"


def test_bad_backend_name_is_rejected():
    with pytest.raises(ValueError):
        from_settings("pf", False, set())


def test_dry_run_logs_commands_and_never_runs_them():
    runner = FakeRunner()
    r = FirewallResponder("iptables", enforce=False, runner=runner)
    a = block()
    assert r.apply(a) is True
    assert runner.calls == []  # nothing touched the host
    assert a["firewall"]["dry_run"] is True
    assert a["firewall"]["commands"] == [f"iptables -I INPUT -s {IP} -m comment --comment cactai -j DROP"]
    assert r.blocklist()["ips"] == [IP]  # the portal still blocks it
    r.revert(a)
    assert r.history[-1]["cmd"][:2] == ["iptables", "-D"] and r.history[-1]["dry_run"]
    assert r.blocklist()["ips"] == []


@pytest.mark.parametrize("target", ["127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "169.254.1.1",
                                    "224.0.0.1", "localhost", "10.0.0.5; rm -rf /", "198.51.100.1"])
def test_unsafe_targets_never_reach_the_firewall(target):
    runner = FakeRunner()
    r = FirewallResponder("nftables", enforce=True, protected_ips={"198.51.100.1"}, runner=runner)
    a = block(target)
    r.apply(a)
    assert runner.calls == [] and "skipped" in a["firewall"]
    r.revert(a)
    assert runner.calls == []


def test_unsafe_reason():
    assert unsafe_reason(IP, set()) is None
    assert unsafe_reason("2001:db8::7", set()) is None
    assert unsafe_reason("::ffff:10.1.1.1", {"10.1.1.1"}) == "protected address"


def test_enforced_iptables_adds_verifies_and_removes_once_per_address():
    runner = FakeRunner()
    r = FirewallResponder("iptables", enforce=True, runner=runner)
    a1, a2 = block(), block()
    assert r.apply(a1) and r.apply(a2)
    assert runner.verbs("iptables") == ["-C", "-I", "-C"]  # second incident reuses the same rule
    r.revert(a1)
    assert runner.verbs("iptables") == ["-C", "-I", "-C"]  # still blocked by the second incident
    r.revert(a2)
    assert runner.verbs("iptables") == ["-C", "-I", "-C", "-D"]
    assert runner.rules == set()
    assert r.status()["blocked"] == []


def test_reapply_after_restart_adopts_the_existing_rule():
    """Saved state re-applies every active block on startup; that must not add duplicate rules."""
    runner = FakeRunner()
    FirewallResponder("iptables", enforce=True, runner=runner).apply(block())
    restarted = FirewallResponder("iptables", enforce=True, runner=runner)  # same host firewall, fresh process
    a = block()
    assert restarted.apply(a) and a["firewall"]["already_in_firewall"]
    assert runner.verbs("iptables") == ["-C", "-I", "-C", "-C"]  # no second -I
    restarted.revert(a)
    assert runner.rules == set()  # the adopted rule is still cleaned up on expiry


@pytest.mark.parametrize("backend", ["nftables", "netsh"])
def test_reapply_is_idempotent_on_every_backend(backend):
    runner = FakeRunner()
    FirewallResponder(backend, enforce=True, runner=runner).apply(block())
    adds = sum(1 for c in runner.calls if "add" in c and IP in " ".join(c))
    FirewallResponder(backend, enforce=True, runner=runner).apply(block())
    assert sum(1 for c in runner.calls if "add" in c and IP in " ".join(c)) == adds == 1


def test_admin_ip_in_protected_ips_is_never_blocked(monkeypatch):
    monkeypatch.setenv("PROTECTED_IPS", "127.0.0.1,::1,localhost,198.51.100.200")
    s = Settings()
    runner = FakeRunner()
    r = from_settings("iptables", True, s.protected_ips, runner=runner)
    a = block("198.51.100.200")
    r.apply(a)
    assert a["firewall"]["skipped"] == "protected address" and runner.calls == []


def test_ipv6_uses_ip6tables():
    add, check, remove = block_commands("iptables", "2001:db8::7")
    assert add[0] == check[0] == remove[0] == "ip6tables"


def test_nftables_sets_up_its_table_once():
    runner = FakeRunner()
    r = FirewallResponder("nftables", enforce=True, runner=runner)
    r.apply(block("203.0.113.1"))
    r.apply(block("2001:db8::7"))
    verbs = [" ".join(c[1:3]) for c in runner.calls]
    assert verbs.count("add table") == 1
    assert ["nft", "add", "element", "inet", "cactai", "blocked4", "{ 203.0.113.1 }"] in runner.calls
    assert ["nft", "add", "element", "inet", "cactai", "blocked6", "{ 2001:db8::7 }"] in runner.calls
    r.reset()  # demo reset takes both addresses out of the firewall
    assert sum(1 for c in runner.calls if c[1:3] == ["delete", "element"]) == 2


def test_netsh_rule_per_address():
    add, check, remove = block_commands("netsh", IP)
    assert add == ["netsh", "advfirewall", "firewall", "add", "rule", f"name=CactAI-block-{IP}",
                   "dir=in", "action=block", f"remoteip={IP}"]
    assert check[3:5] == ["show", "rule"] and remove[3:5] == ["delete", "rule"]


def test_failed_command_reports_not_verified():
    runner = FakeRunner(fail_on="-C")
    r = FirewallResponder("iptables", enforce=True, runner=runner)
    a = block()
    assert r.apply(a) is False and a["firewall"]["ok"] is False
    assert runner.verbs("iptables") == ["-C", "-I", "-C", "-D"]  # the unverified rule is taken out again


def test_other_actions_pass_through_untouched():
    runner = FakeRunner()
    r = FirewallResponder("iptables", enforce=True, runner=runner)
    a = {"type": "lock_user", "target": "admin"}
    assert r.apply(a) and "firewall" not in a and runner.calls == []
    assert r.blocklist()["users"] == ["admin"]


@pytest.fixture
def fw_client(tmp_path):
    def make(runner, enforce=True):
        s = Settings(db_path=tmp_path / "cactai.db", background=False, demo_speed=60.0,
                     firewall="iptables", firewall_enforce=enforce)
        app = create_app(s)
        app.state.core.blocklist_responder.runner = runner
        return TestClient(app)
    return make


def test_approval_ttl_and_rollback_drive_the_firewall(fw_client):
    runner = FakeRunner()
    with fw_client(runner) as c:
        brute_force(c)
        assert runner.calls == []  # nothing happens before approval
        inc = c.post("/incidents/RSK-2026-081/decision", json={"operator": "erick", "decision": "approve"}).json()
        act = next(a for a in inc["actions"] if a["type"] == "block_ip")
        assert act["enforcement"] == "blocklist + firewall (iptables)" and act["verified"]
        assert runner.verbs("iptables") == ["-C", "-I", "-C"]
        assert IP in c.get("/blocklist").json()["ips"]
        c.post("/demo/advance", json={"demo_hours": 2.1})  # TTL expiry
        assert runner.verbs("iptables") == ["-C", "-I", "-C", "-D"]
        assert c.get("/blocklist").json()["ips"] == []
        audit = c.get("/audit").json()["records"]
        applied = [x for x in audit if x["type"] == "action_applied" and x["data"]["type"] == "block_ip"]
        assert "iptables -I INPUT" in applied[0]["data"]["firewall"]["commands"][1]


def test_failed_firewall_block_is_rolled_back(fw_client):
    runner = FakeRunner(fail_on="-I")
    with fw_client(runner) as c:
        brute_force(c)
        inc = c.post("/incidents/RSK-2026-081/decision", json={"operator": "erick", "decision": "approve"}).json()
        act = next(a for a in inc["actions"] if a["type"] == "block_ip")
        assert act["status"] == "rolled_back" and not act["verified"]
        assert IP not in c.get("/blocklist").json()["ips"]
        assert runner.verbs("iptables") == ["-C", "-I"]  # nothing to remove, it never went in


def test_dry_run_core_never_runs_commands(fw_client):
    runner = FakeRunner()
    with fw_client(runner, enforce=False) as c:
        brute_force(c)
        inc = c.post("/incidents/RSK-2026-081/decision", json={"operator": "erick", "decision": "approve"}).json()
        act = next(a for a in inc["actions"] if a["type"] == "block_ip")
        assert act["enforcement"] == "blocklist + firewall dry run (iptables)" and act["verified"]
        assert act["firewall"]["dry_run"] and runner.calls == []
        c.post("/incidents/RSK-2026-081/rollback", json={"operator": "erick", "justification": "test"})
        assert runner.calls == []


def test_auto_backend_detection(monkeypatch):
    monkeypatch.setattr(firewall.platform, "system", lambda: "Windows")
    assert firewall.resolve_backend("auto") == "netsh"
    monkeypatch.setattr(firewall.platform, "system", lambda: "Linux")
    monkeypatch.setattr(firewall.shutil, "which", lambda n: None)
    assert firewall.resolve_backend("auto") is None
    assert type(from_settings("auto", True, set())) is BlocklistResponder
