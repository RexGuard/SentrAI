"""Cyanide: Claude plans containment, deterministic guardrails still decide what runs."""

import threading

import pytest

from app.config import Settings
from app.cyanide import Cyanide

from .conftest import ev

SQLI = "GET /search?q=' OR 1=1 -- 200"


class FakePlanner:
    """Stands in for Claude: returns canned plans per category and records what it was shown."""

    status = "online"

    def __init__(self, plans=None, default=None):
        self.plans = plans or {}
        self.default = default
        self.contexts = []

    def plan(self, context):
        self.contexts.append(context)
        return self.plans.get(context["incident"]["category"], self.default)


def block_only(allow=True, hold=""):
    return {"assessment": "Someone is guessing the admin password from one outside address.",
            "actions": [{"type": "block_ip", "target": "203.0.113.45", "why": "stops the guessing"}],
            "allow_autonomous": allow, "hold_reason": hold}


@pytest.fixture
def make(tmp_path):
    cores = []

    def _make(planner, profile=None, synchronous=True):
        core = Cyanide(Settings(db_path=tmp_path / f"c{len(cores)}.db", background=False, demo_speed=60.0),
                       planner=planner, profile=profile or {}, synchronous=synchronous)
        cores.append(core)
        return core

    yield _make
    for c in cores:
        c.audit.close()


def attack(core):
    core.ingest([ev(i, "POST /login 401 user=admin") for i in range(5)])
    core.ingest([ev(10, SQLI)])


def test_plan_replaces_the_playbook(make):
    core = make(FakePlanner(default=block_only()))
    attack(core)
    inc = core.get_incident("RSK-2026-081")
    assert inc["planned_by"] == "Cyanide"
    assert inc["explanation"].startswith("Someone is guessing")
    assert inc["recommended_action"] == "Block 203.0.113.45 for 2 h"
    # Risk crossed the threshold: autonomous containment ran Cyanide's plan (no account lock).
    assert [(a["type"], a["target"]) for a in inc["actions"]] == [("block_ip", "203.0.113.45")]
    assert core.blocklist() == {"ips": ["203.0.113.45"], "users": []}
    assert any(r["type"] == "cyanide_plan" for r in core.audit.records())
    assert core.audit.verify()[0]


def test_invented_actions_and_targets_are_dropped(make):
    plan = block_only()
    plan["actions"] += [{"type": "lock_user", "target": "root", "why": "x"},
                        {"type": "hack_back", "target": "203.0.113.45", "why": "x"},
                        {"type": "block_ip", "target": "203.0.113.45", "why": "dup"}]
    core = make(FakePlanner(default=plan))
    core.ingest([ev(i, "POST /login 401 user=admin") for i in range(5)])
    rec = next(r for r in core.audit.records() if r["type"] == "cyanide_plan")
    assert rec["data"]["actions"] == [{"type": "block_ip", "target": "203.0.113.45"}]
    assert {d["why"] for d in rec["data"]["dropped"]} == {
        "target not seen in this incident", "action not installed", "duplicate"}


def test_hold_stops_autonomous_action_but_not_the_operator(make):
    core = make(FakePlanner(default=block_only(allow=False, hold="exam week; the admin account is shared")))
    attack(core)
    assert core.risk()["risk_index"] >= core.settings.threshold
    inc = core.get_incident("RSK-2026-081")
    assert inc["actions"] == [] and inc["status"] == "open"
    assert "exam week" in inc["explanation"]
    assert any(n["kind"] == "needs_operator" and "Cyanide" in n["title"] for n in core.notifications)
    inc = core.decision("RSK-2026-081", "erick", "approve", None)
    assert [a["type"] for a in inc["actions"]] == ["block_ip"] and inc["status"] == "contained"


def test_no_plan_falls_back_to_saguaro_playbook(make):
    core = make(FakePlanner(default=None))
    attack(core)
    inc = core.get_incident("RSK-2026-081")
    assert "planned_by" not in inc
    assert {a["type"] for a in inc["actions"]} == {"block_ip", "lock_user", "rate_limit"}
    assert any(t["kind"] == "cyanide_fallback" for t in inc["timeline"])


def test_no_planner_behaves_like_saguaro(make):
    core = make(None)
    attack(core)
    assert core.blocklist() == {"ips": ["203.0.113.45"], "users": ["admin"]}
    claude = next(a for a in core.agents_status() if a["name"] == "Claude")
    assert claude["status"] == "off (playbooks only)"


def test_profile_protected_account_is_enforced_by_needle(make):
    plan = block_only()
    plan["actions"].append({"type": "lock_user", "target": "admin", "why": "stop reuse"})
    core = make(FakePlanner(default=plan), profile={"protected_users": ["admin"]})
    attack(core)
    assert core.blocklist() == {"ips": ["203.0.113.45"], "users": []}


def test_context_marks_logs_untrusted_and_lists_installed_actions(make):
    planner = FakePlanner(default=block_only())
    core = make(planner, profile={"organisation": "Test centre"})
    core.ingest([ev(i, "POST /login 401 user=admin") for i in range(5)])
    ctx = planner.contexts[0]
    assert ctx["system_profile"]["organisation"] == "Test centre"
    assert len(ctx["log_lines_untrusted"]) == 5
    assert set(ctx["installed_actions"]) == core.responders.allowlist
    assert ctx["default_playbook"][0] == {"type": "block_ip", "target": "203.0.113.45"}


def test_background_planning_does_not_block_ingest(make):
    release = threading.Event()
    done = threading.Event()

    class Slow(FakePlanner):
        def plan(self, context):
            release.wait(5)
            try:
                return block_only()
            finally:
                done.set()

    core = make(Slow(), synchronous=False)
    core.ingest([ev(i, "POST /login 401 user=admin") for i in range(5)])
    assert "planned_by" not in core.get_incident("RSK-2026-081")  # ingest returned before the model answered
    release.set()
    assert done.wait(5)
    core._pool.shutdown(wait=True)
    assert core.get_incident("RSK-2026-081")["planned_by"] == "Cyanide"


def test_reset_discards_late_plans(make):
    release = threading.Event()

    class Slow(FakePlanner):
        def plan(self, context):
            release.wait(5)
            return block_only()

    core = make(Slow(), synchronous=False)
    core.ingest([ev(i, "POST /login 401 user=admin") for i in range(5)])
    core.reset()
    core.ingest([ev(100 + i, "POST /login 401 user=admin") for i in range(5)])
    release.set()
    core._pool.shutdown(wait=True)
    assert all(i.get("planned_by") == "Cyanide" for i in core.list_incidents())
    assert len(core.list_incidents()) == 1
