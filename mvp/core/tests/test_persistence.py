"""Incidents, blocks and pending approvals survive a restart of the core."""

import time as real_time

import pytest

from app import clock as clock_mod
from app.config import Settings
from app.cyanide import Cyanide
from app.saguaro import Saguaro

from .conftest import ev
from .test_cyanide import FakePlanner, block_only

SQLI = "GET /search?q=' OR 1=1 -- 200"


class FakeTime:
    """Stands in for the time module in app.clock, so a test can let hours pass while the core is down."""

    def __init__(self):
        self.t = real_time.time()

    def time(self):
        return self.t


@pytest.fixture
def fake_time(monkeypatch):
    ft = FakeTime()
    monkeypatch.setattr(clock_mod, "time", ft)
    return ft


@pytest.fixture
def boot(tmp_path):
    cores = []

    def _boot(cls=Saguaro, **kw):
        if cores:
            cores[-1].audit.close()  # the previous process "stops"
        core = cls(Settings(db_path=tmp_path / "cactai.db", background=False, demo_speed=60.0), **kw)
        cores.append(core)
        return core

    yield _boot
    cores[-1].audit.close()


def attack(core):
    core.ingest([ev(i, "POST /login 401 user=admin") for i in range(5)])
    core.ingest([ev(10, SQLI)])


def test_incidents_blocks_and_notifications_survive_restart(boot, fake_time):
    core = boot()
    core.ingest([ev(i, "POST /login 401 user=admin") for i in range(5)])  # open, awaiting a decision
    core.ingest([ev(20, "GET /search?q=<script>alert(1)</script> 200", ip="198.51.100.7", user=None)])
    xss = next(i["id"] for i in core.list_incidents() if i["category"] == "xss")
    core.decision(xss, "erick", "approve", None)
    before = {i["id"]: i for i in core.list_incidents()}
    pending_before = [n["id"] for n in core.pending_notifications()]
    assert before["RSK-2026-081"]["status"] == "open" and before[xss]["status"] == "contained"

    fake_time.t += 60  # one real minute (one demo hour) later
    core = boot()
    after = {i["id"]: i for i in core.list_incidents()}
    assert set(after) == set(before)
    assert after["RSK-2026-081"]["status"] == "open" and after["RSK-2026-081"]["event_ids"] == before["RSK-2026-081"]["event_ids"]
    assert after[xss]["status"] == "contained" and after[xss]["actions"][0]["status"] == "active"
    assert after[xss]["actions"][0]["expires_at"] == before[xss]["actions"][0]["expires_at"]  # original TTL kept
    assert "198.51.100.7" in core.blocklist()["ips"]
    assert [n["id"] for n in core.pending_notifications()] == pending_before
    # The penalty kept counting while the core was down: the incident was still unanswered.
    assert after["RSK-2026-081"]["time_unaddressed_hours"] >= 1.0
    # Operator verbs work on restored incidents, and new ids continue from the old ones.
    core.decision("RSK-2026-081", "erick", "approve", None)
    assert "203.0.113.45" in core.blocklist()["ips"]
    core.rollback(xss, "erick", "false alarm")
    assert "198.51.100.7" not in core.blocklist()["ips"]
    core.ingest([ev(30, "shell spawned by www-data: /bin/sh", ip="192.0.2.9", layer="os", source="os_process")])
    ids = sorted(i["id"] for i in core.list_incidents())
    assert ids[-1] == "RSK-2026-083"
    assert len({a["action_id"] for a in core.actions}) == len(core.actions)
    assert len({n["id"] for n in core.notifications}) == len(core.notifications)
    types = [r["type"] for r in core.audit.records()]
    assert "state_restored" in types
    assert core.audit.verify()[0]


def test_blocks_that_expired_while_down_are_rolled_back_and_audited(boot, fake_time):
    core = boot()
    attack(core)  # over the threshold: both incidents contained autonomously for 2 demo hours
    assert "203.0.113.45" in core.blocklist()["ips"]
    ids = [a["action_id"] for a in core.actions]

    fake_time.t += 3 * 60  # 3 demo hours pass with the core stopped
    core = boot()
    assert core.blocklist() == {"ips": [], "users": []}
    assert all(a["status"] == "expired" for a in core.actions)
    recs = core.audit.records()
    restored = next(r for r in recs if r["type"] == "state_restored")["data"]
    assert sorted(restored["actions_expired_while_down"]) == sorted(ids)
    expired = [r["data"] for r in recs if r["type"] == "action_expired"]
    assert sorted(d["action_id"] for d in expired) == sorted(ids)
    assert all(d["while_core_down"] for d in expired)
    inc = core.get_incident("RSK-2026-081")
    assert any(t["kind"] == "expired" and "while the core was down" in t["text"] for t in inc["timeline"])
    assert any(n["kind"] == "action_expired" for n in core.pending_notifications())
    assert core.audit.verify()[0]


def test_permanent_block_survives_restart(boot, fake_time):
    core = boot()
    core.ingest([ev(20, "GET /search?q=<script>alert(1)</script> 200", ip="198.51.100.7", user=None)])
    iid = core.list_incidents()[0]["id"]
    core.decision(iid, "erick", "approve", None)
    core.make_permanent(iid, "erick", "known bad")
    fake_time.t += 24 * 60
    core = boot()
    assert "198.51.100.7" in core.blocklist()["ips"]
    assert core.get_incident(iid)["status"] == "resolved"


def test_demo_clock_offset_survives_restart(boot, fake_time):
    core = boot()
    core.ingest([ev(i, "POST /login 401 user=admin") for i in range(5)])
    core.advance(1.5)
    h = core.get_incident("RSK-2026-081")["time_unaddressed_hours"]
    core = boot()
    assert core.get_incident("RSK-2026-081")["time_unaddressed_hours"] == h


def test_reset_clears_saved_state(boot, fake_time):
    core = boot()
    attack(core)
    core.reset()
    core = boot()
    assert core.list_incidents() == [] and core.actions == [] and core.notifications == []
    assert core.blocklist() == {"ips": [], "users": []}
    assert not any(r["type"] == "state_restored" for r in core.audit.records())


def test_cyanide_plan_survives_restart(boot, fake_time):
    hold = block_only(allow=False, hold="exam week: ask first")
    core = boot(Cyanide, planner=FakePlanner(default=hold), profile={}, synchronous=True)
    attack(core)
    inc = core.get_incident("RSK-2026-081")
    assert inc["status"] == "open" and inc["planned_by"] == "Cyanide"
    core = boot(Cyanide, planner=None, profile={}, synchronous=True)
    inc = core.get_incident("RSK-2026-081")
    assert inc["planned_by"] == "Cyanide" and inc["recommended_action"] == "Block 203.0.113.45 for 2 h"
    assert inc["status"] == "open" and core.actions == []  # the hold still applies after the restart
    core.decision("RSK-2026-081", "erick", "approve", None)
    assert core.blocklist() == {"ips": ["203.0.113.45"], "users": []}  # the saved plan, not the playbook
