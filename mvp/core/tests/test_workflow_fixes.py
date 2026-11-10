"""Workflow review quick fixes: dry-run machines, written-down-only fixes, readiness, the AI budget."""

import types

import pytest

import sentrai_llm
from app import jobs, ui_readiness
from app.ui_approvals import handled, written_down_only
from app.ui_machines import blocking_row

from .test_fleet import as_agent, join, panel  # noqa: F401  (fixture)


def test_blocking_row_words():
    assert blocking_row(None, False) is None
    assert blocking_row(None, True)["state"] == "unknown"
    assert blocking_row({"enforce": False}, True)["word"] == "Not blocking yet"
    assert blocking_row({"enforce": True, "backend": "nftables"}, True)["state"] == "on"


def test_agent_report_shows_a_dry_run_and_the_panel_can_switch_it(panel):  # noqa: F811
    key = join(panel)["key"]
    r = panel.post("/fleet/services", json={"services": [], "agent": {"enforce": False, "backend": "nftables",
                                                                      "version": "abc123"}}, headers=as_agent(key))
    assert r.status_code == 200, r.text
    row = next(m for m in panel.get("/ui/machines").json()["machines"] if m["host"] == "office-pc")
    assert row["blocking"]["state"] == "dry_run"
    ready = panel.get("/ui/readiness").json()
    line = next(c for c in ready["checks"] if c["key"] == "blocking")
    assert not line["ok"] and "office-pc" in line["detail"] and not ready["ready"]
    assert "ai_spend" in ready
    q = panel.post("/fleet/jobs", json={"host": "office-pc", "kind": "blocking_on", "operator": "erick"})
    assert q.status_code == 200, q.text
    assert jobs.clean_blocking({"enforce": 1}) == {"enforce": True}


def test_written_down_only_fix_is_not_already_handled():
    inc = {"status": "contained", "actions": [{"type": "rate_limit", "status": "active",
                                              "enforcement": "recorded (simulated)"}]}
    assert written_down_only(inc)
    assert not handled(inc)


def test_readiness_all_good():
    rows = {"machines": [{"host": "a", "online": True, "blocking": {"state": "on"}}]}
    lines = ui_readiness.checks("on", rows, ["email"], None, 0.0)
    assert ui_readiness.summary(lines)["ready"]


def test_ai_budget_stops_calls_once_used(tmp_path, monkeypatch):
    monkeypatch.setenv(sentrai_llm.USAGE_ENV, str(tmp_path / "ai-usage.json"))
    monkeypatch.setenv(sentrai_llm.BUDGET_ENV, "0.01")
    usage = types.SimpleNamespace(input_tokens=1000, output_tokens=1000, cache_read_input_tokens=0,
                                  cache_creation_input_tokens=0)
    reply = types.SimpleNamespace(usage=usage, stop_reason="end_turn", content=[])
    client = types.SimpleNamespace(messages=types.SimpleNamespace(create=lambda **kw: reply))
    p = sentrai_llm.AnthropicProvider(model="claude-opus-5-5", client=client)
    p._create()
    assert sentrai_llm.spent_this_month()["usd"] == pytest.approx(0.024)
    with pytest.raises(sentrai_llm.BudgetError):
        p._create()
    monkeypatch.setenv(sentrai_llm.BUDGET_ENV, "0")  # 0 = no cap
    p._create()
