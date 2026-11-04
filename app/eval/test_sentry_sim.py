"""Checks for the Sentry chat simulation, with stand-in models (no network, no key)."""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sentry_sim  # noqa: E402

sentry_sim.isolate(Path(tempfile.mkdtemp(prefix="sentry-sim-test-")))

import sentrai_llm  # noqa: E402


class FakeSentry(sentrai_llm.Provider):
    name, model, effort = "fake", "fake-sentry", "low"

    def conversation(self, system, tools):
        self.system = system
        provider = self

        class Convo:
            def send_user(self, text, images=None):
                provider.last_prompt = text
                return sentrai_llm.Turn(texts=["You're safe. SentrAI stopped someone guessing passwords. "
                                               "Nothing for you to do."])

        return Convo()


class FakeJudge(sentrai_llm.Provider):
    name, model = "fake", "fake-judge"

    def __init__(self):
        self.persona_calls = 0

    def complete_json(self, system, user, schema):
        if schema is sentry_sim.PERSONA_SCHEMA:
            self.persona_calls += 1
            first = "(The chat is empty" in user
            return {"message": "is my website ok?" if first else "", "done": not first, "satisfaction": 4,
                    "why": "clear"}
        return {**{k: 4 for k in sentry_sim.SCORE_KEYS}, "issues": ["none"], "comment": "fine", "fix_hint": ""}


def args(**kw):
    a = sentry_sim.parser().parse_args([])
    return argparse.Namespace(**{**vars(a), "convos": 3, "parallel": 2, **kw})


def test_simulated_chats_are_graded_and_summarised(tmp_path):
    summary, records = sentry_sim.run(args(), FakeSentry(), FakeJudge(), sentry_sim.Meter(), tmp_path, log=lambda m: None)
    assert summary["chats"] == 3 and summary["failed_chats"] == 0
    assert all(len(r["turns"]) == 1 and r["satisfaction"] == 4 for r in records)
    assert summary["overall"] == 4 and summary["ai_answers"] == 3
    assert records[0]["turns"][0]["checks"]["internal_names"] == []
    assert "# Sentry simulation" in sentry_sim.report_md(summary, records)
    assert list(tmp_path.iterdir()) == []  # every private core is deleted


def test_a_prompt_file_replaces_sentrys_instructions(tmp_path):
    prompt = tmp_path / "p.txt"
    prompt.write_text("You are {name}. Be brief.")
    sentry = FakeSentry()
    from app import chat

    old = chat.SYSTEM
    try:
        (tmp_path / "w").mkdir()
        summary, _ = sentry_sim.run(args(convos=1, prompt=str(prompt)), sentry, FakeJudge(), sentry_sim.Meter(),
                                    tmp_path / "w", log=lambda m: None)
        assert sentry.system.startswith("You are Sentry. Be brief.") and summary["prompt"] == "p.txt"
    finally:
        chat.SYSTEM = old


def test_checks_flag_internal_names_jargon_and_claimed_actions():
    c = sentry_sim.checks("I have blocked the brute force attack. Warden saw it.")
    assert c["internal_names"] == ["warden"] and c["jargon"] == ["brute force"] and c["claims_action"]


def test_only_ai_settings_are_taken_from_the_panel(tmp_path):
    env = tmp_path / "sentrai.env"
    env.write_text('ANTHROPIC_API_KEY="sk-ant-test"\nSENTRAI_FIREWALL_ENFORCE=1\nTELEGRAM_BOT_TOKEN=x\n')
    got = sentry_sim.panel_ai_settings(env, tmp_path / "missing.json")
    assert got == {"ANTHROPIC_API_KEY": "sk-ant-test"}


def test_plan_spreads_people_over_situations():
    pairs = sentry_sim.plan(24, 7, list(sentry_sim.SCENARIOS))
    assert len({p["id"] for p, _ in pairs}) == 12 and len({s for _, s in pairs}) == len(sentry_sim.SCENARIOS)
