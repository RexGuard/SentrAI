"""The first-run setup wizard (mvp/cactai_config.py)."""
from __future__ import annotations

import json
import os

import pytest

from target_app import paths

cfg = paths.cactai_config


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    monkeypatch.setenv("CACTAI_CONFIG", str(path))
    return path


def scripted(answers):
    answers = iter(answers)
    return lambda prompt: next(answers, "")


def test_enter_everywhere_keeps_the_demo_defaults(config_file):
    values = cfg.wizard(ask=scripted([]), ask_secret=scripted([]), say=lambda _: None)
    assert values == {f.env: f.default for f in cfg.FIELDS.values()}


def test_answers_are_saved_per_part_and_loaded_as_env_defaults(config_file, monkeypatch):
    for name in cfg.FIELDS:  # load() below must not leak into other tests
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("RISK_THRESHOLD", "90")  # explicit env var wins over the file
    # collector: logs dir, then 5 more fields; classifier: brute-force count comes next
    values = cfg.wizard(ask=scripted(["/var/log/portal", "", "", "", "", "", "3", "", "", "70"]),
                        ask_secret=scripted([]), say=lambda _: None)
    cfg.save(values)

    saved = json.loads(config_file.read_text())
    assert set(saved) == {"collector", "classifier", "responder", "notifications"}
    assert saved["collector"]["CACTAI_LAB_LOGS"] == "/var/log/portal"
    assert saved["classifier"]["BRUTE_FORCE_COUNT"] == "3"
    assert saved["responder"]["RISK_THRESHOLD"] == "70"

    cfg.load()
    assert os.environ["BRUTE_FORCE_COUNT"] == "3"
    assert os.environ["RISK_THRESHOLD"] == "90"


def test_invalid_number_is_asked_again(config_file):
    said = []
    answers = ["", "", "", "", "", "", "five", "5"]
    values = cfg.wizard(ask=scripted(answers), ask_secret=scripted([]), say=said.append)
    assert values["BRUTE_FORCE_COUNT"] == "5"
    assert "    Please enter a number." in said


def test_rerun_offers_saved_values_as_defaults(config_file):
    cfg.save({"CACTAI_LOG_AUTH": "login.jsonl"})
    values = cfg.wizard(ask=scripted([]), ask_secret=scripted([]), say=lambda _: None)
    assert values["CACTAI_LOG_AUTH"] == "login.jsonl"


def test_new_machine_runs_wizard_only_when_interactive(config_file, monkeypatch):
    cfg.ensure(interactive=False)
    assert not config_file.exists()

    for name in cfg.FIELDS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("builtins.input", scripted([]))
    monkeypatch.setattr(cfg.getpass, "getpass", scripted([]))
    cfg.ensure(interactive=True)
    assert config_file.exists()

    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("asked again on a configured machine"))
    cfg.ensure(interactive=True)
