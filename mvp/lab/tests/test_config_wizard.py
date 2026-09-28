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
    # preset 4 (Advanced), collector: logs dir, then 5 more fields; classifier: brute-force count next
    values = cfg.wizard(ask=scripted(["4", "/var/log/portal", "", "", "", "", "", "3", "", "", "70"]),
                        ask_secret=scripted([]), say=lambda _: None)
    cfg.save(values)

    saved = json.loads(config_file.read_text())
    assert set(saved) == {"preset", "collector", "classifier", "responder", "notifications", "ai"}
    assert saved["preset"]["CACTAI_PRESET"] == "advanced"
    assert saved["collector"]["CACTAI_LAB_LOGS"] == "/var/log/portal"
    assert saved["classifier"]["BRUTE_FORCE_COUNT"] == "3"
    assert saved["responder"]["RISK_THRESHOLD"] == "70"

    cfg.load()
    assert os.environ["BRUTE_FORCE_COUNT"] == "3"
    assert os.environ["RISK_THRESHOLD"] == "90"


def test_invalid_number_is_asked_again(config_file):
    said = []
    answers = ["4", "", "", "", "", "", "", "five", "5"]
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


BEFORE_AI = [f for s in cfg.SECTIONS if s.key != "ai" for f in s.fields]
# With a preset (not Advanced), the preset's fields are not asked.
PLAIN_BEFORE_AI = [""] * sum(not f.secret and f.env not in cfg.PRESET_FIELDS for f in BEFORE_AI)
SECRET_BEFORE_AI = [""] * sum(f.secret for f in BEFORE_AI)


def test_ai_section_takes_a_provider_number_one_key_and_lists_models(config_file):
    said = []
    listed = lambda values: ["deepseek-chat", "deepseek-reasoner"]  # noqa: E731
    answers = iter(PLAIN_BEFORE_AI + ["3", "", "?", "2"])  # provider, base URL, list, pick
    values = cfg.wizard(ask=lambda p: next(answers, ""),
                        ask_secret=scripted(SECRET_BEFORE_AI + ["sk-deep"]), say=said.append, models=listed)
    assert values["CACTAI_LLM_PROVIDER"] == "deepseek"
    assert values["CACTAI_LLM_API_KEY"] == "sk-deep"
    assert values["CACTAI_LLM_MODEL"] == "deepseek-reasoner"
    assert "    3. DeepSeek" in said and "    2. deepseek-reasoner" in said


def test_model_listing_failure_is_explained_and_asked_again(config_file):
    def broken(values):
        raise cfg.cactai_llm.LLMError("the service rejected this API key")

    said = []
    answers = iter(PLAIN_BEFORE_AI + ["", "", "?", "my-model"])
    values = cfg.wizard(ask=lambda p: next(answers, ""), ask_secret=scripted(SECRET_BEFORE_AI + ["bad"]), say=said.append, models=broken)
    assert values["CACTAI_LLM_MODEL"] == "my-model"
    assert "    Could not list the models: the service rejected this API key." in said


def test_settings_saved_with_one_key_per_provider_keep_the_key_in_use(config_file):
    old = {"CACTAI_LLM_PROVIDER": "auto", "ANTHROPIC_API_KEY": "", "OPENAI_API_KEY": "sk-open",
           "DEEPSEEK_API_KEY": "sk-deep", "CACTAI_LLM_MODEL": ""}
    config_file.write_text(json.dumps({"ai": old}))
    values = cfg.read()
    assert (values["CACTAI_LLM_PROVIDER"], values["CACTAI_LLM_API_KEY"]) == ("openai", "sk-open")
    assert "OPENAI_API_KEY" not in values

    config_file.write_text(json.dumps({"ai": {**old, "CACTAI_LLM_PROVIDER": "deepseek"}}))
    assert cfg.read()["CACTAI_LLM_API_KEY"] == "sk-deep"

    config_file.write_text(json.dumps({"ai": {"CACTAI_LLM_PROVIDER": "auto", "CACTAI_LLM_API_KEY": "c",
                                              "CACTAI_LLM_BASE_URL": "https://llm.example.com/v1"}}))
    assert cfg.read()["CACTAI_LLM_PROVIDER"] == "compatible"


def test_default_preset_is_what_the_demo_uses():
    assert cfg.preset_values(cfg.DEFAULT_PRESET) == {env: cfg.FIELDS[env].default for env in cfg.PRESET_FIELDS}
    assert all(set(p.values) == set(cfg.PRESET_FIELDS) for p in cfg.PRESETS.values())
    strict, moderate, balanced = (cfg.preset_values(n) for n in ("strict", "moderate", "balanced"))
    assert int(strict["RISK_THRESHOLD"]) < int(moderate["RISK_THRESHOLD"]) < int(balanced["RISK_THRESHOLD"])


def test_picking_a_preset_sets_its_values_without_asking_them(config_file):
    said = []
    values = cfg.wizard(ask=scripted(["1"]), ask_secret=scripted([]), say=said.append)
    assert values["CACTAI_PRESET"] == "strict"
    assert {env: values[env] for env in cfg.PRESET_FIELDS} == cfg.preset_values("strict")
    assert any(line.startswith("    1. Strict: ") for line in said)
    assert any(line.startswith("    4. Advanced: ") for line in said)


def test_advanced_asks_each_value_and_offers_it_again(config_file):
    # Advanced, 6 collector fields, then brute force count 4 and Enter for the rest
    values = cfg.wizard(ask=scripted(["4", "", "", "", "", "", "", "4"]), ask_secret=scripted([]),
                        say=lambda _: None)
    assert values["CACTAI_PRESET"] == "advanced" and values["BRUTE_FORCE_COUNT"] == "4"
    assert values["RISK_THRESHOLD"] == cfg.preset_values("moderate")["RISK_THRESHOLD"]
    cfg.save(values)

    again = cfg.wizard(ask=scripted([]), ask_secret=scripted([]), say=lambda _: None)  # Enter keeps everything
    assert again["CACTAI_PRESET"] == "advanced" and again["BRUTE_FORCE_COUNT"] == "4"

    back = cfg.wizard(ask=scripted(["2"]), ask_secret=scripted([]), say=lambda _: None)
    assert back["CACTAI_PRESET"] == "moderate" and back["BRUTE_FORCE_COUNT"] == "5"


def test_a_preset_with_values_changed_by_hand_is_saved_as_advanced(config_file):
    cfg.save(cfg.preset_values("strict") | {"CACTAI_PRESET": "strict", "SLA_HOURS": "3"})
    assert json.loads(config_file.read_text())["preset"]["CACTAI_PRESET"] == "advanced"
    cfg.save(cfg.preset_values("strict") | {"CACTAI_PRESET": "strict", "SLA_HOURS": "1.0"})
    assert cfg.read()["CACTAI_PRESET"] == "strict"  # 1.0 is the same number as 1


def test_settings_saved_before_presets_read_as_advanced_when_changed(config_file):
    config_file.write_text(json.dumps({"responder": {"RISK_THRESHOLD": "70", "SLA_HOURS": "2"}}))
    assert cfg.read()["CACTAI_PRESET"] == "advanced"
    config_file.write_text(json.dumps({"responder": {"RISK_THRESHOLD": "80"}}))
    assert cfg.read()["CACTAI_PRESET"] == "moderate"
