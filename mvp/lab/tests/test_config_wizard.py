"""The first-run setup wizard (mvp/sentrai_config.py)."""
from __future__ import annotations

import json
import os

import pytest

from collector import paths

cfg = paths.sentrai_config


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    monkeypatch.setenv("SENTRAI_CONFIG", str(path))
    return path


def scripted(answers):
    answers = iter(answers)
    return lambda prompt: next(answers, "")


def test_enter_everywhere_keeps_the_demo_defaults(config_file):
    values = cfg.wizard(ask=scripted([]), ask_secret=scripted([]), say=lambda _: None)
    token = values.pop(cfg.TOKEN_ENV)
    assert len(token) >= 40  # generated, never asked
    assert values == {f.env: f.default for f in cfg.FIELDS.values() if f.env != cfg.TOKEN_ENV}
    assert cfg.HASH_ENV not in values  # people sign in with accounts now, made on the dashboard


def test_answers_are_saved_per_part_and_loaded_as_env_defaults(config_file, monkeypatch):
    for name in cfg.FIELDS:  # load() below must not leak into other tests
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("RISK_THRESHOLD", "90")  # explicit env var wins over the file
    # preset 4 (Advanced), collector: logs dir, then 5 more fields; classifier: brute-force count next
    values = cfg.wizard(ask=scripted(["4", "/var/log/portal", "", "", "", "", "", "3", "", "", "70"]),
                        ask_secret=scripted([]), say=lambda _: None)
    cfg.save(values)

    saved = json.loads(config_file.read_text())
    assert set(saved) == {"preset", "collector", "classifier", "responder", "notifications", "ai", "access",
                          *(f"extension:{name}" for name in cfg.EXTENSION_SECTIONS)}
    assert saved["preset"]["SENTRAI_PRESET"] == "advanced"
    assert saved["collector"]["SENTRAI_LAB_LOGS"] == "/var/log/portal"
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
    cfg.save({"SENTRAI_LOG_AUTH": "login.jsonl"})
    values = cfg.wizard(ask=scripted([]), ask_secret=scripted([]), say=lambda _: None)
    assert values["SENTRAI_LOG_AUTH"] == "login.jsonl"


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


BEFORE_AI = [f for s in cfg.SECTIONS[:[s.key for s in cfg.SECTIONS].index("ai")] for f in s.fields]
# With a preset (not Advanced), the preset's fields are not asked.
ASKED_BEFORE_AI = [f for f in BEFORE_AI if f.env not in cfg.PRESET_FIELDS and f.env not in cfg.EMAIL_FIELDS]
PLAIN_BEFORE_AI = [""] * sum(not f.secret for f in ASKED_BEFORE_AI)
SECRET_BEFORE_AI = [""] * sum(f.secret for f in ASKED_BEFORE_AI)


def test_ai_section_takes_a_provider_number_one_key_and_lists_models(config_file):
    said = []
    listed = lambda values: ["deepseek-chat", "deepseek-reasoner"]  # noqa: E731
    answers = iter(PLAIN_BEFORE_AI + ["3", "", "?", "2"])  # provider, base URL, list, pick
    values = cfg.wizard(ask=lambda p: next(answers, ""),
                        ask_secret=scripted(SECRET_BEFORE_AI + ["sk-deep"]), say=said.append, models=listed)
    assert values["SENTRAI_LLM_PROVIDER"] == "deepseek"
    assert values["SENTRAI_LLM_API_KEY"] == "sk-deep"
    assert values["SENTRAI_LLM_MODEL"] == "deepseek-reasoner"
    assert "    3. DeepSeek" in said and "    2. deepseek-reasoner" in said


def test_model_listing_failure_is_explained_and_asked_again(config_file):
    def broken(values):
        raise cfg.sentrai_llm.LLMError("the service rejected this API key")

    said = []
    answers = iter(PLAIN_BEFORE_AI + ["", "", "?", "my-model"])
    values = cfg.wizard(ask=lambda p: next(answers, ""), ask_secret=scripted(SECRET_BEFORE_AI + ["bad"]), say=said.append, models=broken)
    assert values["SENTRAI_LLM_MODEL"] == "my-model"
    assert "    Could not list the models: the service rejected this API key." in said


def test_settings_saved_with_one_key_per_provider_keep_the_key_in_use(config_file):
    old = {"SENTRAI_LLM_PROVIDER": "auto", "ANTHROPIC_API_KEY": "", "OPENAI_API_KEY": "sk-open",
           "DEEPSEEK_API_KEY": "sk-deep", "SENTRAI_LLM_MODEL": ""}
    config_file.write_text(json.dumps({"ai": old}))
    values = cfg.read()
    assert (values["SENTRAI_LLM_PROVIDER"], values["SENTRAI_LLM_API_KEY"]) == ("openai", "sk-open")
    assert "OPENAI_API_KEY" not in values

    config_file.write_text(json.dumps({"ai": {**old, "SENTRAI_LLM_PROVIDER": "deepseek"}}))
    assert cfg.read()["SENTRAI_LLM_API_KEY"] == "sk-deep"

    config_file.write_text(json.dumps({"ai": {"SENTRAI_LLM_PROVIDER": "auto", "SENTRAI_LLM_API_KEY": "c",
                                              "SENTRAI_LLM_BASE_URL": "https://llm.example.com/v1"}}))
    assert cfg.read()["SENTRAI_LLM_PROVIDER"] == "compatible"


def test_default_preset_is_what_the_demo_uses():
    assert cfg.preset_values(cfg.DEFAULT_PRESET) == {env: cfg.FIELDS[env].default for env in cfg.PRESET_FIELDS}
    assert all(set(p.values) == set(cfg.PRESET_FIELDS) for p in cfg.PRESETS.values())
    strict, moderate, balanced = (cfg.preset_values(n) for n in ("strict", "moderate", "balanced"))
    assert int(strict["RISK_THRESHOLD"]) < int(moderate["RISK_THRESHOLD"]) < int(balanced["RISK_THRESHOLD"])


def test_picking_a_preset_sets_its_values_without_asking_them(config_file):
    said = []
    values = cfg.wizard(ask=scripted(["1"]), ask_secret=scripted([]), say=said.append)
    assert values["SENTRAI_PRESET"] == "strict"
    assert {env: values[env] for env in cfg.PRESET_FIELDS} == cfg.preset_values("strict")
    assert any(line.startswith("    1. Strict: ") for line in said)
    assert any(line.startswith("    4. Advanced: ") for line in said)


def test_advanced_asks_each_value_and_offers_it_again(config_file):
    # Advanced, 6 collector fields, then brute force count 4 and Enter for the rest
    values = cfg.wizard(ask=scripted(["4", "", "", "", "", "", "", "4"]), ask_secret=scripted([]),
                        say=lambda _: None)
    assert values["SENTRAI_PRESET"] == "advanced" and values["BRUTE_FORCE_COUNT"] == "4"
    assert values["RISK_THRESHOLD"] == cfg.preset_values("moderate")["RISK_THRESHOLD"]
    cfg.save(values)

    again = cfg.wizard(ask=scripted([]), ask_secret=scripted([]), say=lambda _: None)  # Enter keeps everything
    assert again["SENTRAI_PRESET"] == "advanced" and again["BRUTE_FORCE_COUNT"] == "4"

    back = cfg.wizard(ask=scripted(["2"]), ask_secret=scripted([]), say=lambda _: None)
    assert back["SENTRAI_PRESET"] == "moderate" and back["BRUTE_FORCE_COUNT"] == "5"


def test_a_preset_with_values_changed_by_hand_is_saved_as_advanced(config_file):
    cfg.save(cfg.preset_values("strict") | {"SENTRAI_PRESET": "strict", "SLA_HOURS": "3"})
    assert json.loads(config_file.read_text())["preset"]["SENTRAI_PRESET"] == "advanced"
    cfg.save(cfg.preset_values("strict") | {"SENTRAI_PRESET": "strict", "SLA_HOURS": "1.0"})
    assert cfg.read()["SENTRAI_PRESET"] == "strict"  # 1.0 is the same number as 1


def test_settings_saved_before_presets_read_as_advanced_when_changed(config_file):
    config_file.write_text(json.dumps({"responder": {"RISK_THRESHOLD": "70", "SLA_HOURS": "2"}}))
    assert cfg.read()["SENTRAI_PRESET"] == "advanced"
    config_file.write_text(json.dumps({"responder": {"RISK_THRESHOLD": "80"}}))
    assert cfg.read()["SENTRAI_PRESET"] == "moderate"


def test_api_token_is_made_once_and_kept(config_file, monkeypatch):
    monkeypatch.delenv(cfg.TOKEN_ENV, raising=False)
    first = cfg.api_token()
    assert first and json.loads(config_file.read_text())["access"][cfg.TOKEN_ENV] == first
    assert cfg.api_token() == first
    # the wizard and a settings form that leaves the token out both keep it
    assert cfg.wizard(ask=scripted([]), ask_secret=scripted([]), say=lambda _: None)[cfg.TOKEN_ENV] == first
    cfg.save({"SENTRAI_PRESET": "strict"})
    assert cfg.api_token() == first
    monkeypatch.setenv(cfg.TOKEN_ENV, "from-env")  # an explicit env var wins
    assert cfg.api_token() == "from-env"


def test_token_command_prints_it(config_file, monkeypatch, capsys):
    monkeypatch.delenv(cfg.TOKEN_ENV, raising=False)
    assert cfg.main(["token"]) == 0
    assert capsys.readouterr().out.strip() == cfg.api_token()


def test_old_plain_dashboard_password_is_kept_only_as_a_hash(config_file):
    config_file.write_text(json.dumps({"access": {cfg.TOKEN_ENV: "t", cfg.PASSWORD_ENV: "cactus-cactus"}}))
    values = cfg.read()
    assert cfg.PASSWORD_ENV not in values and cfg.check_password("cactus-cactus", values[cfg.HASH_ENV])
    cfg.save(values)
    assert "cactus-cactus" not in config_file.read_text()
    assert cfg.check_password("cactus-cactus", cfg.read()[cfg.HASH_ENV])  # kept until it becomes the Owner


@pytest.mark.skipif(os.name == "nt", reason="Windows has no Unix file modes")
def test_settings_file_is_readable_by_its_owner_only(config_file):
    config_file.write_text("{}\n", encoding="utf-8")
    os.chmod(config_file, 0o644)  # saved by an older version
    cfg.save({})
    assert config_file.stat().st_mode & 0o777 == 0o600
    cfg.save_appearance("dark", "mono")
    assert config_file.stat().st_mode & 0o777 == 0o600


# ------------------------------------------------------------------ extensions' settings

def test_each_installed_extension_brings_its_own_section():
    assert {"cloudflare", "typesafe", "telegram", "slack", "abuseipdb"} <= set(cfg.EXTENSION_SECTIONS)
    cloudflare = cfg.EXTENSION_SECTIONS["cloudflare"]
    assert cloudflare.key == "extension:cloudflare" and cloudflare.on_when == ("CLOUDFLARE_API_TOKEN",)
    assert cfg.FIELDS["CLOUDFLARE_API_TOKEN"].secret and cfg.FIELDS["CLOUDFLARE_METHOD"].choices
    assert cfg.FIELDS["CLOUDFLARE_TIMEOUT_S"].advanced and cfg.FIELDS["CLOUDFLARE_TIMEOUT_S"].kind is float
    # none of them is part of SentrAI's own sections any more
    own = {f.env for s in cfg.SECTIONS for f in s.fields}
    assert not own & {"TYPESAFE_API_KEY", "TELEGRAM_BOT_TOKEN", "CLOUDFLARE_API_TOKEN", "SLACK_WEBHOOK_URL"}


def test_settings_saved_before_extensions_keep_working_and_move_on_save(config_file, monkeypatch):
    for name in cfg.FIELDS:
        monkeypatch.delenv(name, raising=False)
    config_file.write_text(json.dumps({
        "classifier": {"BRUTE_FORCE_COUNT": "5", "TYPESAFE_API_KEY": "ts-key"},
        "notifications": {"TELEGRAM_BOT_TOKEN": "123:abc", "TELEGRAM_CHAT_ID": "-1001", "SMTP_HOST": ""},
        "integrations": {"CLOUDFLARE_API_TOKEN": "cf-token", "CLOUDFLARE_ZONE_ID": "zone",
                         "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T/B/x"},
    }))
    cfg.load()  # read as before: the extensions find their keys in the environment
    assert os.environ["TYPESAFE_API_KEY"] == "ts-key" and os.environ["TELEGRAM_CHAT_ID"] == "-1001"
    assert os.environ["CLOUDFLARE_API_TOKEN"] == "cf-token"

    cfg.save(cfg.read())
    saved = json.loads(config_file.read_text())
    assert "integrations" not in saved and "TYPESAFE_API_KEY" not in saved["classifier"]
    assert "TELEGRAM_BOT_TOKEN" not in saved["notifications"]
    assert saved["extension:typesafe"]["TYPESAFE_API_KEY"] == "ts-key"
    assert saved["extension:telegram"] == {"TELEGRAM_BOT_TOKEN": "123:abc", "TELEGRAM_CHAT_ID": "-1001",
                                           "TELEGRAM_GROUP_COPY": "fallback", "TELEGRAM_REPORT_FROM": "alert-chat"}
    assert saved["extension:cloudflare"]["CLOUDFLARE_ZONE_ID"] == "zone"
    assert saved["extension:slack"]["SLACK_WEBHOOK_URL"].startswith("https://hooks.slack.com/")
    assert cfg.read()["CLOUDFLARE_API_TOKEN"] == "cf-token"


def test_an_uninstalled_extensions_settings_are_kept_when_saving(config_file):
    config_file.write_text(json.dumps({"extension:acme": {"ACME_API_KEY": "k", "ACME_REGION": "eu"},
                                       "integrations": {"OLD_THING_KEY": "x"},
                                       "ai": {"SENTRAI_LLM_PROVIDER": "openai", "OPENAI_API_KEY": "sk-old"}}))
    values = cfg.read()
    assert values["ACME_API_KEY"] == "k"  # still loaded, for when it is installed again
    cfg.save(values | {"SENTRAI_PRESET": "strict"})
    saved = json.loads(config_file.read_text())
    assert saved["extension:acme"] == {"ACME_API_KEY": "k", "ACME_REGION": "eu"}
    assert saved["integrations"] == {"OLD_THING_KEY": "x"}
    assert "OPENAI_API_KEY" not in saved["ai"] and saved["ai"]["SENTRAI_LLM_API_KEY"] == "sk-old"  # moved, not kept twice


def test_wizard_skips_an_extension_without_its_key_and_never_asks_advanced(config_file):
    asked = []

    def ask(prompt):
        asked.append(prompt)
        return "zone-1" if "Cloudflare zone id" in prompt else ""

    def ask_secret(prompt):
        asked.append(prompt)
        return "cf-token" if "Cloudflare API token" in prompt else ""

    said = []
    values = cfg.wizard(ask=ask, ask_secret=ask_secret, say=said.append)
    assert values["CLOUDFLARE_API_TOKEN"] == "cf-token" and values["CLOUDFLARE_ZONE_ID"] == "zone-1"
    assert any("Telegram bot token" in p for p in asked)
    assert not any("Telegram chat id" in p for p in asked)  # no token, so no chat id question
    advanced = [f for s in cfg.EXTENSION_SECTIONS.values() for f in s.fields if f.advanced]
    assert advanced and not any(f.prompt in p for f in advanced for p in asked)
    assert all(values[f.env] == f.default for f in advanced)
    assert any(line.startswith("\nExtensions: ") for line in said)


def test_without_the_extensions_module_there_are_no_extension_sections(monkeypatch):
    monkeypatch.setattr(cfg, "sentrai_extensions", None)
    assert cfg.extension_sections() == {}


def test_an_extension_cannot_take_over_a_sentrai_setting(tmp_path):
    folder = tmp_path / "acme"
    folder.mkdir()
    (folder / "extension.json").write_text(json.dumps({
        "name": "acme", "title": "Acme", "kind": "Other", "what": "Test.", "on_when": ["ACME_KEY"],
        "settings": [{"env": "SENTRAI_API_TOKEN", "prompt": "steal it"}, {"env": "ACME_KEY", "prompt": "key"},
                     {"env": "CLOUDFLARE_API_TOKEN", "prompt": "and this"}]}))
    (folder / "core.py").write_text("def setup(ctx):\n    return None\n")
    sections = cfg.extension_sections({"SENTRAI_EXTENSIONS_DIR": str(tmp_path)})
    assert [f.env for f in sections["acme"].fields] == ["ACME_KEY"]
    assert [f.env for f in sections["cloudflare"].fields][0] == "CLOUDFLARE_API_TOKEN"  # bundled one keeps it


def test_show_lists_the_extension_settings_and_get_reads_them(config_file, monkeypatch, capsys):
    monkeypatch.delenv("CLOUDFLARE_MODE", raising=False)
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    cfg.save({"TELEGRAM_BOT_TOKEN": "123:abc"})
    cfg.mark_setup_done("test")
    assert cfg.main([]) == 0
    out = capsys.readouterr().out
    assert "[Telegram extension]" in out and "TELEGRAM_BOT_TOKEN" in out and "123:abc" not in out
    assert cfg.main(["get", "CLOUDFLARE_MODE"]) == 0
    assert capsys.readouterr().out.strip() == "block"
