"""Guided setup in the Chat page (mvp/setup_chat.py): scripted, so no AI key or core is needed."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import cactai_config as cfg  # noqa: E402
import setup_chat  # noqa: E402


@pytest.fixture(autouse=True)
def config_file(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    monkeypatch.setenv("CACTAI_CONFIG", str(path))
    return path


def run(sc, *answers, interpret=None):
    for a in answers:
        sc.answer(a, interpret=interpret)
    return sc


def last(sc):
    return sc.messages[-1]["text"]


def test_starts_with_a_question_and_buttons():
    sc = setup_chat.SetupChat()
    assert "what does SentrAI guard" in last(sc)
    assert [v for v, _ in sc.options()] == ["sensitive", "office", "busy", "unsure"]


def test_walkthrough_with_buttons_and_typing(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    sc = run(setup_chat.SetupChat(),
             "sensitive",                # suggests Strict
             "yes",                      # use it
             str(logs),
             "my admin pc is 192.168.1.20 and 10.0.0.0/24",
             "admin, backup",
             "Erick",
             "telegram",
             "123456789:" + "A" * 30,
             "-1001234",
             "none",                     # no AI key
             )
    values = sc.values()
    assert values[cfg.PRESET_ENV] == "strict" and values["RISK_THRESHOLD"] == "65"
    assert values["CACTAI_LAB_LOGS"] == str(logs.resolve())
    assert "192.168.1.20" in values["PROTECTED_IPS"] and "10.0.0.0/24" in values["PROTECTED_IPS"]
    assert "127.0.0.1" in values["PROTECTED_IPS"]  # the defaults stay
    assert values["PROTECTED_USERS"] == "admin,backup"
    assert values["CACTAI_OPERATOR"] == "Erick" and values["ON_DUTY"] == "Erick"
    assert values["TELEGRAM_CHAT_ID"] == "-1001234" and values["SMTP_HOST"] == ""
    run(sc, "network", "earlier", "8600", "erick@example.com", "s3cret-password")
    assert sc.state == "review" and "Shall I save it?" in last(sc)
    assert cfg.check_password("s3cret-password", values_hash := sc.values()[cfg.HASH_ENV])
    assert "s3cret-password" not in json.dumps(sc.messages) + json.dumps(sc.values()) and values_hash
    assert sc.values()[cfg.EMAIL_ENV] == "erick@example.com"
    assert setup_chat.deploy_command(sc) == ("sudo ./deploy/install.sh --dashboard-allow 192.168.1.20 "
                                             "--dashboard-allow 10.0.0.0/24 --dashboard-port 8600 --no-questions")
    assert "Strict" in last(sc)
    # the bot token is never echoed in the transcript
    assert all("AAAAAAAAAA" not in m["text"] for m in sc.messages)
    sc.answer("save")
    assert sc.state == "save"


def test_bad_answers_are_asked_again(tmp_path):
    sc = run(setup_chat.SetupChat(), "office", "yes")
    sc.answer(str(tmp_path / "nope"))
    assert "can't find a folder" in last(sc) and sc.step.key == "logs"
    sc.answer("demo")
    sc.answer("whatever")
    assert "couldn't find an IP" in last(sc) and sc.step.key == "ips"


def test_unclear_choice_without_ai_asks_for_a_button():
    sc = setup_chat.SetupChat()
    sc.answer("hmm, what do you mean?")
    assert "Please pick one of the buttons" in last(sc) and sc.step.key == "kind"
    sc.answer("2")  # by number
    assert sc.step.key == "preset" and "Moderate" in last(sc)


def test_ai_maps_an_unclear_answer_but_never_sees_secrets():
    seen = []

    def interpret(question, options, answer):
        seen.append(answer)
        return {"choice": "sensitive", "reply": "Patient records are sensitive."}

    sc = setup_chat.SetupChat()
    sc.answer("we are a dental clinic", interpret=interpret)
    assert sc.step.key == "preset" and "Strict" in last(sc) and "Patient records" in last(sc)
    run(sc, "yes", "demo", "none", "none", "keep", "none")  # ... alerts: just the dashboard
    sc.answer("anthropic", interpret=interpret)
    sc.answer("sk-ant-secret", interpret=interpret)
    assert "sk-ant-secret" not in seen and sc.values()["CACTAI_LLM_API_KEY"] == "sk-ant-secret"


def test_review_and_restart():
    sc = run(setup_chat.SetupChat(), "busy", "yes", "demo", "none", "none", "keep", "console", "none",
             "local", "keep", "keep")
    sc.answer("short")
    assert "at least 8" in last(sc)
    sc.answer("long-enough-pw")
    assert sc.state == "review" and setup_chat.deploy_command(sc) == "sudo ./deploy/install.sh --dashboard-local --no-questions"
    sc.answer("restart")
    assert sc.state == "asking" and sc.step.key == "kind" and not sc.answers


def test_setup_done_marker(config_file):
    assert not cfg.setup_done()
    cfg.api_token()  # makes a file with only the generated token
    assert not cfg.setup_done()
    cfg.mark_setup_done("chat")
    assert cfg.setup_done()
    cfg.save(cfg.read())  # saving keeps the marker
    assert json.loads(config_file.read_text())["setup_done"] == "chat"
    assert "setup_done" not in cfg.read()


def test_launcher_sign_in_does_not_count_as_setup(config_file):
    cfg.ensure_admin("me@example.com")  # what run_demo and install.sh do on a first start
    assert not cfg.setup_done()


def test_changed_values_count_as_done(config_file):
    cfg.save({"CACTAI_OPERATOR": "Erick"})  # saved before the marker existed
    assert cfg.setup_done()
