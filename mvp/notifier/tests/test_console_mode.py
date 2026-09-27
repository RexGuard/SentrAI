import io

import requests

from core import Core
from notifier import console_sender, main, process_pending


def test_console_mode_delivers_and_marks(fake_core):
    requests.post(f"{fake_core}/demo/reset", timeout=3)
    requests.post(f"{fake_core}/dev/trigger/brute_force", timeout=3)
    core = Core(fake_core)
    assert len(core.pending()) == 1
    buf = io.StringIO()
    seen: set[str] = set()
    ids = process_pending(core, console_sender(buf, color=False), "console", seen)
    assert len(ids) == 1
    text = buf.getvalue()
    assert "CactAI" in text and "Brute force" in text and "Approve & Patch" in text
    assert core.pending() == []
    audit = requests.get(f"{fake_core}/audit", timeout=3).json()["records"]
    rec = [r for r in audit if r["type"] == "notification_delivered"][-1]
    assert rec["data"]["channel"] == "console"
    assert str(rec["data"]["message_id"]).startswith("console-")
    # second pass: nothing new
    assert process_pending(core, console_sender(io.StringIO(), color=False), "console", seen) == []


def test_main_falls_back_to_console_without_env(fake_core, monkeypatch, capsys):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    requests.post(f"{fake_core}/dev/trigger/sql_injection", timeout=3)
    assert main(["--core", fake_core, "--once"]) == 0
    out = capsys.readouterr().out
    assert "CONSOLE mode" in out and "SQL injection" in out
    assert Core(fake_core).pending() == []


def test_console_mode_survives_core_down(capsys):
    assert main(["--core", "http://127.0.0.1:9", "--once"]) == 0
    assert "core unavailable" in capsys.readouterr().out
