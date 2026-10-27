"""Test set-up shared by every bundled extension's tests (mvp/extensions/<name>/tests/).

Each extension has two kinds of tests, told apart by the file name, because each side needs its own venv:

    cd mvp/extensions && ../core/.venv/bin/python -m pytest -q --ignore-glob='*_notifier.py'      # test_<name>_core.py
    cd mvp/extensions && ../notifier/.venv/bin/python -m pytest -q --ignore-glob='*_core.py'      # test_<name>_notifier.py

(Scripts/python.exe on Windows.) File names must be unique across extensions: pytest imports them by name.
This file only puts mvp/, mvp/core and mvp/notifier on the import path and makes sure no test can reach a
real outside service; the test files import what they need themselves.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

MVP = Path(__file__).resolve().parents[1]
for _part in ("notifier", "core", "."):
    _p = str((MVP / _part).resolve())
    if _p not in sys.path:
        sys.path.insert(0, _p)

_TMP = Path(tempfile.mkdtemp(prefix="sentrai-ext-test-"))
os.environ["SENTRAI_DB"] = str(_TMP / "import.db")  # app.main builds a module-level app when imported
os.environ["SENTRAI_BACKGROUND"] = "0"
os.environ["SENTRAI_CONFIG"] = str(_TMP / "no-config.json")  # ignore this machine's saved settings
os.environ["SENTRAI_API_TOKEN"] = "test-token"
os.environ["CYANIDE_ENABLED"] = "0"
for _name in ("TYPESAFE_API_KEY", "CLOUDFLARE_API_TOKEN", "ABUSEIPDB_API_KEY", "SLACK_WEBHOOK_URL",
              "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "SENTRAI_EXTENSIONS", "SENTRAI_EXTENSIONS_DIR",
              "SENTRAI_TELEGRAM_LINKS"):
    os.environ.pop(_name, None)  # never call a real service; each test sets what it needs with monkeypatch

import json  # noqa: E402

import pytest  # noqa: E402

AUTH = {"Authorization": "Bearer test-token"}
ATTACKER = "45.33.32.156"  # a public address (203.0.113.x is a documentation range, never sent out)


def ev(n, raw, ip=ATTACKER, user="admin", layer="web", host="web-01", source="flask_auth"):
    return {"event_id": f"evt-ext-{n}", "timestamp": "2026-10-27T14:00:%02d+08:00" % (n % 60), "host": host,
            "layer": layer, "source": source, "src_ip": ip, "user": user, "raw": raw, "asset_criticality": 1.5}


def brute_force(client, ip=ATTACKER, start=0, count=5):
    return [client.post("/events", json=ev(start + i, "POST /login 401 user=admin", ip=ip)).json()
            for i in range(count)]


@pytest.fixture
def make_core(tmp_path, monkeypatch):
    """make_core(routing=None, **env): a running core (TestClient with .core) whose environment has `env`.

    Call it again for a restart: the same folder, so saved blocks, links and Add/Remove choices carry over."""
    from fastapi.testclient import TestClient

    from app.config import Settings
    from app.main import create_app

    clients = []

    def make(routing=None, **env):
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        if routing is not None:
            (tmp_path / "routing.json").write_text(json.dumps(routing), encoding="utf-8")
        app = create_app(Settings(db_path=tmp_path / "sentrai.db", background=False, demo_speed=60.0))
        c = TestClient(app, headers=AUTH)
        c.__enter__()
        c.core = app.state.core
        clients.append(c)
        return c

    yield make
    for c in clients:
        c.__exit__(None, None, None)
