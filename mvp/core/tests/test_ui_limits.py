"""The web dashboard's Automation guardrails (limits map) endpoints."""
import os

import pytest

import sentrai_config as cfg


@pytest.fixture(autouse=True)
def own_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(cfg, "config_path", lambda: tmp_path / "settings.json")
    before = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(before)


def test_map_data_has_the_limits_and_actions(client):
    d = client.get("/ui/limits").json()
    assert set(d["settings"]) >= {"AUTO_ACTIONS", "RISK_THRESHOLD", "PROTECTED_IPS"} and d["read_only"] is False
    assert ["block_ip", "block an address"] in d["actions"] and d["changed"] == {}


def test_save_checks_then_writes_and_leaves_a_note(client):
    d = client.get("/ui/limits").json()
    bad = client.post("/ui/limits", json={"settings": {**d["settings"], "RISK_THRESHOLD": "150"}})
    assert bad.status_code == 400 and bad.json()["detail"].startswith("Not saved:")
    ok = client.post("/ui/limits", json={"settings": {**d["settings"], "RISK_THRESHOLD": "70", "AUTO_ACTIONS": "block_ip"}})
    assert ok.status_code == 200 and "Saved to" in ok.json()["message"]
    after = client.get("/ui/limits").json()
    assert after["settings"]["RISK_THRESHOLD"] == "70" and after["settings"]["AUTO_ACTIONS"] == "block_ip"
    assert after["changed"]["by"]
