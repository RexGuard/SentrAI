"""The web dashboard's Configuration endpoints."""
import pytest

import sentrai_config as cfg


@pytest.fixture(autouse=True)
def own_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(cfg, "config_path", lambda: tmp_path / "settings.json")


def test_lists_sections_without_secrets(client):
    page = client.get("/ui/settings").json()
    fields = [f for s in page["sections"] for f in s["fields"]]
    assert fields and page["presets"] and page["advanced"] == "advanced"
    assert all(f["value"] == "" for f in fields if f["secret"] or f["generated"])


def test_save_checks_then_writes(client):
    bad = client.post("/ui/settings", json={"values": {"BRUTE_FORCE_COUNT": "many"}})
    assert bad.status_code == 400 and "Failed logins" in bad.json()["detail"]
    ok = client.post("/ui/settings", json={"values": {"BRUTE_FORCE_COUNT": "8"}})
    assert ok.status_code == 200 and ok.json()["saved"] == ["BRUTE_FORCE_COUNT"]
    fields = {f["env"]: f for s in client.get("/ui/settings").json()["sections"] for f in s["fields"]}
    assert fields["BRUTE_FORCE_COUNT"]["value"] == "8"


def test_unknown_and_generated_settings_are_refused(client):
    assert client.post("/ui/settings", json={"values": {"NOT_A_SETTING": "1"}}).status_code == 400
    assert client.post("/ui/settings", json={"values": {cfg.TOKEN_ENV: "x"}}).status_code == 400
    assert client.post("/ui/settings", json={}).status_code == 400
