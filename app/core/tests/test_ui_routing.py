"""The web dashboard's Who gets what endpoints."""
import os

import pytest

import sentrai_config as cfg


@pytest.fixture(autouse=True)
def own_files(tmp_path, monkeypatch):
    monkeypatch.setattr(cfg, "config_path", lambda: tmp_path / "settings.json")
    before = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(before)


def test_editor_data_has_the_people_and_rules(client):
    page = client.get("/ui/routing").json()
    editor = page["editor"]
    assert editor["routing"]["contacts"] and editor["routing"]["rules"] and editor["read_only"] is False
    assert editor["categories"] and editor["severities"]


def test_save_round_trips_and_a_bad_file_is_refused(client):
    editor = client.get("/ui/routing").json()["editor"]
    ok = client.post("/ui/routing", json={"routing": editor["routing"], "summary": "no change"})
    assert ok.status_code == 200 and ok.json()["message"].startswith("Saved")
    broken = {**editor["routing"], "rules": [{"name": "x", "match": {}, "owner": "nobody-here", "notify": []}]}
    bad = client.post("/ui/routing", json={"routing": broken, "summary": "bad"})
    assert bad.status_code == 400 and bad.json()["detail"]
