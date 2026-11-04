"""The web dashboard's Overview canvas endpoints."""
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


def test_canvas_data_has_the_steps_and_their_wires(client):
    page = client.get("/ui/overview").json()
    ids = [b["id"] for b in page["blocks"]]
    assert {"step:logs", "step:sort", "step:block"} <= set(ids)
    assert page["wires"] and page["read_only"] is False and "doc" in page


def test_layout_is_saved_and_comes_back(client):
    doc = {"v": 1, "pos": {"step:logs": [40, 60]}, "hidden": [], "notes": {}, "wires": [], "removed": []}
    assert client.post("/ui/overview/layout", json={"doc": doc}).status_code == 200
    saved = client.get("/ui/overview").json()["doc"]
    assert saved["pos"].get("step:logs") == [40, 60] or saved["pos"].get("step:logs") == {"x": 40, "y": 60}


def test_block_settings_are_checked_before_saving(client):
    page = client.get("/ui/overview").json()
    block = next(b for b in page["blocks"] if b["settings"])
    env = block["settings"][0]["env"]
    r = client.post("/ui/overview/settings", json={"block": block["id"], "changes": {"NOT_OFFERED": "1"}})
    assert r.status_code == 400
    assert client.post("/ui/overview/settings", json={"block": "step:nothing", "changes": {env: "1"}}).status_code == 404


def test_toggle_refuses_a_bad_name(client):
    assert client.post("/ui/overview/toggle", json={"name": "../x", "on": True}).status_code == 400
    assert client.post("/ui/overview/toggle", json={"name": "nosuchone", "on": True}).status_code in (400, 404)
