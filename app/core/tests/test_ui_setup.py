"""The web dashboard's guided setup (Cyanide asks the setup questions)."""
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


def test_nothing_is_open_until_started_and_leaving_closes_it(client):
    assert client.get("/ui/setup").json()["active"] is False
    assert client.post("/ui/setup/answer", json={"text": "x"}).status_code == 409
    s = client.post("/ui/setup/start").json()
    assert s["active"] and s["state"] == "asking" and s["messages"][0]["role"] == "assistant" and s["options"]
    assert client.get("/ui/setup").json()["active"] is True
    assert client.post("/ui/setup/leave").json()["active"] is False


def test_walks_to_the_summary_and_saves_only_when_confirmed(client):
    s = client.post("/ui/setup/start").json()
    for _ in range(40):  # take the first button, or a plain answer, until the summary
        if s["state"] != "asking":
            break
        if s["secret"]:
            text = "hidden-secret"
        elif s["options"]:
            values = [o["value"] for o in s["options"]]
            text = next((v for v in ("none", "skip", "keep", "local", "console") if v in values), values[0])
        else:
            text = "none"
        s = client.post("/ui/setup/answer", json={"text": text}).json()
    assert s["state"] == "review", s["messages"][-1]["text"]
    assert not cfg.setup_done()  # nothing is saved before the confirmation
    assert "hidden-secret" not in str(s["messages"])
    s = client.post("/ui/setup/answer", json={"text": "save"}).json()
    assert s["state"] == "saved" and "Saved to" in s["messages"][-1]["text"]
    assert cfg.setup_done() and s["done"] is True
