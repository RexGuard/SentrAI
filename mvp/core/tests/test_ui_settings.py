"""The web dashboard's Configuration endpoints."""
import os

import pytest

import sentrai_config as cfg


@pytest.fixture(autouse=True)
def own_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(cfg, "config_path", lambda: tmp_path / "settings.json")
    before = dict(os.environ)
    yield
    os.environ.clear()  # a save reloads the AI and extensions, which load saved values into the environment
    os.environ.update(before)


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


def test_advanced_settings_are_read_only_in_the_panel(client):
    fields = {f["env"]: f for s in client.get("/ui/settings").json()["sections"] for f in s["fields"]}
    assert fields["TRUSTED_IPS"]["advanced"] and not fields["BRUTE_FORCE_COUNT"]["advanced"]
    r = client.post("/ui/settings", json={"values": {"BRUTE_FORCE_COUNT": "8", "TRUSTED_IPS": "203.0.113.0/24"}})
    assert r.status_code == 403 and "sudo sentrai settings set TRUSTED_IPS" in r.json()["detail"]
    assert "BRUTE_FORCE_COUNT" not in cfg.read()  # nothing written when any part is refused


def test_secrets_show_only_their_last_characters():
    assert cfg.mask("") == "" and cfg.mask("short") == "set"
    assert cfg.mask("smtp-password-a1b2") == "…a1b2"
    assert "password" not in cfg.mask("smtp-password-a1b2")


def test_a_save_is_audited_without_secret_values(client):
    r = client.post("/ui/settings", json={"values": {"BRUTE_FORCE_COUNT": "9", "SMTP_PASSWORD": "app-password-zz99"}})
    assert r.status_code == 200
    rec = [x for x in client.core.audit.records() if x["type"] == "settings_changed"][-1]["data"]
    by = {c["env"]: c for c in rec["changed"]}
    assert by["BRUTE_FORCE_COUNT"]["to"] == "9" and by["SMTP_PASSWORD"] == {"env": "SMTP_PASSWORD", "what": "set", "now": "…zz99"}
    assert "app-password" not in str(rec)
    fields = {f["env"]: f for s in client.get("/ui/settings").json()["sections"] for f in s["fields"]}
    assert fields["SMTP_PASSWORD"]["hint"] == "…zz99" and fields["SMTP_PASSWORD"]["value"] == ""
    # saving the same values again changes nothing, so nothing new is written down
    n = len(client.core.audit.records())
    client.post("/ui/settings", json={"values": {"BRUTE_FORCE_COUNT": "9", "SMTP_PASSWORD": ""}})
    assert len(client.core.audit.records()) == n


def test_cli_shows_how_a_secret_ends():
    import sentrai_cli as cli
    assert cli.secret_text({"is_set": True, "hint": "…zz99"}) == "(set, ends in zz99)"
    assert cli.secret_text({"is_set": True, "hint": "set"}) == "(set)" and cli.secret_text({"is_set": False}) == "(empty)"
