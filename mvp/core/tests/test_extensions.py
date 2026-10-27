"""Extensions (app/extensions.py, mvp/sentrai_extensions.py): the core runs with none, SENTRAI_EXTENSIONS
has the final word, Add and Remove are kept across restarts, and an extension from an extra folder plugs in."""

import json
import os
import stat
import textwrap

import pytest
from fastapi.testclient import TestClient

import sentrai_extensions as se
from app.config import Settings
from app.main import create_app

from .conftest import AUTH, brute_force, ev

BUNDLED = ("typesafe", "telegram", "slack", "cloudflare", "abuseipdb")


def start(tmp_path):
    app = create_app(Settings(db_path=tmp_path / "sentrai.db", background=False, demo_speed=60.0))
    c = TestClient(app, headers=AUTH)
    c.__enter__()
    c.core = app.state.core
    return c


def rows(c):
    return {r["name"]: r for r in c.get("/extensions").json()}


def test_the_core_runs_with_no_extension_added(client):
    r = rows(client)
    assert [n for n in r if not r[n]["built_in"]] == list(BUNDLED)  # page order from the manifests
    assert all(not r[n]["added"] and r[n]["added_by"] == "settings" for n in BUNDLED)
    assert r["webhook"]["built_in"] and r["email"]["built_in"] and r["email"]["added"]
    assert [s.name for s in client.core.classifier.classifiers] == ["rules", "fallback"]
    assert client.core.responders.for_type("block_ip") is client.core.blocklist_responder
    gone = client.get("/telegram/links")
    assert gone.status_code == 404 and "Telegram is not added" in gone.json()["detail"]
    brute_force(client)
    iid = client.get("/incidents").json()[0]["id"]
    client.post(f"/incidents/{iid}/decision", json={"operator": "erick", "decision": "approve"})
    assert client.get(f"/incidents/{iid}").json()["status"] == "contained"
    started = next(x for x in client.get("/audit").json()["records"] if x["type"] == "core_started")
    assert started["data"]["extensions"] == {}


def test_the_core_runs_with_no_extension_installed(tmp_path, monkeypatch):
    monkeypatch.setattr(se, "BUNDLED_DIR", tmp_path / "no-extensions")  # as if mvp/extensions were deleted
    c = start(tmp_path)
    assert [x["name"] for x in c.get("/extensions").json()] == ["webhook", "email"]
    assert c.get("/telegram/links").status_code == 404
    assert c.post("/extensions/cloudflare/add", json={"operator": "erick"}).status_code == 404
    brute_force(c)
    assert c.get("/incidents").json()[0]["classified_by"] == "rules"


def test_sentrai_extensions_on_the_server_has_the_final_word(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRAI_EXTENSIONS", "slack, nope")
    monkeypatch.setenv("TYPESAFE_API_KEY", "ts-key")  # a saved key does not turn it on now
    c = start(tmp_path)
    r = rows(c)
    assert r["slack"]["added"] and not r["typesafe"]["added"]
    assert {r[n]["added_by"] for n in BUNDLED} == {"SENTRAI_EXTENSIONS"}
    assert any("nope" in p for p in c.core.extensions.problems)
    for verb in ("add", "remove"):
        refused = c.post(f"/extensions/typesafe/{verb}", json={"operator": "erick"})
        assert refused.status_code == 409 and "SENTRAI_EXTENSIONS" in refused.json()["detail"]
    monkeypatch.setenv("SENTRAI_EXTENSIONS", "all")
    assert all(x["added"] for x in c.get("/extensions").json())


def test_unknown_names_are_404(client):
    for path in ("/extensions/nope/add", "/extensions/nope/remove"):
        assert client.post(path, json={"operator": "erick"}).status_code == 404
    assert client.post("/extensions/nope/test").status_code == 404
    assert client.post("/integrations/nope/test").status_code == 404
    assert client.post("/integrations/webhook/test").json()["ok"] is False  # built in: no test yet


def test_add_and_remove_are_kept_across_a_restart(tmp_path, monkeypatch):
    c = start(tmp_path)
    row = c.post("/extensions/slack/add", json={"operator": "erick"}).json()
    assert row["added"] and row["added_by"] == "dashboard" and row["changed_by"] == "erick"
    assert row["configured"] is False and "incoming webhook" in row["detail"]  # added, no URL saved yet
    assert rows(start(tmp_path))["slack"]["added"] is True
    c.post("/extensions/slack/remove", json={"operator": "erick"})
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x")
    again = rows(start(tmp_path))["slack"]
    assert again["added"] is False and again["added_by"] == "dashboard"  # removed stays removed
    saved = json.loads((tmp_path / "extensions.json").read_text(encoding="utf-8"))
    assert saved["extensions"]["slack"]["added"] is False and saved["extensions"]["slack"]["by"] == "erick"
    types = [x["type"] for x in c.get("/audit").json()["records"]]
    assert "extension_added" in types and "extension_removed" in types


def test_reload_starts_stops_and_restarts_to_match_the_settings(client, monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/a")
    slack = {x["name"]: x for x in client.post("/extensions/reload").json()}["slack"]
    assert slack["added"] and slack["running"] and slack["configured"]
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/b")
    client.post("/extensions/reload")
    monkeypatch.delenv("SLACK_WEBHOOK_URL")
    client.post("/extensions/reload")
    assert "slack" not in client.core.extensions.running
    changed = [x["data"]["changed"] for x in client.get("/audit").json()["records"] if x["type"] == "extensions_reloaded"]
    assert changed == [{"slack": "started"}, {"slack": "restarted"}, {"slack": "stopped"}]
    client.post("/extensions/reload")  # nothing changed: nothing recorded
    assert len([x for x in client.get("/audit").json()["records"] if x["type"] == "extensions_reloaded"]) == 3


ACME_MANIFEST = {
    "name": "acme", "title": "Acme probe finder", "kind": "Classifier",
    "what": "Spots Acme scanner probes.", "settings": [{"env": "ACME_LEVEL", "prompt": "Level", "default": "3"}],
}
ACME_CORE = '''
    from app.extensions import Classification, Classifier, Extension

    class Probe(Classifier):
        name = "acme"

        def classify(self, event, now):
            if "ACME-PROBE" in str(event.get("raw")):
                return Classification("port_scan", 0.9, 0.9, "an Acme scanner probe")
            return None

    class Acme(Extension):
        def classifiers(self):
            return [Probe()]

        def status(self):
            return {"configured": True, "detail": "level " + LEVEL[0]}

    LEVEL = []

    def setup(ctx):
        LEVEL[:] = [ctx.setting("ACME_LEVEL")]
        return Acme()
'''


def acme(base, core=ACME_CORE):
    folder = base / "acme"
    folder.mkdir(parents=True)
    (folder / "extension.json").write_text(json.dumps(ACME_MANIFEST), encoding="utf-8")
    (folder / "core.py").write_text(textwrap.dedent(core), encoding="utf-8")
    for p in (base, folder):
        p.chmod(0o755)
    return base


def test_an_extension_from_an_extra_folder_plugs_in(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRAI_EXTENSIONS_DIR", str(acme(tmp_path / "more")))
    c = start(tmp_path)
    row = rows(c)["acme"]
    assert row["source"] == str(tmp_path / "more") and row["added"] is False  # no on_when: added by hand
    assert c.post("/extensions/acme/add", json={"operator": "erick"}).json()["detail"] == "level 3"
    assert [s.name for s in c.core.classifier.classifiers] == ["rules", "acme", "fallback"]
    c.post("/events", json=ev(1, "ACME-PROBE banner grab", ip="198.51.100.30", layer="network", source="fw"))
    assert c.get("/incidents").json()[0]["classified_by"] == "acme"
    c.post("/extensions/acme/remove", json={"operator": "erick"})
    assert [s.name for s in c.core.classifier.classifiers] == ["rules", "fallback"]


def test_a_broken_extension_never_stops_the_core(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRAI_EXTENSIONS_DIR", str(acme(tmp_path / "more", "raise RuntimeError('boom')\n")))
    monkeypatch.setenv("SENTRAI_EXTENSIONS", "acme")
    c = start(tmp_path)
    row = rows(c)["acme"]
    assert row["added"] and not row["running"] and "boom" in row["error"] and row["configured"] is False
    brute_force(c)
    assert c.get("/incidents").json()[0]["classified_by"] == "rules"


@pytest.mark.skipif(os.name != "posix", reason="Windows folders are guarded by their ACLs, not mode bits")
def test_a_folder_others_can_change_is_skipped(tmp_path, monkeypatch):
    base = acme(tmp_path / "more")
    (base / "acme").chmod(0o777)
    monkeypatch.setenv("SENTRAI_EXTENSIONS_DIR", str(base))
    found, problems = se.discover()
    assert "acme" not in found and any("other users" in p for p in problems)
    (base / "acme").chmod(0o755)
    (base / "acme" / "core.py").chmod(0o666)
    found, problems = se.discover()
    assert "acme" not in found and any("core.py" in p for p in problems)


def test_a_bundled_name_cannot_be_taken_over(tmp_path, monkeypatch):
    base = tmp_path / "more"
    folder = base / "slack"
    folder.mkdir(parents=True)
    (folder / "extension.json").write_text(json.dumps({**ACME_MANIFEST, "name": "slack"}), encoding="utf-8")
    (folder / "core.py").write_text("def setup(ctx):\n    raise SystemExit\n", encoding="utf-8")
    for p in (base, folder):
        p.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    monkeypatch.setenv("SENTRAI_EXTENSIONS_DIR", str(base))
    found, problems = se.discover()
    assert found["slack"].source == "bundled" and any("already installed" in p for p in problems)


def test_manifests_are_checked():
    good = {"name": "x1", "title": "X", "what": "Does x."}
    for bad, why in ((dict(good, name="webhook"), "built into SentrAI"), (dict(good, kind="Weird"), "kind"),
                     (dict(good, on_when=["NOPE"]), "on_when"), (dict(good, settings=[{"env": "bad name", "prompt": "p"}]),
                                                                 "environment variable"),
                     (dict(good, order="1"), "whole number")):
        with pytest.raises(ValueError, match=why):
            se.read_manifest(_folder(bad), "test")


def _folder(manifest):
    import tempfile
    from pathlib import Path

    folder = Path(tempfile.mkdtemp()) / manifest["name"]
    folder.mkdir()
    (folder / "extension.json").write_text(json.dumps(manifest), encoding="utf-8")
    (folder / "core.py").write_text("", encoding="utf-8")
    return folder
