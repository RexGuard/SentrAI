"""Backups: chosen folders plus SentrAI's own data, checked against the audit trail, restored by a person."""

import json
import tarfile

import pytest


@pytest.fixture
def site(tmp_path, monkeypatch):
    root = tmp_path / "www"
    (root / "img").mkdir(parents=True)
    (root / "index.php").write_text("<?php echo 'hello';")
    (root / "img" / "logo.png").write_bytes(bytes(range(256)) * 10)
    (root / "__pycache__").mkdir()
    (root / "__pycache__" / "x.pyc").write_bytes(b"skip me")
    monkeypatch.setenv("CACTAI_BACKUP_PATHS", str(root))
    monkeypatch.setenv("CACTAI_BACKUP_DIR", str(tmp_path / "backups"))
    return root


def backup(client):
    r = client.post("/backups", json={"operator": "erick"})
    assert r.status_code == 200
    return r.json()


def test_backup_takes_folders_and_sentrai_data(client, site, tmp_path):
    b = backup(client)
    assert b["ok"], b
    names = {f["name"] for f in json.loads(
        tarfile.open(tmp_path / "backups" / f"{b['id']}.tar.gz").extractfile("manifest.json").read())["files"]}
    assert {"files/0/index.php", "files/0/img/logo.png", "sentrai/data/cactai.db"} <= names
    assert not any("__pycache__" in n for n in names)
    status = client.get("/backups").json()
    assert status["backups"][0]["id"] == b["id"] and "real_roots" not in status["backups"][0]
    rec = [r for r in client.core.audit.records() if r["type"] == "backup_made"][-1]["data"]
    assert rec["sha256"] == b["sha256"] and rec["by"] == "erick"


def test_verify_catches_a_swapped_archive(client, site, tmp_path):
    b = backup(client)
    assert client.post(f"/backups/{b['id']}/verify", json={"operator": "erick"}).json()["ok"]
    archive = tmp_path / "backups" / f"{b['id']}.tar.gz"
    archive.write_bytes(archive.read_bytes()[:-20] + b"x" * 20)
    out = client.post(f"/backups/{b['id']}/verify", json={"operator": "erick"}).json()
    assert not out["ok"] and "changed" in out["problems"][0]
    # A broken backup is never restored.
    r = client.post(f"/backups/{b['id']}/restore", json={"operator": "erick"})
    assert r.status_code == 409


def test_restore_to_new_folder_changes_nothing_live(client, site):
    b = backup(client)
    (site / "index.php").write_text("<?php system($_GET['c']);")  # defaced after the backup
    out = client.post(f"/backups/{b['id']}/restore", json={"operator": "erick"}).json()
    assert out["ok"] and not out["in_place"]
    assert "system(" in (site / "index.php").read_text()
    restored = client.core.settings.db_path.parent / "restores"
    copies = list(restored.glob(f"{b['id']}-*/files/0-www/index.php"))
    assert copies and copies[0].read_text() == "<?php echo 'hello';"
    assert list(restored.glob(f"{b['id']}-*/sentrai/data/cactai.db"))
    rec = [r for r in client.core.audit.records() if r["type"] == "backup_restored"][-1]["data"]
    assert rec["ok"] and rec["operator"] == "erick"


def test_in_place_restore_needs_confirmation_and_takes_safety_backup(client, site):
    b = backup(client)
    (site / "index.php").write_text("defaced")
    r = client.post(f"/backups/{b['id']}/restore", json={"operator": "erick", "in_place": True})
    assert r.status_code == 409 and "type the backup id" in r.json()["detail"]
    out = client.post(f"/backups/{b['id']}/restore",
                      json={"operator": "erick", "in_place": True, "confirm": b["id"]}).json()
    assert out["ok"] and out["safety_backup"]
    assert (site / "index.php").read_text() == "<?php echo 'hello';"
    # The restore can be undone from the safety backup.
    undo = client.post(f"/backups/{out['safety_backup']}/restore",
                       json={"operator": "erick", "in_place": True, "confirm": out["safety_backup"]}).json()
    assert undo["ok"] and (site / "index.php").read_text() == "defaced"


def test_failed_backup_alerts(client, tmp_path, monkeypatch):
    monkeypatch.setenv("CACTAI_BACKUP_PATHS", str(tmp_path / "nope"))
    monkeypatch.setenv("CACTAI_BACKUP_DIR", str(tmp_path / "backups"))
    client.core.profile = {"backup": {"include_sentrai": False}}
    out = backup(client)
    assert not out["ok"] and "nothing to back up" in out["error"]
    assert client.core.notifications[-1]["kind"] == "backup_failed"
    assert any(r["type"] == "backup_failed" for r in client.core.audit.records())


def test_keeps_only_the_newest(client, site, monkeypatch):
    monkeypatch.setenv("CACTAI_BACKUP_KEEP", "2")
    ids = [backup(client)["id"] for _ in range(3)]
    left = [b["id"] for b in client.get("/backups").json()["backups"]]
    assert left == [ids[2], ids[1]]


def test_bad_ids_are_refused(client, site):
    for bid in ("../etc", "b-..", "x"):
        assert client.post(f"/backups/{bid}/verify", json={}).status_code == 404


def test_copy_to_second_place(client, site, tmp_path, monkeypatch):
    monkeypatch.setenv("CACTAI_BACKUP_COPY_TO", str(tmp_path / "usb"))
    b = backup(client)
    assert b["copy"]["ok"] and (tmp_path / "usb" / f"{b['id']}.tar.gz").is_file()


def test_chat_fallback_lists_backups_and_offers_button(client, site):
    backup(client)
    reply = client.post("/chat", json={"operator": "erick", "message": "when was the last backup?"}).json()
    assert "last backup" in reply["text"] and any(s.get("kind") == "backup_now" for s in reply["suggestions"])
