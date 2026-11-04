"""The core keeps its files in topic folders next to its database, and moves old loose ones there."""
import json

from fastapi.testclient import TestClient

from app import threats
from app.config import Settings
from app.main import create_app

AUTH = {"Authorization": "Bearer test-token"}


def test_old_loose_files_move_into_topic_folders(tmp_path, monkeypatch):
    monkeypatch.delenv("SENTRAI_MIGRATE", raising=False)  # the conftest turns moves off
    for name in ("SENTRAI_ROUTING", "SENTRAI_TELEGRAM_LINKS", "SENTRAI_THREAT_STATE", "SENTRAI_QUARANTINE"):
        monkeypatch.delenv(name, raising=False)
    routing = {"people": [], "rules": []}
    (tmp_path / "routing.json").write_text(json.dumps(routing), encoding="utf-8")
    (tmp_path / "fleet.json").write_text("{}", encoding="utf-8")
    (tmp_path / "threat_seen.json").write_text("{}", encoding="utf-8")
    app = create_app(Settings(db_path=tmp_path / "sentrai.db", background=False, demo_speed=60.0))
    with TestClient(app, headers=AUTH):
        pass
    assert json.loads((tmp_path / "people" / "routing.json").read_text()) == routing
    assert (tmp_path / "machines" / "fleet.json").exists()
    assert not (tmp_path / "routing.json").exists() and not (tmp_path / "fleet.json").exists()
    assert threats.state_file(tmp_path / "sentrai.db") == tmp_path / "threats" / "threat_seen.json"
    assert (tmp_path / "threats" / "threat_seen.json").exists()
    assert threats.quarantine_dir(tmp_path / "sentrai.db") == tmp_path / "threats" / "quarantine"


def test_files_stay_next_to_the_database(client, tmp_path):
    db_dir = tmp_path
    assert threats.quarantine_dir(client.core.settings.db_path).parent.parent == db_dir
