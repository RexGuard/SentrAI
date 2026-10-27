"""sentrai_paths: one data root, one folder per part, old files moved in by renaming only."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # mvp/
import sentrai_paths as sp  # noqa: E402

PINNED = ("SENTRAI_HOME", "SENTRAI_CONFIG", "SENTRAI_DB", "SENTRAI_COLLECTOR_STATE", "SENTRAI_SCOUT_SOURCES",
          "SENTRAI_SCOUT_PENDING", "SENTRAI_SCOUT_TRAILS", "SENTRAI_AGENT_FILE", "SENTRAI_ACCOUNTS",
          "SENTRAI_LAB_LOGS", "SENTRAI_BACKUP_DIR", "SENTRAI_QUARANTINE", "SENTRAI_THREAT_STATE",
          "SENTRAI_ROUTING", "SENTRAI_TELEGRAM_LINKS", "SENTRAI_STAFF_REPORTS", "NOTIFIER_WITNESS_FILE")


@pytest.fixture
def home(tmp_path, monkeypatch):
    """An empty root, a fake checkout, moves turned on (the conftest turns them off)."""
    for name in PINNED:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("SENTRAI_MIGRATE", raising=False)
    root = tmp_path / "root"
    monkeypatch.setenv("SENTRAI_HOME", str(root))
    checkout = tmp_path / "mvp"
    monkeypatch.setattr(sp, "MVP_DIR", checkout)
    monkeypatch.setattr(sp, "moved", [])
    monkeypatch.setattr(sp, "_warned", set())
    return root, checkout


def write(p: Path, text: str = "x") -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def test_root_order(tmp_path, monkeypatch):
    monkeypatch.delenv("SENTRAI_HOME", raising=False)
    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "conf" / "config.json"))
    assert sp.root() == tmp_path / "conf"
    monkeypatch.setenv("SENTRAI_HOME", str(tmp_path / "home"))
    assert sp.root() == tmp_path / "home"


def test_tree_and_variables_win(home, tmp_path, monkeypatch):
    root, _ = home
    assert sp.path("core.routing") == root / "core" / "people" / "routing.json"
    assert sp.path("core.quarantine") == root / "core" / "threats" / "quarantine"
    assert sp.path("collector.state") == root / "collector" / "state.json"
    assert sp.path("agent.file") == root / "agent" / "agent.json"
    monkeypatch.setenv("SENTRAI_DB", str(tmp_path / "db" / "sentrai.db"))
    assert sp.path("core.fleet") == tmp_path / "db" / "machines" / "fleet.json"  # next to the database
    monkeypatch.setenv("SENTRAI_SCOUT_SOURCES", str(tmp_path / "s" / "sources.json"))
    assert sp.path("scout.pending") == tmp_path / "s" / "pending.json"  # next to sources.json
    monkeypatch.setenv("SENTRAI_ROUTING", str(tmp_path / "r.json"))
    assert sp.path("core.routing") == tmp_path / "r.json"


def test_old_laptop_layout_moves_once_and_nothing_is_lost(home):
    root, mvp = home
    write(mvp / "core" / "data" / "cactai.db", "db")
    write(mvp / "core" / "data" / "cactai.db-wal", "wal")
    write(mvp / "core" / "data" / "routing.json", "{}")
    write(mvp / "core" / "data" / "quarantine" / "q-1.bin", "q")
    write(mvp / "lab" / "scout" / "sources.json", "[]")
    write(mvp / "lab" / "scout" / "trails" / "example-linux.jsonl", "e")
    write(mvp / "lab" / "scout" / "trails" / "2026-10-01.jsonl", "t")
    write(mvp / "notifier" / "data" / "last_witness.txt", "w")
    write(root / "collector-state.json", "{}")
    write(root / "agent.json", "{}")

    sp.migrate_all()
    assert (root / "core" / "sentrai.db").read_text() == "db"
    assert (root / "core" / "sentrai.db-wal").read_text() == "wal"
    assert (root / "core" / "people" / "routing.json").exists()
    assert (root / "core" / "threats" / "quarantine" / "q-1.bin").exists()
    assert (root / "scout" / "sources.json").exists()
    assert (root / "scout" / "trails" / "2026-10-01.jsonl").exists()
    assert (root / "scout" / "trails" / "example-linux.jsonl").exists()  # the folder starts with the examples
    assert (mvp / "lab" / "scout" / "trails" / "example-linux.jsonl").exists()  # shipped file stays
    assert (root / "notifier" / "last_witness.txt").read_text() == "w"
    assert (root / "collector" / "state.json").exists() and (root / "agent" / "agent.json").exists()
    assert not (mvp / "core" / "data").exists() and not (root / "agent.json").exists()

    first = len(sp.moved)
    sp.migrate_all()
    assert len(sp.moved) == first  # nothing left to move


def test_never_overwrites_and_names_the_leftover(home, capsys):
    root, mvp = home
    write(root / "scout" / "sources.json", "new")
    write(mvp / "lab" / "scout" / "sources.json", "old")
    assert sp.path("scout.sources") == root / "scout" / "sources.json"
    assert (root / "scout" / "sources.json").read_text() == "new"
    assert (mvp / "lab" / "scout" / "sources.json").read_text() == "old"
    assert "is the one in use" in capsys.readouterr().err


def test_moves_off_leaves_old_files(home, monkeypatch):
    root, mvp = home
    monkeypatch.setenv("SENTRAI_MIGRATE", "off")
    old = write(mvp / "lab" / "scout" / "sources.json", "[]")
    assert sp.path("scout.sources") == root / "scout" / "sources.json"
    assert old.exists()


def test_failed_move_keeps_the_old_place(home, monkeypatch, capsys):
    root, _ = home
    old = write(root / "collector-state.json", "{}")

    def refuse(self, target):
        raise PermissionError(13, "in use")
    monkeypatch.setattr(Path, "rename", refuse)
    assert sp.path("collector.state") == old
    assert "could not move" in capsys.readouterr().err


def test_own_dirs_are_only_data_folders(home, tmp_path, monkeypatch):
    root, _ = home
    monkeypatch.setenv("SENTRAI_AGENT_FILE", str(tmp_path / "agent.json"))
    dirs = sp.own_dirs()
    assert root / "core" / "threats" / "quarantine" in dirs and tmp_path / "backups" in dirs
    assert tmp_path not in dirs and root not in dirs and root / "logs" not in dirs


def test_index_lists_every_file(home):
    root, _ = home
    target = sp.write_index()
    text = target.read_text(encoding="utf-8")
    assert target == root / "INDEX.md"
    for key in sp.ENTRIES:
        assert sp.ENTRIES[key].what in text
    assert sp.main(["nope"]) == 2
