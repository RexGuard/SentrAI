"""Machines set up before the CactAI -> SentrAI rename keep working (mvp/sentrai_env.py)."""
from __future__ import annotations

import json

from collector import paths

cfg = paths.sentrai_config
env = cfg.sentrai_env


def test_old_variables_fill_in_unset_new_ones():
    environ = {"CACTAI_FIREWALL": "nftables", "CACTAI_CORE_PORT": "8100", "SENTRAI_CORE_PORT": "8200"}
    assert env.adopt_old_names(environ) == ["CACTAI_CORE_PORT", "CACTAI_FIREWALL"]
    assert environ["SENTRAI_FIREWALL"] == "nftables"
    assert environ["SENTRAI_CORE_PORT"] == "8200"  # a new name that is set wins


def test_settings_file_with_old_keys_is_read_under_new_names(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"responder": {"CACTAI_FIREWALL": "iptables"}}), encoding="utf-8")
    monkeypatch.setenv("SENTRAI_CONFIG", str(path))
    assert cfg.read()["SENTRAI_FIREWALL"] == "iptables"


def test_old_settings_folder_moves_to_the_new_one(tmp_path, monkeypatch):
    monkeypatch.setattr(env.Path, "home", lambda: tmp_path)
    (tmp_path / ".cactai").mkdir()
    (tmp_path / ".cactai" / "config.json").write_text("{}", encoding="utf-8")
    assert env.home_dir() == tmp_path / ".sentrai"
    assert (tmp_path / ".sentrai" / "config.json").exists()
    assert not (tmp_path / ".cactai").exists()
    assert env.home_dir() == tmp_path / ".sentrai"  # nothing left to move the second time
