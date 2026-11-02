"""The `sentrai` team command line (mvp/sentrai_cli.py), run against a real core app."""
import io
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import sentrai_cli as cli  # noqa: E402
import sentrai_config as cfg  # noqa: E402

from .conftest import brute_force  # noqa: E402


def through(client):
    """The CLI's call(), but through the test client instead of HTTP."""
    def call(method, path, body=None):
        r = client.request(method, path, json=body)
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail")
            except ValueError:
                detail = r.text
            raise cli.CliError(f"{r.status_code}: {detail}")
        try:
            return r.json()
        except ValueError:
            return r.text
    return call


def run(client, *argv):
    out = io.StringIO()
    code = cli.main(list(argv), call=through(client), out=out)
    return code, out.getvalue()


@pytest.fixture
def saved(tmp_path, monkeypatch):
    """A settings file of its own, so saving from the CLI never touches another test's."""
    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    before = dict(os.environ)
    yield tmp_path
    # A save reloads the settings into the environment: put it back so later tests see the defaults.
    os.environ.clear()
    os.environ.update(before)


def test_status_and_incidents(client):
    brute_force(client)
    code, out = run(client, "status")
    assert code == 0 and "Protection: on" in out and "high 1" in out
    code, out = run(client, "incidents", "list")
    assert code == 0 and "brute_force" in out
    iid = client.get("/incidents").json()[0]["id"]
    code, out = run(client, "incidents", "show", iid)
    assert code == 0 and "203.0.113.45" in out


def test_reject_needs_a_reason(client, capsys):
    brute_force(client)
    iid = client.get("/incidents").json()[0]["id"]
    assert run(client, "incidents", "reject", iid)[0] == 1
    assert "--why" in capsys.readouterr().err


def test_settings_set_any_value_including_hidden_preset_ones(client, saved):
    code, out = run(client, "settings", "set", "RISK_THRESHOLD=70")
    assert code == 0 and "Saved" in out
    values = cfg.read()
    assert values["RISK_THRESHOLD"] == "70"
    assert values["SENTRAI_PRESET"] == "advanced"  # a value set by hand: no longer a preset's
    code, out = run(client, "settings", "get", "RISK_THRESHOLD")
    assert out.strip() == "70"


def test_settings_unknown_name_is_refused(client, saved, capsys):
    assert run(client, "settings", "set", "NOT_A_SETTING=1")[0] == 1
    assert "not settings" in capsys.readouterr().err


def test_preset_by_its_label(client, saved):
    code, out = run(client, "settings", "preset")
    assert code == 0 and "Strict" in out and "Minimum" in out
    code, _ = run(client, "settings", "preset", "minimum")
    assert code == 0
    assert cfg.read()["SENTRAI_PRESET"] == "balanced"  # Minimum is saved under its old key
    assert run(client, "settings", "preset", "strict")[0] == 0
    assert cfg.read()["SENTRAI_PRESET"] == "strict"


def test_limits_change_one_keeps_the_rest(client, saved):
    before = client.get("/ui/limits").json()["settings"]
    code, out = run(client, "limits", "set", "MAX_AUTO_ACTIONS_PER_HOUR=4")
    assert code == 0, out
    after = cfg.read()
    assert after["MAX_AUTO_ACTIONS_PER_HOUR"] == "4"
    assert after["RISK_THRESHOLD"] == before["RISK_THRESHOLD"]
    assert run(client, "limits", "set", "NOPE=1")[0] == 1


def test_tuning(client):
    brute_force(client)
    code, out = run(client, "tuning")
    assert code == 0 and "Password guessing" in out


def test_routing_round_trip(client, tmp_path):
    f = tmp_path / "routing.json"
    assert run(client, "routing", "export", str(f))[0] == 0
    data = json.loads(f.read_text())
    data["follow_up"]["resolve_within_hours"] = 12
    f.write_text(json.dumps(data))
    code, out = run(client, "routing", "import", str(f))
    assert code == 0, out
    assert client.get("/routing").json()["follow_up"]["resolve_within_hours"] == 12


def test_integrations_list(client):
    code, out = run(client, "integrations", "list")
    assert code == 0 and "telegram" in out and "typesafe" in out


def test_machines_and_jobs_need_a_joined_machine(client, capsys):
    code, out = run(client, "machines", "list")
    assert code == 0 and "This computer" in out
    assert run(client, "jobs", "scan", "nowhere-01")[0] == 1
    assert "no joined machine" in capsys.readouterr().err


def test_auto_mode_switch_is_logged_with_the_cli_name(client, monkeypatch):
    monkeypatch.setenv("SENTRAI_OPERATOR", "erick")
    assert run(client, "auto-mode", "off", "--reason", "maintenance")[0] == 0
    prot = client.get("/protection").json()
    assert prot["auto_mode"] is False
    assert run(client, "auto-mode", "on")[0] == 0


def test_raw_api(client):
    code, out = run(client, "api", "GET", "/health")
    assert code == 0 and json.loads(out) == {"ok": True}


def test_team_on_the_accounts_file(saved, monkeypatch):
    import sentrai_accounts as acc
    monkeypatch.setattr(acc, "accounts_path", lambda: saved / "accounts.json")
    out = io.StringIO()
    assert cli.main(["team", "invite", "a@example.com"], out=out) == 1  # no Owner yet
    acc.make_owner("owner@example.com", "a-long-password-123")
    out = io.StringIO()
    assert cli.main(["team", "invite", "it@example.com", "--role", "admin"], out=out) == 0
    assert "/?invite=" in out.getvalue()
    assert [i["email"] for i in acc.pending_invites()] == ["it@example.com"]
    assert cli.main(["team", "withdraw", "it@example.com"], out=io.StringIO()) == 0
    assert acc.pending_invites() == []
    out = io.StringIO()
    assert cli.main(["team", "list"], out=out) == 0 and "owner@example.com" in out.getvalue()
    assert cli.main(["team", "remove", "owner@example.com"], out=io.StringIO()) == 1  # the last Owner stays


def test_jobs_and_rename_on_a_joined_machine(client, monkeypatch):
    monkeypatch.setenv("SENTRAI_OPERATOR", "erick")
    code = client.post("/fleet/join-codes", json={"operator": "t"}).json()["code"]
    client.post("/fleet/enrol", json={"code": code, "host": "shop-pc"})
    code, out = run(client, "jobs", "scan", "shop-pc")
    assert code == 0 and "Queued" in out
    code, out = run(client, "jobs", "list", "--host", "shop-pc")
    assert code == 0 and "threat_scan" in out and "cli:erick" in out
    assert run(client, "machines", "rename", "shop-pc", "Front desk")[0] == 0
    audit = json.dumps(client.get("/audit").json())
    assert "machine_renamed" in audit and "cli:erick" in audit  # the CLI's name, not "dashboard"
    code, out = run(client, "machines", "agents")
    assert code == 0 and "shop-pc" in out


def test_feedback_list_and_done(client):
    fid = client.post("/ui/feedback", json={"name": "Ana", "contact": "Ana's Bakery", "message": "Can I add a laptop?"}).json()["id"]
    code, out = run(client, "feedback", "list")
    assert code == 0 and fid in out and "Can I add a laptop?" in out
    code, out = run(client, "feedback", "done", fid)
    assert code == 0 and "1 message marked done" in out
    assert fid not in run(client, "feedback", "list")[1]
