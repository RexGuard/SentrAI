"""Dashboard accounts (mvp/cactai_accounts.py): setup code, roles, invites, authenticator, recovery codes."""
from __future__ import annotations

import io
import json
import os

import pytest

from target_app import paths  # noqa: F401 - puts mvp/ on sys.path

import cactai_accounts as acc  # noqa: E402
import cactai_config as cfg  # noqa: E402

GOOD = "a-long-password-1"


@pytest.fixture(autouse=True)
def files(tmp_path, monkeypatch):
    monkeypatch.setenv("CACTAI_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.delenv("CACTAI_ACCOUNTS", raising=False)
    for name in (cfg.EMAIL_ENV, cfg.HASH_ENV, cfg.PASSWORD_ENV):  # left behind by load() in other tests
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def owner(email="erick@example.com"):
    return acc.register_owner(acc.new_setup_code(), "Erick", email, GOOD)


def with_authenticator(email):
    secret = acc.start_authenticator(email)
    codes = acc.confirm_authenticator(email, acc.totp_code(secret))
    return secret, codes


def test_totp_matches_the_rfc_6238_test_vector():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # b"12345678901234567890"
    assert acc.totp_code(secret, 59) == "287082"
    assert acc.totp_code(secret, 1111111109) == "081804"


def test_a_new_machine_has_no_one_until_the_setup_code_is_used(files):
    assert not acc.has_accounts() and not acc.setup_code_waiting()
    code = acc.new_setup_code()
    assert acc.setup_code_waiting()
    with pytest.raises(acc.AccountError):
        acc.register_owner("WRONG-CODE-HERE", "Erick", "erick@example.com", GOOD)
    with pytest.raises(acc.AccountError, match="12 characters"):
        acc.register_owner(code, "Erick", "erick@example.com", "short")
    me = acc.register_owner(code, "Erick", "Erick@Example.com ", GOOD)
    assert me["email"] == "erick@example.com" and me["role"] == "owner" and not me["authenticator"]
    with pytest.raises(acc.AccountError):  # used up
        acc.register_owner(code, "Someone", "x@example.com", GOOD)
    saved = (files / "accounts.json").read_text()
    assert GOOD not in saved and code not in saved and code.replace("-", "") not in saved


def test_setup_code_expires(files, monkeypatch):
    code = acc.new_setup_code()
    later = acc._now() + acc.SETUP_CODE_HOURS * 3600 + 1
    monkeypatch.setattr(acc, "_now", lambda: later)
    with pytest.raises(acc.AccountError, match="expired"):
        acc.register_owner(code, "Erick", "erick@example.com", GOOD)


def test_sign_in_needs_password_then_a_fresh_authenticator_code(monkeypatch):
    owner()
    assert acc.check_password("erick@example.com", "wrong-password-x") is None
    assert acc.check_password("nobody@example.com", GOOD) is None
    assert acc.check_password("ERICK@example.com", GOOD)["role"] == "owner"
    secret, codes = with_authenticator("erick@example.com")
    assert len(codes) == acc.RECOVERY_CODES and acc.get("erick@example.com")["authenticator"]
    assert acc.check_second_factor("erick@example.com", "000000") is None
    next_step = acc._now() + acc.TOTP_STEP_S
    monkeypatch.setattr(acc, "_now", lambda: next_step)
    code = acc.totp_code(secret)
    assert acc.check_second_factor("erick@example.com", code) == "totp"
    assert acc.check_second_factor("erick@example.com", code) is None  # a code works once


def test_recovery_codes_work_once_each():
    owner()
    _, codes = with_authenticator("erick@example.com")
    assert acc.check_second_factor("erick@example.com", codes[0].lower()) == "recovery"
    assert acc.check_second_factor("erick@example.com", codes[0]) is None
    assert acc.recovery_left("erick@example.com") == acc.RECOVERY_CODES - 1
    assert codes[1] not in json.dumps(json.loads(acc.accounts_path().read_text()))


def test_people_join_only_by_invite_with_the_role_given():
    owner()
    code = acc.invite("erick@example.com", "Hozen@example.com", "auditor")
    assert acc.invite_for(code) == {"email": "hozen@example.com", "role": "auditor", "reset": False}
    assert acc.invite_for("made-up") is None
    hozen = acc.accept_invite(code, "Hozen", GOOD)
    assert hozen["role"] == "auditor" and acc.invite_for(code) is None
    with pytest.raises(acc.AccountError):  # an invite works once
        acc.accept_invite(code, "Hozen", GOOD)
    assert not acc.can("auditor", "act") and not acc.can("auditor", "configure") and acc.can("auditor", "export")
    with pytest.raises(acc.AccountError, match="Owner or an Admin"):
        acc.invite("hozen@example.com", "someone@example.com", "admin")


def test_invites_expire(monkeypatch):
    owner()
    code = acc.invite("erick@example.com", "ishmail@example.com", "admin")
    later = acc._now() + acc.INVITE_HOURS * 3600 + 1
    monkeypatch.setattr(acc, "_now", lambda: later)
    assert acc.invite_for(code) is None
    with pytest.raises(acc.AccountError, match="expired"):
        acc.accept_invite(code, "Ishmail", GOOD)


def test_admins_cannot_touch_owners_and_the_last_owner_stays():
    owner()
    acc.accept_invite(acc.invite("erick@example.com", "ishmail@example.com", "admin"), "Ishmail", GOOD)
    with pytest.raises(acc.AccountError, match="Only an Owner"):
        acc.invite("ishmail@example.com", "x@example.com", "owner")
    with pytest.raises(acc.AccountError, match="Only an Owner"):
        acc.remove("ishmail@example.com", "erick@example.com")
    with pytest.raises(acc.AccountError, match="at least one Owner"):
        acc.set_role("erick@example.com", "erick@example.com", "admin")
    acc.set_role("erick@example.com", "ishmail@example.com", "owner")
    acc.set_role("ishmail@example.com", "erick@example.com", "auditor")  # two Owners now, so one may step down
    assert [p["role"] for p in acc.people()] == ["owner", "auditor"]


def test_a_reset_link_replaces_password_and_authenticator():
    owner()
    acc.accept_invite(acc.invite("erick@example.com", "ishmail@example.com", "admin"), "Ishmail", GOOD)
    with_authenticator("ishmail@example.com")
    code = acc.reset("erick@example.com", "ishmail@example.com")
    assert acc.check_password("ishmail@example.com", GOOD) is None  # the old password stops at once
    assert acc.invite_for(code)["reset"]
    again = acc.accept_invite(code, "", "another-password-2")
    assert again["name"] == "Ishmail" and again["role"] == "admin" and not again["authenticator"]
    assert acc.check_password("ishmail@example.com", "another-password-2")


def test_old_single_sign_in_becomes_the_owner(files):
    cfg.config_path().write_text(json.dumps({"access": {cfg.TOKEN_ENV: "t", cfg.EMAIL_ENV: "boss@example.com",
                                                        cfg.HASH_ENV: cfg.hash_password("old-password")}}))
    cfg.save(cfg.read())
    assert cfg.read()[cfg.HASH_ENV]  # kept by save() until it is moved
    assert acc.check_password("boss@example.com", "old-password")["role"] == "owner"
    assert not acc.get("boss@example.com")["authenticator"]  # added at the next sign-in
    cfg.save(cfg.read())
    assert cfg.HASH_ENV not in cfg.read()  # moved: the settings file no longer holds a password


def test_admin_command_prints_a_setup_code_then_lists_people(capsys):
    assert cfg.main(["admin"]) == 0
    out = capsys.readouterr().out
    code = out.split("Dashboard setup code: ")[1].split()[0]
    acc.register_owner(code, "Erick", "erick@example.com", GOOD)
    assert cfg.main(["admin"]) == 0
    assert "Owner: erick@example.com" in capsys.readouterr().out


def test_admin_command_makes_the_owner_from_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("from-stdin-password\n"))
    assert cfg.main(["admin", "--email", "ops@example.com", "--password-stdin"]) == 0
    out = capsys.readouterr().out
    assert "ops@example.com" in out and "from-stdin-password" not in out
    assert acc.check_password("ops@example.com", "from-stdin-password")["role"] == "owner"


def test_admin_reset_from_the_shell_sets_a_new_password_and_clears_the_authenticator(capsys):
    owner()
    with_authenticator("erick@example.com")
    assert cfg.main(["admin", "--reset"]) == 0
    password = capsys.readouterr().out.split("new password: ")[1].split(")")[0]
    assert acc.check_password("erick@example.com", password)
    assert not acc.get("erick@example.com")["authenticator"]


@pytest.mark.skipif(os.name == "nt", reason="Windows has no Unix file modes")
def test_accounts_file_is_readable_by_its_owner_only():
    owner()
    assert oct(acc.accounts_path().stat().st_mode & 0o777) == "0o600"
