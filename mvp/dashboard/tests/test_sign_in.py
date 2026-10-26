"""The console's first screens: register with the setup code, invites, authenticator, roles."""
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[2]))
import cactai_accounts as acc  # noqa: E402
import cactai_config as cfg  # noqa: E402
from cactai_ui.api import CoreClient, CoreError  # noqa: E402

APP = str(Path(__file__).resolve().parents[1] / "app.py")
GOOD = "a-long-password-1"


@pytest.fixture
def app(fake_core, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("CACTAI_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.delenv("CACTAI_ACCOUNTS", raising=False)
    monkeypatch.delenv("CACTAI_DASHBOARD_LOGIN")
    for name in (cfg.EMAIL_ENV, cfg.HASH_ENV, cfg.PASSWORD_ENV):
        monkeypatch.delenv(name, raising=False)
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    return at


def signed_in(at) -> bool:
    return any(b.label == "Sign out" for b in at.sidebar.button)


def button(at, label):
    return next(b for b in at.button if b.label == label)


def add_authenticator(at, email):
    """The enrolment screen: read the key it shows, type the code an app would make from it."""
    secret = at.session_state["totp_secret"]
    assert secret.replace(" ", "")[:4] in at.code[0].value.replace(" ", "")
    at.text_input[0].input(acc.totp_code(secret))
    button(at, "Confirm").click().run()
    assert "Save your recovery codes" in " ".join(m.value for m in at.markdown)
    button(at, "I saved them").click().run()


def owner_with_authenticator(email="erick@example.com"):
    acc.register_owner(acc.new_setup_code(), "Erick", email, GOOD)
    secret = acc.start_authenticator(email)
    acc.confirm_authenticator(email, acc.totp_code(secret))
    data = acc._read()
    data["accounts"][0]["totp_step"] = 0  # the test's sign-in may reuse this time step's code
    acc._write(data)
    return secret


def password_step(at, email, password):
    at.text_input[0].input(email)
    at.text_input[1].input(password)
    button(at, "Sign in").click().run()


def test_new_machine_without_a_setup_code_says_how_to_get_one(app):
    app.run()
    assert not app.sidebar.button
    assert any("cactai_config.py admin" in w.value for w in app.warning)


def test_setup_code_creates_the_owner_who_adds_an_authenticator(app):
    code = acc.new_setup_code()
    app.run()
    assert "Create your Owner account" in " ".join(m.value for m in app.markdown)
    for n, value in enumerate(["WRONG-CODE-XXXX", "Erick", "erick@example.com", GOOD, GOOD]):
        app.text_input[n].input(value)
    button(app, "Create account").click().run()
    assert any("wrong or has expired" in e.value for e in app.error)
    app.text_input[0].input(code)
    button(app, "Create account").click().run()
    assert not app.exception, app.exception
    add_authenticator(app, "erick@example.com")
    assert signed_in(app)
    assert any("Team" in b.label for b in app.sidebar.button)
    assert acc.get("erick@example.com")["authenticator"]


def test_sign_in_asks_for_password_then_the_app_code(app):
    secret = owner_with_authenticator()
    app.run()
    password_step(app, "erick@example.com", "wrong-password-1")
    assert "Wrong email or password." in [e.value for e in app.error]
    password_step(app, "ERICK@example.com ", GOOD)
    assert not signed_in(app)
    app.text_input[0].input("123456")
    button(app, "Verify").click().run()
    assert any("doesn't match" in e.value for e in app.error)
    app.text_input[0].input(acc.totp_code(secret))
    button(app, "Verify").click().run()
    assert not app.exception, app.exception
    assert signed_in(app)
    assert acc.get("erick@example.com")["last_sign_in"]


def test_sign_in_locks_after_repeated_wrong_tries(app):
    owner_with_authenticator()
    app.run()
    for _ in range(5):
        password_step(app, "erick@example.com", "nope-nope-nope")
    password_step(app, "erick@example.com", GOOD)
    assert any("Too many wrong tries" in e.value for e in app.error)
    assert "pending" not in app.session_state


def test_invite_link_lets_an_auditor_join_who_can_change_nothing(app, fake_core):
    owner_with_authenticator()
    code = acc.invite("erick@example.com", "hozen@example.com", "auditor")
    app.query_params["invite"] = code
    app.run()
    assert "Join SentrAI" in " ".join(m.value for m in app.markdown)
    for n, value in enumerate(["Hozen", GOOD, GOOD]):
        app.text_input[n].input(value)
    button(app, "Continue").click().run()
    add_authenticator(app, "hozen@example.com")
    assert signed_in(app)
    assert not any("Team" in b.label for b in app.sidebar.button)  # Owners and Admins only
    app.session_state["page"] = "config"
    app.run()
    assert button(app, "Save settings").disabled


def test_team_page_makes_an_invite_link(app):
    secret = owner_with_authenticator()
    app.run()
    password_step(app, "erick@example.com", GOOD)
    app.text_input[0].input(acc.totp_code(secret))
    button(app, "Verify").click().run()
    app.session_state["page"] = "team"
    app.run()
    assert not app.exception, app.exception
    email = next(t for t in app.text_input if t.label == "Their email")
    email.input("ishmail@example.com")
    button(app, "Make invite link").click().run()
    link = next(c.value for c in app.code if "?invite=" in c.value)
    assert acc.invite_for(link.split("?invite=")[1])["role"] == "admin"


def test_old_plain_password_from_the_environment_becomes_the_owner(app, monkeypatch):
    monkeypatch.setenv(cfg.PASSWORD_ENV, "cactus-cactus")
    app.run()
    password_step(app, cfg.LEGACY_EMAIL, "cactus-cactus")
    assert "Add an authenticator app" in " ".join(m.value for m in app.markdown)


def test_an_auditor_client_refuses_changes_before_they_reach_the_core(fake_core):
    ro = CoreClient(fake_core, read_only=True)
    assert isinstance(ro.incidents(), list)  # reading works
    with pytest.raises(CoreError, match="Auditors"):
        ro.set_protection(False, "hozen@example.com")
