"""The web dashboard's sign-in: password, authenticator code, session cookie, roles."""
import pytest
from fastapi.testclient import TestClient

import sentrai_accounts as acc
from app import auth
from app.config import Settings
from app.main import create_app

PASSWORD = "correct horse battery"
WEB = {"X-SentrAI-Web": "1"}


@pytest.fixture
def web(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRAI_ACCOUNTS", str(tmp_path / "accounts.json"))
    auth._fails.clear(), auth._sessions.clear(), auth._pending.clear()
    app = create_app(Settings(db_path=tmp_path / "sentrai.db", background=False, demo_speed=60.0))
    with TestClient(app) as c:  # no token header: a browser
        yield c


def sign_in(web, email, role="owner"):
    acc.make_owner(email, PASSWORD, "Test") if role == "owner" else None
    r = web.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 200 and r.json()["next"] == "add_authenticator"
    secret = web.post("/auth/authenticator/start").json()["secret"]
    r = web.post("/auth/authenticator/confirm", json={"code": acc.totp_code(secret)})
    assert r.status_code == 200 and len(r.json()["recovery_codes"]) == acc.RECOVERY_CODES
    return secret


def test_needs_sign_in(web):
    assert web.get("/incidents").status_code == 401
    assert web.get("/auth/me").status_code == 401
    assert web.get("/auth/state").json()["has_accounts"] is False


def test_owner_signs_in_and_acts(web):
    sign_in(web, "owner@example.com")
    me = web.get("/auth/me").json()
    assert me["role"] == "owner" and "act" in me["permissions"]
    assert web.get("/incidents").status_code == 200
    assert web.post("/protection", json={"on": True, "operator": "x"}).status_code == 403  # no web header
    assert web.post("/protection", json={"on": True, "operator": "x"}, headers=WEB).status_code != 401
    web.post("/auth/logout")
    assert web.get("/incidents").status_code == 401


def test_wrong_password_and_code(web):
    acc.make_owner("owner@example.com", PASSWORD, "Test")
    assert web.post("/auth/login", json={"email": "owner@example.com", "password": "nope nope nope"}).status_code == 401
    assert web.post("/auth/totp", json={"code": "123456"}).status_code == 401  # no pending sign-in


def test_rate_limit(web):
    acc.make_owner("owner@example.com", PASSWORD, "Test")
    codes = [web.post("/auth/login", json={"email": "owner@example.com", "password": "bad bad bad bad"}).status_code
             for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429


def test_auditor_reads_but_cannot_write(web):
    acc.make_owner("owner@example.com", PASSWORD, "Owner")
    code = acc.invite("owner@example.com", "aud@example.com", "auditor")
    assert web.post("/auth/invite/accept", json={"code": code, "name": "Aud", "password": PASSWORD}).status_code == 200
    secret = web.post("/auth/authenticator/start").json()["secret"]
    assert web.post("/auth/authenticator/confirm", json={"code": acc.totp_code(secret)}).status_code == 200
    assert web.get("/incidents").status_code == 200
    r = web.post("/protection", json={"on": False, "operator": "x"}, headers=WEB)
    assert r.status_code == 403


def test_the_signed_in_person_is_the_operator(web):
    sign_in(web, "owner@example.com")
    r = web.post("/chat", json={"operator": "someone-else", "message": "What is happening right now?"}, headers=WEB)
    assert r.status_code == 200
    asked = [m for m in web.get("/chat").json()["messages"] if m.get("role") == "operator"]
    assert asked and asked[-1]["operator"] == "owner@example.com"
