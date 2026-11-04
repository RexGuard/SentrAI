"""The web dashboard's Team endpoints."""
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
    with TestClient(app) as c:
        yield c


def sign_in(web, email):
    assert web.post("/auth/login", json={"email": email, "password": PASSWORD}).status_code == 200
    secret = web.post("/auth/authenticator/start").json()["secret"]
    assert web.post("/auth/authenticator/confirm", json={"code": acc.totp_code(secret)}).status_code == 200


def test_the_token_alone_cannot_manage_people(web):
    assert web.get("/ui/team", headers={"Authorization": "Bearer test-token"}).status_code == 403


def test_owner_invites_changes_and_removes(web):
    acc.make_owner("owner@example.com", PASSWORD, "Owner")
    sign_in(web, "owner@example.com")
    team = web.get("/ui/team").json()
    assert team["my_role"] == "owner" and [p["email"] for p in team["people"]] == ["owner@example.com"]
    made = web.post("/ui/team/invite", json={"email": "aud@example.com", "role": "auditor"}, headers=WEB).json()
    assert made["path"].startswith("/?invite=")
    assert web.get("/ui/team").json()["invites"][0]["email"] == "aud@example.com"
    assert web.post("/ui/team/withdraw", json={"email": "aud@example.com"}, headers=WEB).status_code == 200
    assert web.get("/ui/team").json()["invites"] == []
    code = acc.invite("owner@example.com", "adm@example.com", "admin")
    acc.accept_invite(code, "Adm", PASSWORD)
    assert web.post("/ui/team/role", json={"email": "adm@example.com", "role": "auditor"}, headers=WEB).status_code == 200
    assert web.post("/ui/team/remove", json={"email": "adm@example.com"}, headers=WEB).status_code == 200
    r = web.post("/ui/team/remove", json={"email": "owner@example.com"}, headers=WEB)
    assert r.status_code == 400 and "at least one Owner" in r.json()["detail"]


def test_an_auditor_cannot_see_the_team(web):
    acc.make_owner("owner@example.com", PASSWORD, "Owner")
    code = acc.invite("owner@example.com", "aud@example.com", "auditor")
    assert web.post("/auth/invite/accept", json={"code": code, "name": "Aud", "password": PASSWORD}).status_code == 200
    secret = web.post("/auth/authenticator/start").json()["secret"]
    web.post("/auth/authenticator/confirm", json={"code": acc.totp_code(secret)})
    assert web.get("/ui/team").status_code == 403
