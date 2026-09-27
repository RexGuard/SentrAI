"""Target app: login flow and blocklist (containment) enforcement."""
from __future__ import annotations

import pytest

from target_app import create_app, paths
from target_app.blocklist import blocklist


@pytest.fixture()
def client():
    app = create_app(start_polling=False)
    app.config.update(TESTING=True)
    # Ensure a clean blocklist for each test.
    blocklist.update(ips=[], users=[])
    with app.test_client() as c:
        yield c
    blocklist.update(ips=[], users=[])


def _admin_password() -> str:
    return (paths.seed_dir() / "admin_password.txt").read_text(encoding="utf-8").strip()


def test_login_page_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Aegis Academy" in resp.data


def test_login_valid_credentials(client):
    resp = client.post("/login", data={"user": "admin", "password": _admin_password()})
    assert resp.status_code == 200
    assert b"Welcome" in resp.data


def test_login_invalid_credentials(client):
    resp = client.post("/login", data={"user": "admin", "password": "wrong"})
    assert resp.status_code == 401
    assert b"Invalid credentials" in resp.data


def test_blocklist_blocks_ip(client):
    blocklist.update(ips=["203.0.113.45"], users=[])
    resp = client.get("/", headers={"X-Demo-Src-IP": "203.0.113.45"})
    assert resp.status_code == 403
    assert b"Blocked by CactAI" in resp.data


def test_blocklist_blocks_user_on_login(client):
    blocklist.update(ips=[], users=["admin"])
    resp = client.post("/login", data={"user": "admin", "password": _admin_password()})
    assert resp.status_code == 403
    assert b"temporary containment" in resp.data


def test_blocklist_allows_other_ip(client):
    blocklist.update(ips=["203.0.113.45"], users=[])
    resp = client.get("/", headers={"X-Demo-Src-IP": "192.0.2.10"})
    assert resp.status_code == 200


def test_admin_run_never_executes(client):
    resp = client.get("/admin/run", query_string={"cmd": "whoami"})
    assert resp.status_code == 200
    assert b"SIMULATED" in resp.data
    assert b"not executed" in resp.data
