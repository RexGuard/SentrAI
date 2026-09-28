"""The core API needs the shared token everywhere except /health and /blocklist."""
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

from .conftest import ev


@pytest.fixture
def anon(tmp_path):
    app = create_app(Settings(db_path=tmp_path / "a.db", background=False, api_token="s3cret"))
    with TestClient(app) as c:
        yield c


def test_health_and_blocklist_are_open(anon):
    assert anon.get("/health").status_code == 200
    assert anon.get("/blocklist").status_code == 200


@pytest.mark.parametrize("method,path", [
    ("post", "/events"),
    ("post", "/incidents/INC-1/ack"),
    ("post", "/incidents/INC-1/decision"),
    ("post", "/incidents/INC-1/rollback"),
    ("post", "/incidents/INC-1/permanent"),
    ("post", "/ai/reload"),
    ("post", "/log-sources"),
    ("post", "/demo/reset"),
    ("get", "/incidents"),
    ("get", "/audit"),
    ("get", "/chat"),
])
def test_everything_else_needs_the_token(anon, method, path):
    r = anon.post(path, json={}) if method == "post" else anon.get(path)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_wrong_token_is_refused(anon):
    assert anon.get("/incidents", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert anon.get("/incidents", headers={"X-CactAI-Token": "nope"}).status_code == 401


def test_bearer_or_header_token_is_accepted(anon):
    assert anon.get("/incidents", headers={"Authorization": "Bearer s3cret"}).status_code == 200
    assert anon.get("/incidents", headers={"X-CactAI-Token": "s3cret"}).status_code == 200
    assert anon.post("/demo/reset", headers={"Authorization": "bearer s3cret"}).status_code == 200



def test_signed_report_link_opens_without_the_token(anon):
    auth = {"Authorization": "Bearer s3cret"}
    for n in range(5):
        anon.post("/events", json=ev(n, "POST /login 401 user=admin"), headers=auth)
    note = next(n for n in anon.get("/notifications/pending", headers=auth).json() if n["incident"])
    url = urlsplit(note["report_url"])
    assert anon.get(f"{url.path}?{url.query}").status_code == 200
    assert anon.get(url.path).status_code == 401
    assert anon.get(f"{url.path}?sig=0000").status_code == 401
    other = url.path.replace(note["incident"], "RSK-2026-999")
    assert anon.get(f"{other}?{url.query}").status_code == 401  # a signature fits one report only
    assert anon.get(f"/reports/{note['incident']}?{url.query}").status_code == 401  # the .md path only
