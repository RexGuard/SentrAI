"""The staff report page is for registered users only: a sign-in (or the token), the reporter-safe answer, the cap."""
from fastapi.testclient import TestClient

TEXT = "I got an email from 'IT support' asking me to confirm my password with a link. I clicked it."


def anon(client):
    return TestClient(client.app)  # no token, no cookie


def test_nothing_is_open_without_a_sign_in(client):
    a = anon(client)
    assert a.get("/ui/report").status_code == 401
    assert a.post("/ui/report", json={"text": TEXT}).status_code == 401
    assert a.get("/public/report").status_code in (401, 404)  # the open endpoint of the first version is gone


def test_a_signed_in_person_reports_and_gets_only_the_reporter_view(client, monkeypatch):
    monkeypatch.delenv("SENTRAI_REPORT_PAGE", raising=False)
    info = client.get("/ui/report").json()
    assert info["on"] is True and isinstance(info["machines"], list)
    r = client.post("/ui/report", json={"text": TEXT, "reporter": "Mei"})
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["id"] and got["advice"] and "triage" not in got and "notes" not in got
    stored = client.get(f"/staff-reports/{got['id']}").json()
    assert stored["channel"] == "dashboard" and stored["reporter"] == "Mei"


def test_short_text_cap_and_off_switch(client, monkeypatch):
    assert client.post("/ui/report", json={"text": "odd"}).status_code == 400
    for _ in range(5):
        last = client.post("/ui/report", json={"text": TEXT})
    assert last.status_code == 429 or client.post("/ui/report", json={"text": TEXT}).status_code == 429
    monkeypatch.setenv("SENTRAI_REPORT_PAGE", "off")
    assert client.get("/ui/report").json() == {"on": False, "reporter": "", "machines": []}
    assert client.post("/ui/report", json={"text": TEXT}).status_code == 404
