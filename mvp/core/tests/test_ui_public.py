"""The open staff report page: no sign-in, a code when asked, the reporter-safe answer, the sender cap."""
from fastapi.testclient import TestClient

TEXT = "I got an email from 'IT support' asking me to confirm my password with a link. I clicked it."


def anon(client):
    return TestClient(client.app)  # no token, no cookie


def test_page_info_and_report_without_signing_in(client, monkeypatch):
    monkeypatch.delenv("SENTRAI_REPORT_CODE", raising=False)
    monkeypatch.delenv("SENTRAI_REPORT_PAGE", raising=False)
    a = anon(client)
    assert a.get("/staff-reports").status_code == 401  # the rest of the API stays closed
    info = a.get("/public/report").json()
    assert info["on"] is True and info["code_needed"] is False and isinstance(info["machines"], list)
    r = a.post("/public/report", json={"text": TEXT, "reporter": "Mei"})
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["id"] and got["advice"] and "triage" not in got and "notes" not in got
    assert client.get(f"/staff-reports/{got['id']}").json()["channel"] == "dashboard"


def test_code_page_off_short_text_and_cap(client, monkeypatch):
    a = anon(client)
    monkeypatch.setenv("SENTRAI_REPORT_CODE", "blue-door")
    assert a.get("/public/report").json()["code_needed"] is True
    assert a.post("/public/report", json={"text": TEXT, "code": "wrong"}).status_code == 400
    assert a.post("/public/report", json={"text": TEXT, "code": " blue-door "}).status_code == 200
    monkeypatch.delenv("SENTRAI_REPORT_CODE")
    assert a.post("/public/report", json={"text": "odd"}).status_code == 400
    for _ in range(5):
        last = a.post("/public/report", json={"text": TEXT}, headers={"x-forwarded-for": "198.51.100.7"})
    assert last.status_code == 429 or a.post("/public/report", json={"text": TEXT}, headers={"x-forwarded-for": "198.51.100.7"}).status_code == 429
    monkeypatch.setenv("SENTRAI_REPORT_PAGE", "off")
    assert a.get("/public/report").json() == {"on": False, "code_needed": False, "machines": []}
    assert a.post("/public/report", json={"text": TEXT}).status_code == 404
