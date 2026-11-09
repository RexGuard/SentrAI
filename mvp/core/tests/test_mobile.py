"""The phone app: invites and sign-in, a person sees only their own coaching, the phone check, owners' alerts."""
import time

import pytest
from fastapi.testclient import TestClient

import sentrai_accounts as acc
from app import auth
from app import mobile as mb
from app.config import Settings
from app.main import create_app

from .test_web_auth import PASSWORD, sign_in

TOKEN = {"Authorization": "Bearer test-token"}


@pytest.fixture
def web(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRAI_ACCOUNTS", str(tmp_path / "accounts.json"))
    auth._fails.clear(), auth._sessions.clear(), auth._pending.clear()
    app = create_app(Settings(db_path=tmp_path / "sentrai.db", background=False, demo_speed=60.0))
    with TestClient(app) as c:  # no token header: a phone, or a browser
        c.core = app.state.core  # type: ignore[attr-defined]
        yield c


def coach_on(c, apps=("phone",)):
    r = c.post("/ui/coach/settings", headers=TOKEN, json={
        "regions": ["sg"], "region_checks": {"sg": [0, 1, 2]}, "notice_shared": True, "apps_on": list(apps)})
    assert r.status_code == 200 and r.json()["ready"]
    for email, name in (("maya@acme.test", "Maya Tan"), ("ravi@acme.test", "Ravi Kumar")):
        assert c.post("/ui/coach/people", headers=TOKEN, json={"email": email, "name": name}).status_code == 200


def staff_key(c, email="maya@acme.test", password="a long password"):
    code = c.post("/ui/mobile/invites", headers=TOKEN, json={"email": email}).json()["code"]
    r = c.post("/mobile/invite/accept", json={"code": code.lower(), "password": password, "device": "Pixel\n8"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['key']}"}, r.json()


def test_check_is_minimal_and_problems_are_mapped():
    from datetime import date
    out = mb.clean_check({"screen_lock": False, "outside_apps": 3, "apps": ["com.secret.bank"], "patch": "2026-01-05",
                          "usb_debugging": "yes", "rooted": False, "android": True}, today=date(2026, 11, 9))
    assert out == {"screen_lock": False, "outside_apps": 3, "rooted": False, "patch": "2026-01-05", "patch_days": 308}
    assert mb.problems(out) == ["phone_no_lock", "phone_out_of_date", "phone_outside_apps"]
    assert mb.problems(mb.clean_check({"screen_lock": True, "patch": "2026-10-01"}, today=date(2026, 11, 9))) == []


def test_staff_invite_sign_in_and_own_data_only(web):
    coach_on(web)
    assert web.post("/ui/mobile/invites", headers=TOKEN, json={"email": "who@acme.test"}).status_code == 404
    assert web.get("/mobile/hello").json()["app"] == "sentrai"
    h, out = staff_key(web)
    assert out["me"]["role"] == "Staff" and out["me"]["device"] == "Pixel 8" and not out["me"]["sees_alerts"]
    # the invite works once
    assert web.post("/mobile/login", json={"email": "maya@acme.test", "password": "wrong one!!"}).status_code == 401
    r = web.post("/mobile/login", json={"email": "MAYA@acme.test", "password": "a long password", "device": "Tab"})
    assert r.status_code == 200 and r.json()["key"].startswith("sm_")
    # the phone key reaches /mobile/* only, and the API token does not reach /mobile/*
    assert web.get("/incidents", headers=h).status_code == 403
    assert web.get("/ui/coach", headers=h).status_code == 403
    assert web.get("/mobile/me", headers=TOKEN).status_code == 401
    assert web.get("/mobile/me").status_code == 401
    assert web.get("/mobile/alerts", headers=h).status_code == 403
    # a sample moment for Ravi is not Maya's to answer
    web.post("/ui/coach/settings", headers=TOKEN, json={"apps_on": ["phone", "google"]})
    got = web.post("/ui/coach/events", headers=TOKEN, json={"events": [
        {"person": "ravi@acme.test", "app": "google", "kind": "file_shared_public"},
        {"person": "maya@acme.test", "app": "google", "kind": "two_step_off"}]}).json()
    assert got["moments"] == 2
    me = web.get("/mobile/me", headers=h).json()["coach"]
    assert me["notice_confirmed"] is False and me["notes"] == [] and me["open"] == 1  # held until the notice
    assert "Security Coach notice" in web.get("/mobile/notice", headers=h).json()["text"]
    me = web.post("/mobile/notice", headers=h).json()["coach"]
    assert me["notice_confirmed"] and len(me["notes"]) == 1 and "2-step" in me["notes"][0]["text"]
    ravi = next(m["id"] for m in web.get("/ui/coach", headers=TOKEN).json()["moments"] if m["kind"] == "file_shared_public")
    assert web.post(f"/mobile/moments/{ravi}", headers=h, json={"answer": "fixed"}).status_code == 404
    mine = me["notes"][0]["moment"]
    assert web.post(f"/mobile/moments/{mine}", headers=h, json={"answer": "fixed"}).json()["moment"]["status"] == "fixed"
    assert web.post("/mobile/lessons/two-step/answer", headers=h, json={"answers": [9, 9]}).json()["passed"] is False
    data = web.get("/mobile/my-data", headers=h).json()
    assert data["coach"]["person"]["email"] == "maya@acme.test" and len(data["phones"]) == 2
    assert all(n["person"] == "maya@acme.test" for n in data["coach"]["notes"])
    # signing out ends the key
    assert web.post("/mobile/logout", headers=h).json()["signed_out"]
    assert web.get("/mobile/me", headers=h).status_code == 401


def test_phone_check_coaches_new_problems_once(web):
    coach_on(web)
    h, _ = staff_key(web)
    web.post("/mobile/notice", headers=h)
    bad = {"screen_lock": False, "usb_debugging": True, "outside_apps": 0, "patch": "2020-01-01",
           "app_names": ["should not be kept"]}
    out = web.post("/mobile/check", headers=h, json=bad).json()
    assert set(out["new"]) == {"phone_no_lock", "phone_dev_mode", "phone_out_of_date"} and out["coached"] == 3
    assert "app_names" not in out["result"]
    assert web.post("/mobile/check", headers=h, json=bad).json()["new"] == []  # not raised again every day
    notes = web.get("/mobile/me", headers=h).json()["coach"]["notes"]
    assert any("Your phone check found that your phone has no screen lock" in n["text"] for n in notes)
    team = web.get("/ui/mobile", headers=TOKEN).json()
    assert team["team"]["phones_checked"] == 1 and team["phones"][0]["to_fix"] is None  # names are off
    # the coach not switched on for the phone app: the result is kept, no note is made
    web.post("/ui/coach/settings", headers=TOKEN, json={"apps_on": []})
    web.post("/mobile/check", headers=h, json={"screen_lock": True})
    assert web.post("/mobile/check", headers=h, json={"screen_lock": False}).json()["coached"] == 0


def test_staff_report_from_the_app(web):
    coach_on(web)
    h, _ = staff_key(web)
    r = web.post("/mobile/report", headers=h, json={"text": "A man asked for my door code on the phone today."})
    assert r.status_code == 200, r.text
    reports = web.get("/staff-reports", headers=TOKEN).json()["reports"]
    assert reports[0]["channel"] == "app" and reports[0]["reporter"] == "maya@acme.test"


def test_owner_signs_in_with_code_and_sees_alerts(web):
    secret = sign_in(web, "owner@acme.test")
    web.cookies.clear()
    body = {"email": "owner@acme.test", "password": PASSWORD, "device": "Owner phone"}
    assert web.post("/mobile/login", json=body).json() == {"need_code": True}
    assert web.post("/mobile/login", json={**body, "code": "000000"}).status_code == 401
    r = web.post("/mobile/login", json={**body, "code": acc.totp_code(secret, time.time() + 30)})
    assert r.status_code == 200, r.text
    h = {"Authorization": f"Bearer {r.json()['key']}"}
    assert r.json()["me"]["role"] == "Owner" and r.json()["me"]["sees_alerts"]
    al = web.get("/mobile/alerts", headers=h).json()
    assert {"risk_index", "alerts", "open", "phones", "coach"} <= set(al)
    # the owner can sign the phone out from the panel
    sid = web.get("/ui/mobile", headers=TOKEN).json()["phones"][0]["id"]
    assert web.post(f"/ui/mobile/{sid}/sign-out", headers=TOKEN).status_code == 200
    assert web.get("/mobile/me", headers=h).status_code == 401
    types = {rec["type"] for rec in web.get("/audit", headers=TOKEN).json()["records"]}
    assert {"phone_signed_in", "phone_signed_out"} <= types


def test_wrong_tries_are_limited_and_erase_removes_the_app(web):
    coach_on(web)
    h, _ = staff_key(web)
    for _ in range(mb.FAIL_LIMIT):
        web.post("/mobile/login", json={"email": "maya@acme.test", "password": "nope nope nope"})
    assert web.post("/mobile/login", json={"email": "maya@acme.test", "password": "a long password"}).status_code == 429
    erased = web.post("/ui/coach/people/maya@acme.test/erase", headers=TOKEN).json()["erased"]
    assert erased["app_password"] == 1 and erased["app_sign_ins"] == 1
    assert web.get("/mobile/me", headers=h).status_code == 401


def test_cli(client):
    import io
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    import sentrai_cli as cli
    from .test_cli import through

    def run(*argv):
        out = io.StringIO()
        code = cli.main(list(argv), call=through(client), out=out)
        return code, out.getvalue()

    run("coach", "setup", "--regions", "sg", "--checks-done", "--notice-shared")
    run("coach", "person", "ann@acme.test", "--name", "Ann", "--reach", "app")
    code, text = run("coach", "app-invite", "ann@acme.test")
    assert code == 0 and "App invite for ann@acme.test:" in text and "Install the SentrAI app" in text
    assert "0 phone sign-in(s)" in run("coach", "phones")[1]


def test_new_phone_kinds_switch_on_for_saved_settings(tmp_path):
    import json
    from app import coach as cm
    old = sorted(k for k in cm.KINDS if not k.startswith("phone_") and k != "meeting_open")  # admin turned one off
    (tmp_path / "coach.json").write_text(json.dumps({"settings": {"kinds_on": old}}))
    c = cm.Coach(tmp_path / "coach.json")
    on = set(c.settings()["kinds_on"])
    assert "phone_no_lock" in on and "meeting_open" not in on
    c.save_settings({"kinds_on": [k for k in on if k != "phone_rooted"]}, "x")
    assert "phone_rooted" not in cm.Coach(tmp_path / "coach.json").settings()["kinds_on"]
