"""Security Coach: privacy rules enforced in code, moments and lessons, retention, and the endpoints."""
import pytest

from app import coach as cm

from .conftest import brute_force

NOW = 1_800_000_000.0


def ready(c: cm.Coach, **extra):
    c.save_settings({"regions": ["sg"], "region_checks": {"sg": [0, 1, 2]}, "notice_shared": True,
                     "apps_on": ["google"], **extra}, "owner@example.com")


def make(tmp_path, months=None):
    m = months or {"coach_activity": 1, "coach_notes": 12}
    return cm.Coach(tmp_path / "coach.json", months=lambda k: m.get(k), clock=lambda: NOW)


def test_catalogue_is_consistent():
    assert {"google", "microsoft", "okta", "slack", "zoom", "dropbox", "box", "github", "salesforce"} <= cm.APP_KEYS
    for k, rule in cm.KINDS.items():
        assert rule["lesson"] in cm.LESSONS and rule["level"] in cm.LEVELS, k
    for k, lesson in cm.LESSONS.items():
        assert lesson.get("next") in (None, *cm.LESSONS), k
        assert len(lesson["questions"]) == 2 and all(0 <= q["answer"] < len(q["options"]) for q in lesson["questions"])
    for words in [l["card"] for l in cm.LESSONS.values()] + [r["title"] for r in cm.KINDS.values()]:
        for internal in ("Warden", "Cyanide", "Garrison", "Scribe", "Jev"):
            assert internal not in words


def test_nothing_recorded_before_notice_and_checklist(tmp_path):
    c = make(tmp_path)
    c.upsert_person({"email": "a@acme.test", "name": "Ann"})
    ev = [{"person": "a@acme.test", "app": "google", "kind": "file_shared_public"}]
    with pytest.raises(cm.CoachError, match="not switched on"):
        c.ingest(ev)
    c.save_settings({"regions": ["sg"], "region_checks": {"sg": [0]}, "notice_shared": True}, "x")
    with pytest.raises(cm.CoachError, match="checklist for Singapore"):
        c.ingest(ev)
    ready(c)
    assert c.ingest(ev)["moments"] == 1


def test_scope_and_minimisation(tmp_path):
    c = make(tmp_path)
    ready(c, groups_off=["Board"])
    c.upsert_person({"email": "a@acme.test", "name": "Ann Lee"})
    c.upsert_person({"email": "b@acme.test", "group": "Board"})
    out = c.ingest([
        {"person": "a@acme.test", "app": "google", "kind": "file_shared_public", "file_type": "spreadsheet",
         "label": "Salaries 2026.xlsx", "body": "secret text", "subject": "pay", "ip": "203.0.113.9",
         "country": "sg", "recipients": ["x@y.z"]},
        {"person": "a@acme.test", "app": "slack", "kind": "guest_added"},          # app not on
        {"person": "b@acme.test", "app": "google", "kind": "file_shared_public"},  # group left out
        {"person": "nobody@acme.test", "app": "google", "kind": "file_shared_public"},
        {"person": "a@acme.test", "app": "google", "kind": "made_up"},
    ])
    assert out["recorded"] == 1 and out["dropped"] == 4
    data = c.my_data("a@acme.test")
    rec = data["activity"][0]
    assert set(rec) <= {"id", "person", "app", "kind", "ts", "at", "what", "country", "device", "label", "count", "sample"}
    assert rec["what"] == "a spreadsheet" and "label" not in rec and rec["country"] == "SG"
    assert "Salaries" not in str(data) and "secret" not in str(data) and "203.0.113" not in str(data)
    assert "a spreadsheet" in data["moments"][0]["title"]
    assert c.my_data  # b and nobody: nothing stored
    with pytest.raises(cm.CoachError):
        c.my_data("nobody@acme.test")
    assert c.my_data("b@acme.test")["activity"] == []


def test_consent_region_waits_for_the_person(tmp_path):
    c = make(tmp_path)
    c.save_settings({"regions": ["id"], "region_checks": {"id": [0, 1]}, "notice_shared": True, "apps_on": ["google"]}, "x")
    c.upsert_person({"email": "a@acme.test", "region": "id"})
    ev = [{"person": "a@acme.test", "app": "google", "kind": "two_step_off"}]
    assert c.ingest(ev)["why_dropped"] == {"waiting for the person's consent": 1}
    c.upsert_person({"email": "a@acme.test", "notice_confirmed": True})
    assert c.ingest(ev)["moments"] == 1


def test_notes_held_until_notice_then_deeper_lessons(tmp_path):
    c = make(tmp_path)
    ready(c)
    c.upsert_person({"email": "a@acme.test", "name": "Ann Lee"})
    ev = [{"person": "a@acme.test", "app": "google", "kind": "file_shared_public", "ts": NOW - 60}]
    c.ingest(ev)
    note = c.my_data("a@acme.test")["notes"][0]
    assert note["status"] == "held for notice" and note["text"].startswith("Hi Ann")
    c.upsert_person({"email": "a@acme.test", "notice_confirmed": True})
    c.ingest(ev)
    notes = c.my_data("a@acme.test")["notes"]
    assert notes[1]["status"] == "ready to send" and notes[1]["lesson"] == "public-links-2"
    assert "2nd time" in notes[1]["text"] and "Make it private again" in notes[1]["buttons"]


def test_answers_points_and_not_me(tmp_path):
    c = make(tmp_path)
    ready(c)
    c.upsert_person({"email": "a@acme.test", "notice_confirmed": True})
    c.ingest([{"person": "a@acme.test", "app": "google", "kind": "sign_in_new_place", "country": "VN"}])
    m = c.my_data("a@acme.test")["moments"][0]
    assert m["level"] == "tip"
    assert c.respond(m["id"], "not_me")["level"] == "urgent"
    wrong = c.answer_lesson("a@acme.test", "two-step", [0, 1])
    assert not wrong["passed"] and wrong["tip"]
    ok = c.answer_lesson("a@acme.test", "two-step", [1, 0])
    assert ok["passed"] and ok["level"]["points"] == 10
    assert c.answer_lesson("a@acme.test", "two-step", [1, 0])["level"]["points"] == 10  # once only
    with pytest.raises(cm.CoachError):
        c.respond(m["id"], "whatever")


def test_retention_deletes_old_records(tmp_path):
    c = make(tmp_path, {"coach_activity": 1, "coach_notes": 1})
    ready(c)
    c.upsert_person({"email": "a@acme.test"})
    c.ingest([{"person": "a@acme.test", "app": "google", "kind": "bulk_download", "ts": NOW - 40 * cm.DAY},
              {"person": "a@acme.test", "app": "google", "kind": "bulk_download", "ts": NOW - 1 * cm.DAY}])
    d = c.my_data("a@acme.test")
    assert len(d["activity"]) == 1 and len(d["moments"]) == 1 and len(d["notes"]) == 1
    c0 = make(tmp_path / "zero", {"coach_activity": 0, "coach_notes": 12})
    ready(c0)
    c0.upsert_person({"email": "a@acme.test"})
    c0.ingest([{"person": "a@acme.test", "app": "google", "kind": "bulk_download"}])
    assert c0.my_data("a@acme.test")["activity"] == [] and len(c0.my_data("a@acme.test")["moments"]) == 1


def test_names_hidden_unless_urgent_or_turned_on(tmp_path):
    c = make(tmp_path)
    ready(c, apps_on=["google", "microsoft"])
    c.upsert_person({"email": "a@acme.test", "name": "Ann Lee"})
    c.ingest([{"person": "a@acme.test", "app": "google", "kind": "file_shared_public"},
              {"person": "a@acme.test", "app": "microsoft", "kind": "mail_forward_outside"}])
    ov = c.overview()
    assert ov["people"] is None
    whos = {m["level"]: m["who"] for m in ov["moments"]}
    assert whos == {"urgent": "Ann Lee", "fix_soon": "A team member"} and ov["moments"][0]["level"] == "urgent"
    c.save_settings({"show_names": True}, "x")
    assert {m["who"] for m in c.overview()["moments"]} == {"Ann Lee"} and c.overview()["people"][0]["name"] == "Ann Lee"


def test_erase_and_notice(tmp_path):
    c = make(tmp_path)
    ready(c)
    c.upsert_person({"email": "a@acme.test"})
    c.ingest([{"person": "a@acme.test", "app": "google", "kind": "two_step_off"}])
    assert c.erase_person("a@acme.test") == {"person": 1, "activity": 1, "moments": 1, "notes": 1}
    text = cm.notice(c.overview(), "Acme", "dpo@acme.test")
    assert "Acme: Security Coach notice" in text and "never reads the text" in text and "dpo@acme.test" in text
    assert "File names are not kept" in text and "team totals only" in text and "PDPA 2012" in text
    for claim in ("redact", "mask", "anonymi"):
        assert claim not in text.lower()


def test_endpoints(client):
    brute_force(client)
    ov = client.get("/ui/coach").json()
    assert ov["ready"] is False and len(ov["apps"]) >= 10
    r = client.post("/ui/coach/sample", json={})
    assert r.status_code == 409 and "not switched on" in r.json()["detail"]
    assert client.post("/ui/coach/settings", json={"apps_on": ["nope"]}).status_code == 400
    ov = client.post("/ui/coach/settings", json={"regions": ["sg"], "region_checks": {"sg": [0, 1, 2]},
                                                  "notice_shared": True}).json()
    assert ov["ready"] is True
    out = client.post("/ui/coach/sample", json={}).json()
    assert out["added"]["moments"] == 8 and out["has_sample"] and out["team"]["urgent_open"] == 1
    assert out["team"]["notes_ready"] == 8
    m = out["moments"][0]
    assert m["level"] == "urgent" and m["who"] == "Lena Ong"
    assert client.post(f"/ui/coach/moments/{m['id']}", json={"answer": "fixed"}).json()["moment"]["status"] == "fixed"
    lessons = client.get("/ui/coach/lessons").json()["lessons"]
    assert lessons and "answer" not in lessons[0]["questions"][0]
    assert client.post("/ui/coach/lessons/phishing/answer",
                       json={"person": "maya.tan@example.com", "answers": [1, 0]}).json()["passed"]
    mine = client.get("/ui/coach/people/maya.tan@example.com/data").json()
    assert mine["person"]["level"]["points"] == 10 and len(mine["moments"]) == 3
    # a connector sends activity; out-of-scope apps are dropped (only sample data may bypass the app switch)
    got = client.post("/ui/coach/events", json={"events": [{"person": "maya.tan@example.com", "app": "google",
                                                              "kind": "two_step_off"}]}).json()
    assert got["dropped"] == 1 and got["why_dropped"] == {"app not switched on": 1}
    client.post("/ui/privacy", json={"organisation": "Acme", "contact": "dpo@acme.test"})
    md = client.get("/ui/coach/notice.md").text
    assert "Acme: Security Coach notice" in md and "dpo@acme.test" in md
    assert "Work app activity" in client.get("/ui/privacy/notice.md").text
    assert client.post("/ui/privacy", json={"months": {"coach_activity": 6}}).status_code == 400
    assert client.post("/ui/privacy", json={"months": {"coach_notes": None}}).status_code == 400
    erased = client.post("/ui/coach/people/maya.tan@example.com/erase").json()["erased"]
    assert erased["person"] == 1 and erased["moments"] == 3
    assert client.post("/ui/coach/sample", json={"clear": True}).json()["cleared"]["people"] == 2
    types = [rec["type"] for rec in client.get("/audit").json()["records"]]
    assert {"coach_settings_changed", "coach_sample", "coach_urgent", "coach_person_erased"} <= set(types)


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

    code, text = run("coach", "status")
    assert code == 0 and "Off: Pick the regions" in text
    assert "Still off" in run("coach", "setup", "--regions", "sg,my")[1]
    assert "Coach is on." in run("coach", "setup", "--checks-done", "--notice-shared")[1]
    assert "google, microsoft" in run("coach", "apps", "on", "google", "microsoft")[1]
    assert "Saved ann@acme.test" in run("coach", "person", "ann@acme.test", "--name", "Ann", "--region", "sg")[1]
    assert "8 risky moments" in run("coach", "sample")[1]
    assert "On: recording" in run("coach", "status")[1]
    assert "Security Coach notice" in run("coach", "notice")[1]
    assert "1 person" in run("coach", "erase", "ann@acme.test")[1]
    assert run("coach", "erase")[0] != 0
