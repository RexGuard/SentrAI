"""The one-page client summary (summary.py) and the plain-words parts of the evidence report."""

import json
from datetime import datetime

from fastapi.testclient import TestClient

from app.summary import Schedule

from .conftest import brute_force, ev

INTERNAL = ("Countersign", "Gatehouse", "Scribe", "Warden", "Garrison", "Watchtower", "Cyanide")


def _contained(client):
    brute_force(client)
    client.post("/events", json=ev(10, "GET /search?q=' OR 1=1 -- 200", source="flask_access"))  # over 80: contained


def _pages(pdf: bytes) -> int:
    return pdf.count(b"/Type /Page") - pdf.count(b"/Type /Pages")


def test_incident_carries_plain_next_steps(client):
    brute_force(client)
    inc = client.get("/incidents").json()[0]
    assert inc["next_steps"] and "password" in " ".join(inc["next_steps"])


def test_daily_summary_counts_what_happened(client):
    _contained(client)
    brute_force(client, ip="198.51.100.7", start=20)  # a second attacker, still open
    r = client.get("/summary/daily").json()
    n = r["numbers"]
    assert r["period"] == "daily" and n["threats"] == 3
    assert n["stopped_automatically"] == 2 and n["need_attention"] == 1
    assert r["attention"][0]["what"] == "Password guessing" and r["attention"][0]["next_step"]
    assert r["machines"][0]["machine"] == "web-01" and r["machines"][0]["threats"] == 3
    assert r["proof"]["chain_valid"] is True and r["proof"]["fingerprint"].startswith("SENTRAI-FP v1")
    assert r["headline"] == "3 threats today. 1 still needs your attention."
    md = client.get("/summary/daily.md").text
    assert "Needs your attention" in md and "Can I trust this?" in md
    assert not any(name in md for name in INTERNAL)
    pdf = client.get("/summary/weekly.pdf")
    assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf"
    assert _pages(pdf.content) == 1
    assert client.get("/summary/monthly").status_code == 404


def test_quiet_period_and_many_incidents_stay_on_one_page(client):
    assert client.get("/summary/daily").json()["headline"].startswith("All quiet")
    client.post("/protection", json={"operator": "erick", "on": False, "reason": "test: keep them all open"})
    for k in range(25):
        for i in range(5):
            client.post("/events", json=ev(k * 5 + i, "POST /login 401 user=admin", ip=f"198.51.100.{k + 1}",
                                           host=f"web-{k:02d}"))
    r = client.get("/summary/daily").json()
    assert r["numbers"]["threats"] >= 20
    assert _pages(client.get("/summary/daily.pdf").content) == 1
    assert "more on the dashboard" in client.get("/summary/daily.md").text


def test_summary_period_ends_at_until(client):
    brute_force(client)
    before = int(client.core.clock.now()) - 3600
    assert client.get(f"/summary/daily?until={before}").json()["numbers"]["threats"] == 0


def test_schedule_slots():
    now = datetime(2026, 10, 28, 10, 0).timestamp()  # a Wednesday
    assert datetime.fromtimestamp(Schedule("daily", "08:00").last_slot(now)) == datetime(2026, 10, 28, 8, 0)
    assert datetime.fromtimestamp(Schedule("daily", "11:30").last_slot(now)) == datetime(2026, 10, 27, 11, 30)
    assert datetime.fromtimestamp(Schedule("weekly", "09:00", "fri").last_slot(now)) == datetime(2026, 10, 23, 9, 0)
    assert datetime.fromtimestamp(Schedule("weekly", "09:00", "fri").next_slot(now)) == datetime(2026, 10, 30, 9, 0)
    assert Schedule("off").last_slot(now) is None


def test_schedule_preference_is_saved_and_audited(client, tmp_path):
    r = client.post("/summary/schedule", json={"operator": "erick", "every": "weekly", "day": "Friday", "at": "9:00",
                                                "to": "Acme Pte Ltd (owner)"}).json()
    assert (r["every"], r["day"], r["at"], r["to"]) == ("weekly", "fri", "09:00", "Acme Pte Ltd (owner)")
    assert r["changed_by"] == "erick" and r["next_at"]
    saved = json.loads((tmp_path / "summary.json").read_text())
    assert saved["every"] == "weekly" and saved["day"] == "fri"
    assert client.get("/summary/schedule").json()["every"] == "weekly"
    for bad in ({"every": "hourly"}, {"at": "25:00"}, {"day": "someday"}):
        assert client.post("/summary/schedule", json={"operator": "erick", **bad}).status_code == 400
    types = [x["type"] for x in client.get("/audit").json()["records"]]
    assert "summary_schedule_changed" in types


def test_summary_goes_out_once_at_each_due_time(client):
    core = client.core
    brute_force(client)
    now = core.clock.now()
    sched = core.summary_schedule
    sched.last_sent_ts = sched.last_slot(now) - 1  # pretend the last one went out a day ago
    sent = core._send_summary(now)
    assert sent and sent["notification"]["kind"] == "summary"
    n = sent["notification"]
    assert n["recipients"] == [sched.to] and "/summary/daily.pdf?until=" in n["report_url"]
    assert core._send_summary(now) is None  # not again until the next due time
    sched.every = "off"
    sched.last_sent_ts = 0
    assert core._send_summary(now) is None
    types = [x["type"] for x in client.get("/audit").json()["records"]]
    assert "summary_sent" in types


def test_signed_summary_link_opens_without_the_token(client):
    sent = client.post("/summary/send", json={"operator": "erick"}).json()
    url = sent["link"].split("127.0.0.1:8000", 1)[1]
    anon = TestClient(client.app)
    assert anon.get(url).status_code == 200
    assert anon.get(url.replace("until=", "until=1")).status_code == 401  # a different period is not covered
    assert anon.get(url.replace(".pdf", ".md")).status_code == 401
    assert anon.get(url.split("?")[0].replace(".pdf", "")).status_code == 401  # JSON needs the token


def test_evidence_report_has_plain_words_and_no_internal_names(client):
    _contained(client)
    rep = client.get("/reports/RSK-2026-081").json()
    assert "stepped in on its own" in rep["in_plain_words"] and rep["outcome"].startswith("Contained")
    assert rep["next_steps"] and len(rep["how_to_check"]) == 3
    md = client.get("/reports/RSK-2026-081.md").text
    assert "In plain words" in md and "What to do next" in md and "How to check this report" in md
    assert not any(name in md for name in INTERNAL)
    assert "safety check" in md
    assert client.get("/reports/RSK-2026-081.pdf").status_code == 200
