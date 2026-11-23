""""Not checked" is never green: "all quiet" only when the computers really report in (app/coverage.py)."""
from io import StringIO

from app import coverage, ui_readiness


def page(*online):
    return {"machines": [{"name": f"pc-{n}", "host": f"pc-{n}", "online": up} for n, up in enumerate(online)]}


def test_states_and_words():
    assert coverage.of(page(True, True))["state"] == "watching" and coverage.of(page(True))["words"] == ""
    part = coverage.of(page(True, False))
    assert part["state"] == "partly" and part["quiet"] == ["pc-1"] and "pc-1" in part["words"]
    assert coverage.of(page(False, False))["state"] == "not_watching"
    none = coverage.of({"machines": []})
    assert none["state"] == "not_watching" and none["words"] == coverage.NOT_WATCHING_WORDS
    assert coverage.of(None)["total"] == 0


def test_quiet_headline_never_says_quiet_when_not_watching():
    assert coverage.quiet_headline("All quiet.", "Nothing new.", None) == "All quiet."
    assert coverage.quiet_headline("All quiet.", "Nothing new.", coverage.of(page(True))) == "All quiet."
    text = coverage.quiet_headline("All quiet.", "Nothing new.", coverage.of({"machines": []}))
    assert "quiet" not in text.lower() and text.startswith("Nothing new.") and "reporting in" in text
    assert coverage.safe(lambda: 1 / 0) is None and coverage.safe(None) is None


def not_watching(client):
    client.core.watching = lambda: coverage.of({"machines": []})


def test_command_center_briefing_and_approvals_say_so(client):
    assert "All quiet" in client.get("/ui/risks").json()["headline"]  # the test panel is this computer, reporting
    assert client.get("/ui/risks").json()["watching"]["state"] == "watching"
    not_watching(client)
    risks = client.get("/ui/risks").json()
    assert "All quiet" not in risks["headline"] and "reporting in" in risks["headline"]
    assert risks["watching"]["state"] == "not_watching"
    brief = client.get("/chat/briefing").json()
    assert "quiet" not in brief["headline"].lower() and brief["watching"]["state"] == "not_watching"
    assert client.get("/ui/approvals").json()["watching"]["state"] == "not_watching"


def test_client_summary_is_not_green_when_nothing_reports(client):
    not_watching(client)
    r = client.get("/summary/daily").json()
    assert "All quiet" not in r["headline"] and "reporting in" in r["headline"]
    assert client.get("/summary/daily.pdf").status_code == 200


def test_readiness_not_checked_is_never_ready():
    lines = ui_readiness.checks("on", {"machines": []}, ["email"], "unreadable", 0.0)
    by = {c["key"]: c for c in lines}
    assert by["blocking"]["state"] == "not_checked" and by["blocking"]["ok"] is False
    assert "Not checked" in by["blocking"]["detail"]
    assert by["backup"]["state"] == "not_checked" and by["backup"]["ok"] is False
    assert by["reporting"]["state"] == "missing"
    out = ui_readiness.summary(lines)
    assert not out["ready"] and out["not_checked"] == 2 and "could not check" in out["headline"]
    only = ui_readiness.summary([{**by["blocking"]}])
    assert "could not check yet" in only["headline"] and not only["ready"]


def test_cli_status_marks_not_checked(client):
    import sentrai_cli as cli
    from .test_cli import through

    client.core.watching = lambda: coverage.of({"machines": []})
    out = StringIO()
    cli.main(["status"], call=through(client), out=out)
    assert "Readiness:" in out.getvalue()
