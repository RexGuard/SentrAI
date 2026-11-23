"""Security Coach connectors (app/coach_connectors.py): Google Workspace's and Microsoft 365's activity logs become
the coach's records, read only while the coach may record, and never twice."""
from io import StringIO

import pytest

from app import coach as cm
from app import coach_connectors as cc

NOW = 1_800_000_000.0
T = cc._rfc3339(NOW - 600)

GOOGLE_ENV = {"COACH_GOOGLE_CLIENT_ID": "id", "COACH_GOOGLE_CLIENT_SECRET": "secret",
              "COACH_GOOGLE_REFRESH_TOKEN": "refresh", "COACH_GOOGLE_DOMAIN": "acme.test"}
MS_ENV = {"COACH_MS_TENANT_ID": "tenant", "COACH_MS_CLIENT_ID": "id", "COACH_MS_CLIENT_SECRET": "secret"}


def g(app_name, email, *events, at=T):
    return {"actor": {"email": email}, "id": {"time": at, "applicationName": app_name},
            "events": [{"name": n, "parameters": [{"name": k, "value": v} for k, v in p.items()]} for n, p in events]}


GOOGLE_LOGS = {
    "login": [g("login", "ann@acme.test", ("suspicious_login", {}))]
             + [g("login", "bob@acme.test", ("login_failure", {}), at=cc._rfc3339(NOW - 900 + i)) for i in range(5)],
    "user_accounts": [g("user_accounts", "bob@acme.test", ("2sv_disable", {}))],
    "token": [g("token", "ann@acme.test", ("authorize", {"app_name": "Free PDF Tool"}))],
    "drive": [g("drive", "ann@acme.test", ("change_document_visibility", {"visibility": "people_with_link",
                                                                          "doc_type": "spreadsheet",
                                                                          "doc_title": "Payroll 2027"})),
              g("drive", "ann@acme.test", ("change_user_access", {"target_user": "ann.home@gmail.com",
                                                                  "doc_type": "document", "doc_title": "Plan"})),
              g("drive", "ann@acme.test", ("change_user_access", {"target_user": "partner@acme.test"}))],
}


class FakeHttp:
    def __init__(self, logs=None, signins=(), audits=(), token_status=200, log_status=200):
        self.logs, self.signins, self.audits = logs or GOOGLE_LOGS, list(signins), list(audits)
        self.token_status, self.log_status = token_status, log_status
        self.calls = []

    def __call__(self, method, url, headers, params, form):
        self.calls.append((method, url, params))
        if "token" in url and method == "POST":
            if self.token_status != 200:
                return self.token_status, {"error": "invalid_grant", "error_description": "Token has been revoked."}
            return 200, {"access_token": "t"}
        if self.log_status != 200:
            return self.log_status, {"error": {"message": "nope"}}
        if "admin.googleapis.com" in url:
            return 200, {"items": self.logs.get(url.rsplit("/", 1)[1], [])}
        if url.endswith("signIns"):
            return 200, {"value": self.signins}
        if url.endswith("directoryAudits"):
            return 200, {"value": self.audits}
        return 404, {}


def coach(tmp_path, apps=("google", "microsoft")):
    c = cm.Coach(tmp_path / "coach.json", months=lambda k: {"coach_activity": 1, "coach_notes": 12}.get(k),
                 clock=lambda: NOW)
    c.save_settings({"regions": ["sg"], "region_checks": {"sg": [0, 1, 2]}, "notice_shared": True,
                     "apps_on": list(apps), "file_names": True}, "owner@acme.test")
    for e in ("ann@acme.test", "bob@acme.test"):
        c.upsert_person({"email": e})
    return c


def make(tmp_path, env, http, c=None, clock=lambda: NOW):
    audit = []
    con = cc.Connectors(c or coach(tmp_path), tmp_path / "conn.json", env=lambda: env, http=http, clock=clock,
                        record=lambda t, d: audit.append((t, d)))
    return con, audit


def test_google_log_becomes_records_with_only_the_fixed_fields():
    recs = [r for app, items in GOOGLE_LOGS.items() for r in cc.google_records(app, items, "acme.test")]
    kinds = sorted(r["kind"] for r in recs)
    assert kinds == ["app_access_granted", "file_shared_personal", "file_shared_public", "sign_in_failed_many",
                     "sign_in_risky", "two_step_off"]
    public = next(r for r in recs if r["kind"] == "file_shared_public")
    assert public["file_type"] == "spreadsheet" and public["label"] == "Payroll 2027"
    assert next(r for r in recs if r["kind"] == "sign_in_failed_many")["count"] == 5
    for r in recs:
        assert set(r) <= {"person", "app", "ts", "kind", "label", "file_type", "count", "country", "device"}
    # four wrong passwords are not "many"; sharing with a colleague is not outside
    assert cc.google_records("login", GOOGLE_LOGS["login"][1:5], "acme.test") == []


def test_microsoft_sign_ins_new_place_only_after_the_first_read():
    known = {}
    first = [{"userPrincipalName": "ann@acme.test", "createdDateTime": T, "location": {"countryOrRegion": "SG"},
              "status": {"errorCode": 0}, "deviceDetail": {"operatingSystem": "Windows 11"}}]
    assert cc.ms_sign_in_records(first, known, first_poll=True) == []
    later = [{**first[0], "createdDateTime": cc._rfc3339(NOW - 60), "location": {"countryOrRegion": "RU"},
              "deviceDetail": {"operatingSystem": "Android"}},
             {**first[0], "riskLevelDuringSignIn": "high"}]
    later += [{**first[0], "userPrincipalName": "bob@acme.test", "status": {"errorCode": 50126}}] * 5
    recs = cc.ms_sign_in_records(later, known, first_poll=False)
    assert sorted(r["kind"] for r in recs) == ["sign_in_failed_many", "sign_in_new_place", "sign_in_risky"]
    new = next(r for r in recs if r["kind"] == "sign_in_new_place")
    assert new["country"] == "RU" and new["device"] == "phone"
    assert "ann@acme.test" not in str(known)  # countries are kept by a hash of the email only
    audits = cc.ms_audit_records([
        {"activityDisplayName": "Consent to application", "activityDateTime": T,
         "initiatedBy": {"user": {"userPrincipalName": "ann@acme.test"}},
         "targetResources": [{"displayName": "Mail Helper"}]},
        {"activityDisplayName": "User deleted security info", "activityDateTime": T,
         "initiatedBy": {"user": {"userPrincipalName": "bob@acme.test"}}, "targetResources": []},
        {"activityDisplayName": "Update user", "activityDateTime": T,
         "initiatedBy": {"user": {"userPrincipalName": "bob@acme.test"}}}])
    assert [(r["kind"], r.get("label")) for r in audits] == [("app_access_granted", "Mail Helper"),
                                                              ("two_step_off", None)]


def test_poll_feeds_the_coach_and_never_reads_twice(tmp_path):
    http = FakeHttp()
    con, audit = make(tmp_path, GOOGLE_ENV, http)
    out = con.poll(by="owner@acme.test")
    assert out["microsoft"] == {"skipped": "not connected yet"}
    assert out["google"]["records"] == 6 and out["google"]["moments"] == 6
    assert any(t == "coach_urgent" for t, _ in audit) and audit[-1][0] == "coach_connector_poll"
    start = next(p for m, u, p in http.calls if "admin.googleapis.com" in u)["startTime"]
    assert start == cc._rfc3339(NOW - cc.FIRST_LOOK_H * 3600)
    # the next read looks back OVERLAP_H for late entries, and the same entries are not counted again
    http.calls.clear()
    again = con.poll()
    assert again["google"]["records"] == 0
    start = next(p for m, u, p in http.calls if "admin.googleapis.com" in u)["startTime"]
    assert start == cc._rfc3339(NOW - cc.OVERLAP_H * 3600)
    st = con.status()[0]
    assert st["configured"] and st["switched_on"] and st["last_ok"] and st["last_records"] == 0


def test_nothing_is_read_while_the_coach_may_not_record(tmp_path):
    c = cm.Coach(tmp_path / "coach.json", months=lambda k: 1, clock=lambda: NOW)
    http = FakeHttp()
    con, _ = make(tmp_path, GOOGLE_ENV, http, c=c)
    assert "not switched on yet" in con.poll()["google"]["skipped"] and http.calls == []
    con2, _ = make(tmp_path, GOOGLE_ENV, http, c=coach(tmp_path / "x", apps=("microsoft",)))
    assert "not switched on in the coach" in con2.poll()["google"]["skipped"] and http.calls == []


def test_errors_are_kept_in_plain_words_and_the_other_app_still_reads(tmp_path):
    env = {**GOOGLE_ENV, **MS_ENV}
    http = FakeHttp(token_status=400, signins=[{"userPrincipalName": "ann@acme.test", "createdDateTime": T,
                                                "riskLevelDuringSignIn": "high"}])
    con, _ = make(tmp_path, env, http)
    http_ms_ok = http

    def mixed(method, url, headers, params, form):
        if "oauth2.googleapis.com" in url:
            return 400, {"error": "invalid_grant", "error_description": "Token has been revoked."}
        if "login.microsoftonline.com" in url:
            return 200, {"access_token": "t"}
        return http_ms_ok(method, url, headers, params, form)

    con.http = mixed
    out = con.poll()
    assert "refused the sign-in" in out["google"]["error"] and "revoked" in out["google"]["error"]
    assert out["microsoft"]["records"] == 1
    assert con.status()[0]["last_error"].startswith("Google Workspace refused")
    con.http = FakeHttp(log_status=403)
    assert "missing a permission" in con.poll(only="microsoft")["microsoft"]["error"]


def test_endpoints_and_cli(client, monkeypatch):
    for k, v in GOOGLE_ENV.items():
        monkeypatch.setenv(k, v)
    page = client.get("/ui/coach/connectors").json()["connectors"]
    assert [c["app"] for c in page] == ["google", "microsoft"] and page[0]["configured"] and not page[1]["configured"]
    apps = {a["key"]: a for a in client.get("/ui/coach").json()["apps"]}
    assert apps["google"]["status"] == "live" and apps["microsoft"]["status"] == "ready"
    assert "SentrAI team" in apps["microsoft"]["connection"]
    assert client.post("/ui/coach/connectors/read", json={"app": "okta"}).status_code == 400
    out = client.post("/ui/coach/connectors/read", json={}).json()
    assert "not switched on yet" in out["results"]["google"]["skipped"]
    import sentrai_cli as cli
    from .test_cli import through
    buf = StringIO()
    assert cli.main(["coach", "connectors"], call=through(client), out=buf) == 0
    text = buf.getvalue()
    assert "Google Workspace: connected, but switched off" in text and "COACH_MS_TENANT_ID=..." in text
    buf = StringIO()
    assert cli.main(["coach", "read", "google"], call=through(client), out=buf) == 0
    assert "google: the coach is not switched on yet" in buf.getvalue()
    assert cli.main(["coach", "read", "okta"], call=through(client), out=StringIO()) != 0


def test_settings_are_advanced_secrets_and_the_wizard_never_asks():
    import sentrai_config as cfg
    coach = next(s for s in cfg.SECTIONS if s.key == "coach")
    assert all(f.advanced for f in coach.fields)
    assert {f.env for f in coach.fields if f.secret} == {"COACH_GOOGLE_CLIENT_SECRET", "COACH_GOOGLE_REFRESH_TOKEN",
                                                         "COACH_MS_CLIENT_SECRET"}
    assert set(sum(cc.SETTINGS.values(), ())) <= {f.env for f in coach.fields}


@pytest.mark.parametrize("os_name,device", [("iOS 18", "phone"), ("Windows 10", "computer"), ("", "unknown")])
def test_device_words(os_name, device):
    assert cc._device(os_name) == device
