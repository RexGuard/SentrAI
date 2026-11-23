"""Security Coach connectors: read Google Workspace's and Microsoft 365's admin activity logs, read-only, and hand the
coach one short record per risky action (coach.py turns it into a moment, a lesson and a kind note).

Nothing is fetched until the coach may record (the staff notice is shared and each region's checklist is done) and
the admin switched that app on in the coach's settings. Each poll asks only for the activity since the last one
(the first looks back FIRST_LOOK_H hours), and only the fixed fields the coach keeps leave this module: who, which
app, the kind of action, when, a country, the kind of device, a count, and a file's type (its name only when the
admin turned file names on). Message and file contents are never asked for.

Set up by SentrAI's team in the terminal (advanced settings, `sudo sentrai settings set ...`):

  Google Workspace  COACH_GOOGLE_CLIENT_ID, COACH_GOOGLE_CLIENT_SECRET, COACH_GOOGLE_REFRESH_TOKEN (an OAuth client
                    the company's super admin signed in to once, scope admin.reports.audit.readonly) and
                    COACH_GOOGLE_DOMAIN (the company's own email domain, to tell outside sharing apart).
                    Reads the Admin SDK Reports API: login, user_accounts, token and drive.
  Microsoft 365     COACH_MS_TENANT_ID, COACH_MS_CLIENT_ID, COACH_MS_CLIENT_SECRET (an app registration with the
                    application permission AuditLog.Read.All, admin-consented). Reads Microsoft Graph sign-ins
                    (needs Entra ID P1) and directory audits.

What each log becomes:
  Google  suspicious sign-in (login)                           -> sign_in_risky
          FAILED_MANY+ wrong passwords for one person in a poll -> sign_in_failed_many
          2-step verification turned off (user_accounts)        -> two_step_off
          mail forwarding to another domain (user_accounts)     -> mail_forward_outside
          an app given access to the account (token)            -> app_access_granted
          a file made public or link-shared (drive)             -> file_shared_public
          a file shared with a personal email address (drive)   -> file_shared_personal
          BULK_DOWNLOAD+ downloads by one person in a poll      -> bulk_download
  Microsoft  sign-in Entra marked risky                         -> sign_in_risky
             FAILED_MANY+ failed sign-ins for one person        -> sign_in_failed_many
             sign-in from a country new for that person         -> sign_in_new_place (after the first poll)
             consent given to an app                            -> app_access_granted
             security info (2-step) removed                     -> two_step_off
Mail forwarding rules in Microsoft 365 live in the Office 365 Management Activity API, not Graph: not read yet.

The connectors' own state (coach-connectors.json, sentrai_paths "core.coach_connectors") is the time of the last
poll, the last result, and per person (by a hash of the email, never the email) the last few sign-in countries.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

FIRST_LOOK_H = 24
FAILED_MANY = 5
BULK_DOWNLOAD = 50
MAX_PAGES = 10
KNOWN_COUNTRIES = 5
POLL_MINUTES = 15
OVERLAP_H = 3  # both logs can show an action hours late: each read looks this far back again, and skips repeats
AGGREGATED = {"sign_in_failed_many", "bulk_download"}

GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GOOGLE_REPORTS = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/{app}"
MS_TOKEN = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
MS_GRAPH = "https://graph.microsoft.com/v1.0"

SETTINGS = {"google": ("COACH_GOOGLE_CLIENT_ID", "COACH_GOOGLE_CLIENT_SECRET", "COACH_GOOGLE_REFRESH_TOKEN"),
            "microsoft": ("COACH_MS_TENANT_ID", "COACH_MS_CLIENT_ID", "COACH_MS_CLIENT_SECRET")}
NAMES = {"google": "Google Workspace", "microsoft": "Microsoft 365"}
PERSONAL_DOMAINS = {"gmail.com", "googlemail.com", "yahoo.com", "yahoo.com.sg", "hotmail.com", "outlook.com",
                    "live.com", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com",
                    "qq.com", "163.com"}
GOOGLE_RISKY = {"suspicious_login", "suspicious_login_less_secure_app", "suspicious_programmatic_login",
                "gov_attack_warning", "account_disabled_hijacked"}
PUBLIC_VISIBILITY = {"people_with_link", "public_on_the_web", "people_within_domain_with_link_and_public"}
DOC_TYPES = {"spreadsheet": "spreadsheet", "document": "document", "presentation": "presentation", "pdf": "pdf",
             "folder": "folder", "image": "image", "video": "video", "drawing": "image"}
MS_2STEP_OFF = {"User deleted security info", "Admin deleted security info", "Disable Strong Authentication",
                "User disabled Strong Authentication"}

# method, url, headers, params, form -> (status, json body)
Http = Callable[[str, str, dict[str, str], dict[str, Any] | None, dict[str, str] | None], tuple[int, dict[str, Any]]]


class ConnectorError(Exception):
    """A connector could not read its log; the message says why in plain words."""


def httpx_http(method: str, url: str, headers: dict[str, str], params: dict[str, Any] | None,
               form: dict[str, str] | None) -> tuple[int, dict[str, Any]]:
    import httpx
    r = httpx.request(method, url, headers=headers, params=params, data=form, timeout=20.0)
    try:
        body = r.json()
    except ValueError:
        body = {}
    return r.status_code, body if isinstance(body, dict) else {}


def _epoch(text: Any) -> float | None:
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _rfc3339(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _who(email: Any) -> str:
    return hashlib.sha256(str(email or "").strip().lower().encode()).hexdigest()[:16]


def _seen_key(r: dict[str, Any]) -> str:
    when = int(r["ts"] // 3600) if r["kind"] in AGGREGATED else round(float(r["ts"]), 3)
    return hashlib.sha256(f"{r['app']}|{r['person']}|{r['kind']}|{when}|{r.get('label', '')}".encode()).hexdigest()[:20]


def _params(event: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for p in event.get("parameters") or []:
        if isinstance(p, dict) and p.get("name"):
            out[p["name"]] = p.get("value", p.get("boolValue", p.get("multiValue", p.get("intValue"))))
    return out


# --------------------------------------------------------------------------- Google Workspace: log -> records
def google_records(app: str, items: list[dict[str, Any]], domain: str) -> list[dict[str, Any]]:
    """Reports API activities for one application -> the coach's records (only its fixed fields)."""
    out: list[dict[str, Any]] = []
    failed: dict[str, list[float]] = {}
    downloads: dict[str, list[float]] = {}
    domain = domain.strip().lower().lstrip("@")
    for item in items:
        person = str((item.get("actor") or {}).get("email") or "").lower()
        ts = _epoch((item.get("id") or {}).get("time"))
        if not person or ts is None:
            continue
        for ev in item.get("events") or []:
            name, p = str(ev.get("name") or ""), _params(ev)
            base = {"person": person, "app": "google", "ts": ts}
            if app == "login":
                if name in GOOGLE_RISKY:
                    out.append({**base, "kind": "sign_in_risky"})
                elif name == "login_failure":
                    failed.setdefault(person, []).append(ts)
            elif app == "user_accounts":
                if name == "2sv_disable":
                    out.append({**base, "kind": "two_step_off"})
                elif name == "email_forwarding_out_of_domain":
                    out.append({**base, "kind": "mail_forward_outside"})
            elif app == "token" and name == "authorize":
                out.append({**base, "kind": "app_access_granted", "label": str(p.get("app_name") or "")[:80]})
            elif app == "drive":
                ftype = DOC_TYPES.get(str(p.get("doc_type") or "").lower(), "file")
                label = str(p.get("doc_title") or "")[:80]
                target = str(p.get("target_user") or "").lower()
                visibility = str(p.get("visibility") or p.get("new_value") or "").lower()
                if name == "download":
                    downloads.setdefault(person, []).append(ts)
                elif name in ("change_document_visibility", "change_document_access_scope") \
                        and (visibility in PUBLIC_VISIBILITY or any(v in PUBLIC_VISIBILITY for v in
                                                                    (p.get("new_value") or []) if isinstance(v, str))):
                    out.append({**base, "kind": "file_shared_public", "file_type": ftype, "label": label})
                elif name == "change_user_access" and "@" in target:
                    where = target.rsplit("@", 1)[1]
                    if where in PERSONAL_DOMAINS and where != domain:
                        out.append({**base, "kind": "file_shared_personal", "file_type": ftype, "label": label})
    for person, times in failed.items():
        if len(times) >= FAILED_MANY:
            out.append({"person": person, "app": "google", "ts": max(times), "kind": "sign_in_failed_many",
                        "count": len(times)})
    for person, times in downloads.items():
        if len(times) >= BULK_DOWNLOAD:
            out.append({"person": person, "app": "google", "ts": max(times), "kind": "bulk_download",
                        "count": len(times)})
    return out


# --------------------------------------------------------------------------- Microsoft 365: log -> records
def _device(os_name: Any) -> str:
    text = str(os_name or "").lower()
    if any(w in text for w in ("android", "ios", "iphone")):
        return "phone"
    if "ipad" in text:
        return "tablet"
    if any(w in text for w in ("windows", "mac", "linux", "chrome")):
        return "computer"
    return "unknown"


def ms_sign_in_records(items: list[dict[str, Any]], known: dict[str, list[str]],
                       first_poll: bool) -> list[dict[str, Any]]:
    """Graph sign-ins -> records. `known` (hash of email -> countries) is updated in place."""
    out: list[dict[str, Any]] = []
    failed: dict[str, list[float]] = {}
    for s in sorted(items, key=lambda x: str(x.get("createdDateTime") or "")):
        person = str(s.get("userPrincipalName") or "").lower()
        ts = _epoch(s.get("createdDateTime"))
        if not person or "@" not in person or ts is None:
            continue
        country = str((s.get("location") or {}).get("countryOrRegion") or "").upper()
        base = {"person": person, "app": "microsoft", "ts": ts, "device": _device((s.get("deviceDetail") or {})
                                                                                   .get("operatingSystem"))}
        if country:
            base["country"] = country
        risky = str(s.get("riskLevelDuringSignIn") or "").lower() in ("high", "medium") \
            or str(s.get("riskState") or "") in ("atRisk", "confirmedCompromised")
        code = (s.get("status") or {}).get("errorCode")
        if risky:
            out.append({**base, "kind": "sign_in_risky"})
        elif code not in (None, 0):
            failed.setdefault(person, []).append(ts)
        elif country:
            seen = known.setdefault(_who(person), [])
            if country not in seen:
                if seen and not first_poll:
                    out.append({**base, "kind": "sign_in_new_place"})
                known[_who(person)] = (seen + [country])[-KNOWN_COUNTRIES:]
    for person, times in failed.items():
        if len(times) >= FAILED_MANY:
            out.append({"person": person, "app": "microsoft", "ts": max(times), "kind": "sign_in_failed_many",
                        "count": len(times)})
    return out


def ms_audit_records(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Graph directory audits -> records."""
    out: list[dict[str, Any]] = []
    for a in items:
        user = ((a.get("initiatedBy") or {}).get("user") or {})
        person = str(user.get("userPrincipalName") or "").lower()
        ts = _epoch(a.get("activityDateTime"))
        name = str(a.get("activityDisplayName") or "")
        if not person or "@" not in person or ts is None:
            continue
        if name == "Consent to application":
            app_name = next((str(t.get("displayName") or "") for t in a.get("targetResources") or []
                             if isinstance(t, dict)), "")
            out.append({"person": person, "app": "microsoft", "ts": ts, "kind": "app_access_granted",
                        "label": app_name[:80]})
        elif name in MS_2STEP_OFF:
            target = next((str(t.get("userPrincipalName") or "").lower() for t in a.get("targetResources") or []
                           if isinstance(t, dict) and t.get("userPrincipalName")), person)
            out.append({"person": target, "app": "microsoft", "ts": ts, "kind": "two_step_off"})
    return out


# --------------------------------------------------------------------------- the connectors
class Connectors:
    def __init__(self, coach: Any, path: Path, env: Callable[[], dict[str, str]], http: Http | None = None,
                 clock: Callable[[], float] = time.time,
                 record: Callable[[str, dict[str, Any]], Any] | None = None) -> None:
        self.coach = coach
        self.path = Path(path)
        self.env = env
        self.http = http or httpx_http
        self.clock = clock
        self.record = record
        self._lock = threading.Lock()

    # -- state
    def _read(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def configured(self, app: str) -> bool:
        e = self.env()
        return all(str(e.get(k) or "").strip() for k in SETTINGS[app])

    def live(self) -> set[str]:
        return {a for a in SETTINGS if self.configured(a)}

    def status(self) -> list[dict[str, Any]]:
        state = self._read()
        try:
            on = set(self.coach.settings().get("apps_on") or [])
        except Exception:  # noqa: BLE001
            on = set()
        out = []
        for app in SETTINGS:
            st = state.get(app) or {}
            out.append({"app": app, "name": NAMES[app], "configured": self.configured(app), "switched_on": app in on,
                        "last_poll": st.get("last_poll"), "last_ok": st.get("last_ok"),
                        "last_error": st.get("last_error"), "last_records": st.get("last_records"),
                        "last_result": st.get("last_result"),
                        "setup": "sudo sentrai settings set " + " ".join(f"{k}=..." for k in SETTINGS[app])})
        return out

    # -- tokens
    def _token(self, app: str) -> str:
        e = self.env()
        if app == "google":
            status, body = self.http("POST", GOOGLE_TOKEN, {}, None, {
                "grant_type": "refresh_token", "client_id": e["COACH_GOOGLE_CLIENT_ID"],
                "client_secret": e["COACH_GOOGLE_CLIENT_SECRET"], "refresh_token": e["COACH_GOOGLE_REFRESH_TOKEN"]})
        else:
            status, body = self.http("POST", MS_TOKEN.format(tenant=e["COACH_MS_TENANT_ID"]), {}, None, {
                "grant_type": "client_credentials", "client_id": e["COACH_MS_CLIENT_ID"],
                "client_secret": e["COACH_MS_CLIENT_SECRET"], "scope": "https://graph.microsoft.com/.default"})
        token = body.get("access_token")
        if status != 200 or not token:
            raise ConnectorError(f"{NAMES[app]} refused the sign-in ({status}: "
                                 f"{str(body.get('error_description') or body.get('error') or 'no token')[:160]}). "
                                 "Check the connection settings.")
        return str(token)

    def _pages(self, url: str, token: str, params: dict[str, Any] | None, items_key: str,
               next_key: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        headers = {"Authorization": f"Bearer {token}"}
        for _ in range(MAX_PAGES):
            status, body = self.http("GET", url, headers, params, None)
            if status == 403:
                raise ConnectorError("the connection is missing a permission (read-only audit log access).")
            if status != 200:
                raise ConnectorError(f"the activity log answered {status}: "
                                     f"{str((body.get('error') or {}).get('message') if isinstance(body.get('error'), dict) else body.get('error') or '')[:160]}")
            out += [x for x in body.get(items_key) or [] if isinstance(x, dict)]
            nxt = body.get(next_key)
            if not nxt:
                break
            if next_key == "nextPageToken":
                params = {**(params or {}), "pageToken": nxt}
            else:
                url, params = str(nxt), None
        return out

    def _fetch(self, app: str, since: float, state: dict[str, Any]) -> list[dict[str, Any]]:
        token = self._token(app)
        if app == "google":
            domain = str(self.env().get("COACH_GOOGLE_DOMAIN") or "")
            records: list[dict[str, Any]] = []
            for log in ("login", "user_accounts", "token", "drive"):
                items = self._pages(GOOGLE_REPORTS.format(app=log), token,
                                    {"startTime": _rfc3339(since), "maxResults": 1000}, "items", "nextPageToken")
                records += google_records(log, items, domain)
            return records
        first = not state.get("last_ok")
        known = state.setdefault("countries", {})
        flt = f"createdDateTime ge {_rfc3339(since)}"
        signins = self._pages(f"{MS_GRAPH}/auditLogs/signIns", token, {"$filter": flt, "$top": 500}, "value",
                              "@odata.nextLink")
        audits = self._pages(f"{MS_GRAPH}/auditLogs/directoryAudits", token,
                             {"$filter": f"activityDateTime ge {_rfc3339(since)}", "$top": 500}, "value",
                             "@odata.nextLink")
        return ms_sign_in_records(signins, known, first) + ms_audit_records(audits)

    def _ingest(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {"recorded": 0, "moments": 0, "dropped": 0, "urgent": []}
        size = int(getattr(self.coach, "max_events", 0) or 500)
        for i in range(0, len(records), size):
            part = self.coach.ingest(records[i:i + size])
            for k in ("recorded", "moments", "dropped"):
                out[k] += int(part.get(k) or 0)
            out["urgent"] += part.get("urgent") or []
        return out

    def poll(self, only: str | None = None, by: str = "schedule") -> dict[str, Any]:
        """Read each configured, switched-on app's log since the last poll and hand the records to the coach.
        Returns {app: result}. Nothing is fetched while the coach may not record."""
        ok, why = self.coach.ready()
        on = set(self.coach.settings().get("apps_on") or [])
        results: dict[str, Any] = {}
        with self._lock:
            state = self._read()
            for app in SETTINGS:
                if only and app != only:
                    continue
                st = state.setdefault(app, {})
                if not self.configured(app):
                    results[app] = {"skipped": "not connected yet"}
                    continue
                if not ok:
                    results[app] = {"skipped": "the coach is not switched on yet: " + why}
                    continue
                if app not in on:
                    results[app] = {"skipped": f"{NAMES[app]} is not switched on in the coach's settings"}
                    continue
                now = self.clock()
                since = float(st["since"]) - OVERLAP_H * 3600 if st.get("since") else now - FIRST_LOOK_H * 3600
                st["last_poll"] = _rfc3339(now)
                try:
                    seen = {k: t for k, t in (st.get("seen") or {}).items() if t >= since}
                    records = [r for r in self._fetch(app, since, st) if _seen_key(r) not in seen]
                    seen |= {_seen_key(r): r["ts"] for r in records}
                    out = self._ingest(records)
                except Exception as exc:  # noqa: BLE001  one app failing must not stop the other
                    st["last_error"] = str(exc)[:300]
                    results[app] = {"error": st["last_error"]}
                    continue
                st.update({"since": now, "seen": seen, "last_ok": _rfc3339(now), "last_error": None, "last_records": len(records),
                           "last_result": {k: out.get(k) for k in ("recorded", "moments", "dropped")}})
                results[app] = {"records": len(records), **st["last_result"], "urgent": out.get("urgent", [])}
                if self.record is not None:
                    for u in out.get("urgent", []):
                        self.record("coach_urgent", {"moment": u["id"], "kind": u["kind"], "by": f"{app} connector"})
            self._write(state)
        if self.record is not None and by != "schedule":
            self.record("coach_connector_poll", {"by": by, "apps": {a: {k: v for k, v in r.items() if k != "urgent"}
                                                                    for a, r in results.items()}})
        return results
