"""Thin HTTP client for the SentrAI core API (see mvp/CONTRACT.md)."""
from __future__ import annotations

from typing import Any
from urllib.parse import quote

import requests

DEFAULT_TIMEOUT = 2.5
CHAT_TIMEOUT = 90.0  # the orchestrator may call its AI model several times per answer
AI_TEST_TIMEOUT = 45.0  # one real request to the AI provider
SCAN_TIMEOUT = 40.0
BACKUP_TIMEOUT = 600.0  # a backup or restore copies whole folders  # PowerShell/CIM process listing can take a few seconds on Windows


class CoreError(Exception):
    """Raised when the core API is unreachable or returns an error."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


READ_ONLY_POSTS = ("/chat",)  # asking the orchestrator a question changes nothing
READ_ONLY_POST_ENDS = ("/verify",)  # checking a backup is intact changes nothing either
READ_ONLY_MESSAGE = "Auditors can see everything but change nothing. Ask an Owner or Admin."


class CoreClient:
    def __init__(self, base_url: str, timeout: float = DEFAULT_TIMEOUT, token: str = "",
                 read_only: bool = False) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.read_only = read_only  # an Auditor's console: every change is refused before it leaves
        self.session = requests.Session()
        if token:  # the core's API token (sentrai_config.api_token())
            self.session.headers["Authorization"] = f"Bearer {token}"

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def _request(self, method: str, path: str, body: Any | None = None,
                 timeout: float | None = None) -> requests.Response:
        if self.read_only and method != "GET" and path not in READ_ONLY_POSTS \
                and not path.endswith(READ_ONLY_POST_ENDS):
            raise CoreError(READ_ONLY_MESSAGE, 403)
        try:
            resp = self.session.request(method, self._url(path), json=body, timeout=(0.8, timeout or self.timeout))
        except requests.RequestException as exc:
            raise CoreError(f"Core unreachable at {self.base_url} ({exc.__class__.__name__})") from exc
        if resp.status_code >= 400:
            detail = resp.text[:300]
            try:
                payload = resp.json()
                if isinstance(payload, dict) and "detail" in payload:
                    detail = str(payload["detail"])
            except ValueError:
                pass
            raise CoreError(f"{method} {path} -> HTTP {resp.status_code}: {detail}", resp.status_code)
        return resp

    def get_json(self, path: str) -> Any:
        resp = self._request("GET", path)
        try:
            return resp.json()
        except ValueError as exc:
            raise CoreError(f"GET {path} returned non-JSON") from exc

    def get_text(self, path: str) -> str:
        return self._request("GET", path).text

    def post_json(self, path: str, body: Any | None = None, timeout: float | None = None) -> Any:
        resp = self._request("POST", path, body if body is not None else {}, timeout)
        try:
            return resp.json()
        except ValueError:
            return {"ok": True}

    # ---- convenience wrappers (paths from the contract) ----
    def health(self) -> bool:
        try:
            return bool(self.get_json("/health").get("ok"))
        except (CoreError, AttributeError):
            return False

    def risk(self) -> dict:
        return self.get_json("/risk")

    def protection(self) -> dict:
        return self.get_json("/protection")

    def set_protection(self, on: bool, operator: str, reason: str = "") -> dict:
        return self.post_json("/protection", {"on": on, "operator": operator, "reason": reason})

    def incidents(self) -> list[dict]:
        data = self.get_json("/incidents")
        if isinstance(data, dict):  # tolerate {"incidents": [...]}
            data = data.get("incidents", [])
        return list(data or [])

    def audit(self, limit: int = 0) -> Any:
        return self.get_json(f"/audit?limit={limit}" if limit else "/audit")

    def agents(self) -> list[dict]:
        return list(self.get_json("/agents") or [])

    def blocklist(self) -> dict:
        return self.get_json("/blocklist")

    # ---- a central panel: machines that joined it (core fleet.py) ----
    def machines(self) -> list[dict]:
        return list(self.get_json("/machines") or [])

    def machine_incidents(self, host: str) -> list[dict]:
        return list(self.get_json(f"/incidents?host={quote(host, safe='')}") or [])

    def fleet_agents(self) -> list[dict]:
        return list(self.get_json("/fleet/agents") or [])

    def fleet_panel(self) -> dict:
        """The HTTPS address and certificate pin new machines use (the core's SENTRAI_PANEL_URL)."""
        return dict(self.get_json("/fleet/panel") or {})

    def join_code(self, operator: str, name: str | None = None) -> dict:
        return self.post_json("/fleet/join-codes", {"operator": operator, "name": name or None})

    def revoke_agent(self, agent_id: str, operator: str) -> dict:
        return self.post_json(f"/fleet/agents/{quote(agent_id, safe='')}/revoke", {"operator": operator})

    def machine_jobs(self, host: str) -> list[dict]:
        return list(self.get_json(f"/fleet/jobs?host={quote(host, safe='')}") or [])

    def queue_job(self, host: str, kind: str, operator: str) -> dict:
        """Ask one joined machine's agent to run a threat scan or a backup there (core jobs.py)."""
        return self.post_json("/fleet/jobs", {"host": host, "kind": kind, "operator": operator})

    def cancel_job(self, job_id: str, operator: str) -> dict:
        return self.post_json(f"/fleet/jobs/{quote(job_id, safe='')}/cancel", {"operator": operator})

    def report_md(self, incident_id: str) -> str:
        return self.get_text(f"/reports/{incident_id}.md")

    def report_json(self, incident_id: str) -> Any:
        return self.get_json(f"/reports/{incident_id}")

    def report_pdf(self, incident_id: str) -> bytes:
        return self._request("GET", f"/reports/{incident_id}.pdf").content

    def summary_md(self, period: str) -> str:
        return self.get_text(f"/summary/{period}.md")

    def summary_pdf(self, period: str) -> bytes:
        return self._request("GET", f"/summary/{period}.pdf").content

    def summary_schedule(self) -> dict:
        return self.get_json("/summary/schedule")

    def set_summary_schedule(self, operator: str, every: str, at: str, day: str, to: str) -> dict:
        return self.post_json("/summary/schedule", {"operator": operator, "every": every, "at": at, "day": day, "to": to})

    def send_summary(self, operator: str) -> dict:
        return self.post_json("/summary/send", {"operator": operator})

    def decision(self, incident_id: str, operator: str, decision: str, justification: str = "") -> Any:
        return self.post_json(
            f"/incidents/{incident_id}/decision",
            {"operator": operator, "decision": decision, "justification": justification},
        )

    def ack(self, incident_id: str, operator: str, channel: str = "dashboard") -> Any:
        return self.post_json(f"/incidents/{incident_id}/ack", {"operator": operator, "channel": channel})

    def assign(self, incident_id: str, assignee: str, operator: str, note: str = "") -> Any:
        return self.post_json(f"/incidents/{incident_id}/assign",
                              {"assignee": assignee, "operator": operator, "note": note or None})

    def resolve(self, incident_id: str, operator: str, note: str) -> Any:
        return self.post_json(f"/incidents/{incident_id}/resolve", {"operator": operator, "note": note})

    def routing(self) -> dict:
        return self.get_json("/routing")

    def save_routing(self, routing: dict, operator: str, summary: str = "") -> dict:
        """Replace the whole routing file (people, rules, follow-up, map layout); the core checks it before
        writing and puts the summary of what changed in the audit log."""
        return self.post_json("/routing", {"routing": routing, "operator": operator, "summary": summary})

    def telegram_link_code(self, contact: str, operator: str) -> dict:
        return self.post_json("/telegram/link-codes", {"contact": contact, "operator": operator})

    def telegram_unlink(self, contact: str, operator: str) -> Any:
        return self.post_json("/telegram/unlink", {"contact": contact, "operator": operator})

    def rollback(self, incident_id: str, operator: str, justification: str) -> Any:
        return self.post_json(
            f"/incidents/{incident_id}/rollback", {"operator": operator, "justification": justification}
        )

    def permanent(self, incident_id: str, operator: str, justification: str) -> Any:
        return self.post_json(
            f"/incidents/{incident_id}/permanent", {"operator": operator, "justification": justification}
        )

    def chat_history(self) -> dict:
        data = self.get_json("/chat")
        return data if isinstance(data, dict) else {"messages": list(data or [])}

    def chat(self, operator: str, message: str, incident: str | None = None) -> dict:
        return self.post_json("/chat", {"operator": operator, "message": message, "incident": incident},
                              timeout=CHAT_TIMEOUT)

    def setup_interpret(self, question: str, options: list[tuple[str, str]], answer: str) -> dict:
        """Guided setup: let the AI model map an answer the script could not match (never a secret)."""
        return self.post_json("/chat/setup/interpret", {
            "question": question, "options": [{"value": v, "label": label} for v, label in options],
            "answer": answer}, timeout=CHAT_TIMEOUT)

    def clear_chat(self) -> Any:
        return self.post_json("/chat/clear", {})

    def ai_status(self) -> dict:
        return self.get_json("/ai")

    def ai_reload(self) -> dict:
        """Make the running core read the saved AI settings again (no restart)."""
        return self.post_json("/ai/reload", {})

    def integrations(self) -> list[dict]:
        """Outside services (Cloudflare, AbuseIPDB, Slack...): whether each is set up. Never their keys."""
        return self.get_json("/integrations")

    def test_integration(self, name: str) -> dict:
        return self.post_json(f"/integrations/{name}/test", timeout=AI_TEST_TIMEOUT)

    def ai_test(self, settings: dict | None = None) -> dict:
        """One real request to the AI provider: with settings, those; without, what Cyanide uses now."""
        return self.post_json("/ai/test", settings, timeout=AI_TEST_TIMEOUT)

    def scan_system(self, operator: str) -> dict:
        """Read-only scan of the running programs; returns suggested log files, each with an id."""
        return self.post_json("/system/scan", {"operator": operator}, timeout=SCAN_TIMEOUT)

    def latest_scan(self) -> dict:
        return self.get_json("/system/scan")

    def scan_threats(self, operator: str) -> dict:
        """Read-only threat scan of the configured folders; findings each have an id for quarantine."""
        return self.post_json("/threats/scan", {"operator": operator}, timeout=SCAN_TIMEOUT)

    def latest_threats(self) -> dict:
        return self.get_json("/threats")

    def quarantine(self, finding_id: str, operator: str, reason: str = "") -> dict:
        return self.post_json(f"/threats/{finding_id}/quarantine", {"operator": operator, "reason": reason})

    def quarantined(self) -> list[dict]:
        return list(self.get_json("/quarantine") or [])

    def restore(self, quarantine_id: str, operator: str) -> dict:
        return self.post_json(f"/quarantine/{quarantine_id}/restore", {"operator": operator})

    def backups(self) -> dict:
        """Backup settings, the next one due and every backup kept (newest first)."""
        return self.get_json("/backups")

    def backup_now(self, operator: str) -> dict:
        out = self.post_json("/backups", {"operator": operator}, timeout=BACKUP_TIMEOUT)
        if not out.get("ok"):
            raise CoreError(out.get("error") or out.get("note") or "backup failed")
        return out

    def verify_backup(self, backup_id: str, operator: str) -> dict:
        out = self.post_json(f"/backups/{backup_id}/verify", {"operator": operator}, timeout=BACKUP_TIMEOUT)
        if not out.get("ok"):
            raise CoreError("; ".join(out.get("problems") or ["check failed"]))
        return out

    def restore_backup(self, backup_id: str, operator: str, in_place: bool = False, confirm: str = "") -> dict:
        out = self.post_json(f"/backups/{backup_id}/restore",
                             {"operator": operator, "in_place": in_place, "confirm": confirm}, timeout=BACKUP_TIMEOUT)
        if not out.get("ok"):
            raise CoreError(f"{out.get('files_restored', 0)} files restored, {len(out.get('failed') or [])} failed: "
                            + "; ".join((out.get("failed") or [])[:3]))
        return out

    def log_sources(self) -> list[dict]:
        """Extra log files the collector watches (approved from a scan, or by Scout)."""
        return list(self.get_json("/log-sources") or [])

    def watch_log(self, file_id: str, operator: str, layer: str | None = None) -> dict:
        return self.post_json("/log-sources", {"file_id": file_id, "operator": operator, "layer": layer})

    def pending_log_sources(self) -> list[dict]:
        """Log files Scout proposed that wait for an operator's yes or no."""
        return list(self.get_json("/log-sources/pending") or [])

    def decide_log_source(self, proposal_id: str, operator: str, approve: bool, reason: str = "") -> dict:
        return self.post_json(f"/log-sources/pending/{proposal_id}",
                              {"operator": operator, "approve": approve, "reason": reason})

    # ---- staff reports: anyone at the business reports something suspicious ----
    def report_suspicious(self, text: str, reporter: str = "", contact: str = "", where: str = "",
                          sender: str = "", host: str = "") -> dict:
        """Send one staff report; the answer holds the advice for the reporter. Sorting may use the AI model."""
        return self.post_json("/staff-reports", {"text": text, "reporter": reporter, "contact": contact,
                                                 "where": where, "channel": "dashboard", "sender": sender,
                                                 "host": host}, timeout=CHAT_TIMEOUT)

    def machine_names(self) -> list[str]:
        """Machines a central panel knows (GET /machines); empty when this core has no such list."""
        try:
            rows = self.get_json("/machines")
        except CoreError:
            return []
        return [str(m["host"]) for m in rows or [] if isinstance(m, dict) and m.get("host")]

    def staff_reports(self, status: str | None = None) -> dict:
        return self.get_json(f"/staff-reports?status={status}" if status else "/staff-reports")

    def update_staff_report(self, report_id: str, operator: str, status: str | None = None,
                            assignee: str | None = None, note: str | None = None) -> dict:
        return self.post_json(f"/staff-reports/{report_id}", {"operator": operator, "status": status,
                                                              "assignee": assignee, "note": note})
