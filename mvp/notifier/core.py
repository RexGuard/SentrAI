"""Minimal SentrAI core API client for the notifier (see mvp/CONTRACT.md)."""
from __future__ import annotations

from typing import Any

import requests


class CoreError(Exception):
    pass


class Core:
    def __init__(self, base_url: str, timeout: float = 3.0, token: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        if token:  # the core's API token (cactai_config.api_token())
            self.session.headers["Authorization"] = f"Bearer {token}"

    def _req(self, method: str, path: str, body: Any | None = None) -> Any:
        try:
            r = self.session.request(method, f"{self.base_url}{path}", json=body, timeout=(1.0, self.timeout))
        except requests.RequestException as exc:
            raise CoreError(f"core unreachable at {self.base_url}: {exc.__class__.__name__}") from exc
        if r.status_code >= 400:
            raise CoreError(f"{method} {path} -> HTTP {r.status_code}: {r.text[:200]}")
        try:
            return r.json()
        except ValueError:
            return None

    def verify(self, line: str) -> dict:
        """Asks the core whether its audit chain still matches a witnessed fingerprint line."""
        try:
            r = self.session.get(f"{self.base_url}/audit/verify", params={"fingerprint": line},
                                 timeout=(1.0, self.timeout))
        except requests.RequestException as exc:
            raise CoreError(f"core unreachable at {self.base_url}: {exc.__class__.__name__}") from exc
        if r.status_code >= 400:
            raise CoreError(f"GET /audit/verify -> HTTP {r.status_code}: {r.text[:200]}")
        return r.json()

    def pending(self) -> list[dict]:
        data = self._req("GET", "/notifications/pending")
        if isinstance(data, dict):  # tolerate {"notifications": [...]}
            data = data.get("notifications") or data.get("pending") or []
        return [n for n in (data or []) if isinstance(n, dict)]

    def delivered(self, notification_id: str, channel: str, message_id: str) -> Any:
        return self._req("POST", f"/notifications/{notification_id}/delivered",
                         {"channel": channel, "message_id": str(message_id)})

    def incident(self, incident_id: str) -> dict | None:
        try:
            return self._req("GET", f"/incidents/{incident_id}")
        except CoreError:
            return None

    def risk(self) -> dict | None:
        try:
            return self._req("GET", "/risk")
        except CoreError:
            return None

    def ack(self, incident_id: str, operator: str, channel: str) -> Any:
        return self._req("POST", f"/incidents/{incident_id}/ack", {"operator": operator, "channel": channel})

    def decision(self, incident_id: str, operator: str, decision: str, justification: str) -> Any:
        return self._req("POST", f"/incidents/{incident_id}/decision",
                         {"operator": operator, "decision": decision, "justification": justification})

    def rollback(self, incident_id: str, operator: str, justification: str) -> Any:
        return self._req("POST", f"/incidents/{incident_id}/rollback",
                         {"operator": operator, "justification": justification})

    def permanent(self, incident_id: str, operator: str, justification: str) -> Any:
        return self._req("POST", f"/incidents/{incident_id}/permanent",
                         {"operator": operator, "justification": justification})

    def staff_report(self, text: str, reporter: str, sender: str, channel: str = "telegram") -> dict:
        """Sends a staff report. Returns the core's answer, or {"error": why} when the core refused it
        (too short, too many reports): that reason is meant for the reporter."""
        try:
            r = self.session.post(f"{self.base_url}/staff-reports", timeout=(1.0, max(self.timeout, 60.0)),
                                  json={"text": text, "reporter": reporter, "channel": channel, "sender": sender})
        except requests.RequestException as exc:
            raise CoreError(f"core unreachable at {self.base_url}: {exc.__class__.__name__}") from exc
        if r.status_code in (400, 429):
            try:
                return {"error": str(r.json().get("detail") or "The report was refused.")}
            except ValueError:
                return {"error": "The report was refused."}
        if r.status_code >= 400:
            raise CoreError(f"POST /staff-reports -> HTTP {r.status_code}: {r.text[:200]}")
        return r.json()
