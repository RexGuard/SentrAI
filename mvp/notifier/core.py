"""Minimal SentrAI core API client for the notifier (see mvp/CONTRACT.md)."""
from __future__ import annotations

from typing import Any

import requests


class CoreError(Exception):
    def __init__(self, message: str, detail: str = "") -> None:
        super().__init__(message)
        self.detail = detail  # the core's own explanation ("detail" of an HTTP error), if it gave one


class Core:
    def __init__(self, base_url: str, timeout: float = 3.0, token: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        if token:  # the core's API token (sentrai_config.api_token())
            self.session.headers["Authorization"] = f"Bearer {token}"

    def _req(self, method: str, path: str, body: Any | None = None) -> Any:
        try:
            r = self.session.request(method, f"{self.base_url}{path}", json=body, timeout=(1.0, self.timeout))
        except requests.RequestException as exc:
            raise CoreError(f"core unreachable at {self.base_url}: {exc.__class__.__name__}") from exc
        if r.status_code >= 400:
            try:
                detail = str((r.json() or {}).get("detail") or "")
            except (ValueError, AttributeError):
                detail = ""
            raise CoreError(f"{method} {path} -> HTTP {r.status_code}: {r.text[:200]}", detail)
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

    def delivered(self, notification_id: str, channel: str, message_id: str, to: str | None = None) -> Any:
        body = {"channel": channel, "message_id": str(message_id)}
        if to:  # a direct message to one person
            body["to"] = to
        return self._req("POST", f"/notifications/{notification_id}/delivered", body)

    def telegram_links(self) -> list[dict]:
        """Private chats linked to routing contacts; [] when the core is older or unreachable."""
        try:
            data = self._req("GET", "/telegram/links")
        except CoreError:
            return []
        return [x for x in data or [] if isinstance(x, dict)]

    def telegram_link(self, code: str, chat_id: str, username: str) -> dict:
        return self._req("POST", "/telegram/link", {"code": code, "chat_id": str(chat_id), "username": username})

    def telegram_unlink(self, chat_id: str, operator: str) -> Any:
        return self._req("POST", "/telegram/unlink", {"chat_id": str(chat_id), "operator": operator})

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

    def assign(self, incident_id: str, assignee: str, operator: str, note: str | None = None) -> Any:
        return self._req("POST", f"/incidents/{incident_id}/assign",
                         {"assignee": assignee, "operator": operator, "note": note})

    def decision(self, incident_id: str, operator: str, decision: str, justification: str) -> Any:
        return self._req("POST", f"/incidents/{incident_id}/decision",
                         {"operator": operator, "decision": decision, "justification": justification})

    def rollback(self, incident_id: str, operator: str, justification: str) -> Any:
        return self._req("POST", f"/incidents/{incident_id}/rollback",
                         {"operator": operator, "justification": justification})

    def permanent(self, incident_id: str, operator: str, justification: str) -> Any:
        return self._req("POST", f"/incidents/{incident_id}/permanent",
                         {"operator": operator, "justification": justification})
