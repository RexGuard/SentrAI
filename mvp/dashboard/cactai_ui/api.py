"""Thin HTTP client for the CactAI core API (see mvp/CONTRACT.md)."""
from __future__ import annotations

from typing import Any

import requests

DEFAULT_TIMEOUT = 2.5
CHAT_TIMEOUT = 90.0  # the orchestrator may call its AI model several times per answer


class CoreError(Exception):
    """Raised when the core API is unreachable or returns an error."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class CoreClient:
    def __init__(self, base_url: str, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def _request(self, method: str, path: str, body: Any | None = None,
                 timeout: float | None = None) -> requests.Response:
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

    def report_md(self, incident_id: str) -> str:
        return self.get_text(f"/reports/{incident_id}.md")

    def report_json(self, incident_id: str) -> Any:
        return self.get_json(f"/reports/{incident_id}")

    def decision(self, incident_id: str, operator: str, decision: str, justification: str = "") -> Any:
        return self.post_json(
            f"/incidents/{incident_id}/decision",
            {"operator": operator, "decision": decision, "justification": justification},
        )

    def ack(self, incident_id: str, operator: str, channel: str = "dashboard") -> Any:
        return self.post_json(f"/incidents/{incident_id}/ack", {"operator": operator, "channel": channel})

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

    def clear_chat(self) -> Any:
        return self.post_json("/chat/clear", {})

    def reset_demo(self) -> Any:
        return self.post_json("/demo/reset", {})
