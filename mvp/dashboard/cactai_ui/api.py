"""Thin HTTP client for the SentrAI core API (see mvp/CONTRACT.md)."""
from __future__ import annotations

from typing import Any

import requests

DEFAULT_TIMEOUT = 2.5
CHAT_TIMEOUT = 90.0  # the orchestrator may call its AI model several times per answer
AI_TEST_TIMEOUT = 45.0  # one real request to the AI provider
SCAN_TIMEOUT = 40.0  # PowerShell/CIM process listing can take a few seconds on Windows


class CoreError(Exception):
    """Raised when the core API is unreachable or returns an error."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class CoreClient:
    def __init__(self, base_url: str, timeout: float = DEFAULT_TIMEOUT, token: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        if token:  # the core's API token (cactai_config.api_token())
            self.session.headers["Authorization"] = f"Bearer {token}"

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

    def report_pdf(self, incident_id: str) -> bytes:
        return self._request("GET", f"/reports/{incident_id}.pdf").content

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

    def ai_status(self) -> dict:
        return self.get_json("/ai")

    def ai_reload(self) -> dict:
        """Make the running core read the saved AI settings again (no restart)."""
        return self.post_json("/ai/reload", {})

    def ai_test(self, settings: dict | None = None) -> dict:
        """One real request to the AI provider: with settings, those; without, what Cyanide uses now."""
        return self.post_json("/ai/test", settings, timeout=AI_TEST_TIMEOUT)

    def scan_system(self, operator: str) -> dict:
        """Read-only scan of the running programs; returns suggested log files, each with an id."""
        return self.post_json("/system/scan", {"operator": operator}, timeout=SCAN_TIMEOUT)

    def latest_scan(self) -> dict:
        return self.get_json("/system/scan")

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

    def reset_demo(self) -> Any:
        return self.post_json("/demo/reset", {})
