"""CactAI core API (FastAPI, http://127.0.0.1:8000). Endpoints follow mvp/CONTRACT.md."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from typing import Any, Optional, Union

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict

from .config import Settings
from .reports import build_report, render_markdown
from . import ai
from .chat import OperatorChat, default_chat_provider
from .discovery import Discovery
from .cyanide import Cyanide, default_planner
from .saguaro import BadRequestError, ConflictError, Saguaro

log = logging.getLogger("cactai.core")


class EventIn(BaseModel):
    model_config = ConfigDict(extra="allow")
    event_id: Optional[str] = None
    timestamp: Optional[str] = None
    host: Optional[str] = "unknown"
    layer: Optional[str] = "web"
    source: Optional[str] = "unknown"
    src_ip: Optional[str] = None
    user: Optional[str] = None
    raw: Optional[str] = ""
    asset_criticality: Optional[float] = 1.0


class DecisionIn(BaseModel):
    operator: str
    decision: str
    justification: Optional[str] = None


class OperatorIn(BaseModel):
    operator: str
    justification: Optional[str] = None


class AckIn(BaseModel):
    operator: str
    channel: Optional[str] = "dashboard"


class DeliveredIn(BaseModel):
    channel: str
    message_id: Optional[Union[str, int]] = None


class ProtectionIn(BaseModel):
    operator: str
    on: bool
    reason: Optional[str] = None


class AdvanceIn(BaseModel):
    demo_hours: float = 1.0


class ChatIn(BaseModel):
    operator: str
    message: str
    incident: Optional[str] = None


class ScanIn(BaseModel):
    operator: str = "operator"


class LogSourceIn(BaseModel):
    operator: str
    file_id: str
    layer: Optional[str] = None


class AITestIn(BaseModel):
    provider: str
    api_key: str = ""
    base_url: str = ""
    model: str = ""


class HeartbeatIn(BaseModel):
    collector: str


def create_app(settings: Settings | None = None) -> FastAPI:
    # Cyanide (Claude-planned) is the default orchestrator; CACTAI_ENGINE=saguaro keeps the fixed playbooks.
    if os.getenv("CACTAI_ENGINE", "cyanide").lower() == "saguaro":
        core: Saguaro = Saguaro(settings or Settings())
    else:
        core = Cyanide(settings or Settings(), planner=default_planner())

    async def ticker() -> None:
        while True:
            await asyncio.sleep(core.settings.tick_s)
            try:
                core.tick()
            except Exception:  # never let the loop die
                log.exception("tick failed")

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI):
        task = asyncio.create_task(ticker()) if core.settings.background else None
        yield
        if task:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        core.audit.close()

    # Operator chat: read-only tools plus suggestion buttons; answers from the core's own
    # explanations when no AI key is set (or when the fixed-playbook engine runs).
    discovery = Discovery(core)
    chat = OperatorChat(core, default_chat_provider() if isinstance(core, Cyanide) else None, discovery)
    chat.off_reason = core.ai_off_reason = ai.why_off()

    app = FastAPI(title="CactAI core", version="0.1.0", lifespan=lifespan)
    app.state.core = core
    app.state.chat = chat
    app.state.discovery = discovery

    def not_found(iid: str) -> HTTPException:
        return HTTPException(status_code=404, detail=f"incident {iid} not found")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True}

    @app.post("/events")
    def post_events(payload: Union[list[EventIn], EventIn] = Body(...)) -> dict[str, Any]:
        items = payload if isinstance(payload, list) else [payload]
        return core.ingest([e.model_dump() for e in items])

    @app.get("/risk")
    def get_risk(history: int = Query(600, ge=0, le=3600)) -> dict[str, Any]:
        return core.risk(history=history)

    @app.get("/incidents")
    def get_incidents() -> list[dict[str, Any]]:
        return core.list_incidents()

    @app.get("/incidents/{iid}")
    def get_incident(iid: str) -> dict[str, Any]:
        try:
            return core.get_incident(iid)
        except KeyError:
            raise not_found(iid)

    @app.get("/incidents/{iid}/why")
    def get_why(iid: str) -> dict[str, Any]:
        try:
            return {"incident": iid, "answer": core.why(iid)}
        except KeyError:
            raise not_found(iid)

    def _verb(fn, iid: str, *args: Any) -> dict[str, Any]:
        try:
            return fn(iid, *args)
        except KeyError:
            raise not_found(iid)
        except BadRequestError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except ConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    @app.post("/incidents/{iid}/decision")
    def post_decision(iid: str, body: DecisionIn) -> dict[str, Any]:
        return _verb(core.decision, iid, body.operator, body.decision.strip().lower(), body.justification)

    @app.post("/incidents/{iid}/rollback")
    def post_rollback(iid: str, body: OperatorIn) -> dict[str, Any]:
        return _verb(core.rollback, iid, body.operator, body.justification)

    @app.post("/incidents/{iid}/permanent")
    def post_permanent(iid: str, body: OperatorIn) -> dict[str, Any]:
        return _verb(core.make_permanent, iid, body.operator, body.justification)

    @app.post("/incidents/{iid}/ack")
    def post_ack(iid: str, body: AckIn) -> dict[str, Any]:
        return _verb(core.ack, iid, body.operator, body.channel or "dashboard")

    @app.get("/audit")
    def get_audit(limit: int = Query(0, ge=0), incident: Optional[str] = None) -> dict[str, Any]:
        valid, bad = core.audit.verify()
        records = core.audit.records()
        total = len(records)
        if incident:
            records = [r for r in records if r["data"].get("incident") == incident]
        if limit:
            records = records[-limit:]
        return {"chain_valid": valid, "first_invalid_seq": bad, "count": total,
                "head_hash": core.audit.head_hash(), "records": records}

    # The .md route must be registered before the JSON route.
    @app.get("/reports/{iid}.md", response_class=PlainTextResponse)
    def get_report_md(iid: str) -> PlainTextResponse:
        try:
            return PlainTextResponse(render_markdown(build_report(core, iid)), media_type="text/markdown; charset=utf-8")
        except KeyError:
            raise not_found(iid)

    @app.get("/reports/{iid}")
    def get_report(iid: str) -> dict[str, Any]:
        try:
            return build_report(core, iid)
        except KeyError:
            raise not_found(iid)

    @app.get("/protection")
    def get_protection() -> dict[str, Any]:
        return core.protection()

    @app.post("/protection")
    def post_protection(body: ProtectionIn) -> dict[str, Any]:
        try:
            return core.set_protection(body.on, body.operator, body.reason)
        except BadRequestError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/blocklist")
    def get_blocklist() -> dict[str, list[str]]:
        return core.blocklist()

    @app.get("/notifications/pending")
    def get_pending() -> list[dict[str, Any]]:
        return core.pending_notifications()

    @app.get("/notifications")
    def get_notifications() -> list[dict[str, Any]]:
        from .saguaro import public
        with core.lock:
            return public(core.notifications)

    @app.post("/notifications/{nid}/delivered")
    def post_delivered(nid: str, body: DeliveredIn) -> dict[str, Any]:
        try:
            mid = None if body.message_id is None else str(body.message_id)
            return core.mark_delivered(nid, body.channel, mid)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"notification {nid} not found")

    @app.get("/agents")
    def get_agents() -> list[dict[str, Any]]:
        return core.agents_status()

    @app.get("/helpdesk/why")
    def helpdesk_why(target: str) -> dict[str, Any]:
        return core.why_target(target)

    @app.get("/chat")
    def get_chat(limit: int = Query(100, ge=0, le=200)) -> dict[str, Any]:
        return chat.messages(limit)

    @app.post("/chat")
    def post_chat(body: ChatIn) -> dict[str, Any]:
        try:
            return chat.ask(body.operator, body.message, body.incident)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/chat/clear")
    def clear_chat() -> dict[str, Any]:
        return chat.clear()

    # Process scan: read-only, suggests log files; an operator approves each one by id.
    @app.post("/system/scan")
    def post_scan(body: Optional[ScanIn] = None) -> dict[str, Any]:
        return discovery.scan((body.operator if body else None) or "operator")

    @app.get("/system/scan")
    def get_scan() -> dict[str, Any]:
        return discovery.latest() or {"suggestions": [], "processes": [], "scanned_at": None}

    @app.get("/log-sources")
    def get_log_sources() -> list[dict[str, Any]]:
        return discovery.sources()

    @app.post("/log-sources")
    def post_log_source(body: LogSourceIn) -> dict[str, Any]:
        try:
            return discovery.approve(body.file_id, body.operator, body.layer)
        except KeyError as e:
            raise HTTPException(404, str(e).strip("'\""))
        except ValueError as e:
            raise HTTPException(409, str(e))

    @app.get("/ai")
    def ai_status() -> dict[str, Any]:
        return ai.status(core, chat)

    @app.post("/ai/reload")
    def ai_reload() -> dict[str, Any]:
        return ai.reload(core, chat)

    @app.post("/ai/test")
    def ai_test(body: Optional[AITestIn] = None) -> dict[str, Any]:
        return ai.test(core, chat, body.model_dump() if body else None)

    @app.post("/heartbeat")
    def post_heartbeat(body: HeartbeatIn) -> dict[str, Any]:
        core.ingest([{"source": "heartbeat", "host": body.collector, "layer": "os", "raw": "heartbeat"}])
        return {"ok": True}

    @app.post("/demo/reset")
    def demo_reset() -> dict[str, Any]:
        chat.clear()
        return core.reset()

    @app.post("/demo/advance")
    def demo_advance(body: AdvanceIn) -> dict[str, Any]:
        return core.advance(body.demo_hours)

    return app


app = create_app()
