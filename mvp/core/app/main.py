"""SentrAI core API (FastAPI, http://127.0.0.1:8000). Endpoints follow mvp/CONTRACT.md."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import logging
import os
from pathlib import Path
from typing import Any, Optional, Union

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from .config import Settings, sign
import sentrai_paths
from .reports import build_report, render_markdown, render_pdf
from . import summary as client_summary
from . import ai, anchor, fleet, integrations, jobs, webhook
from .chat import OperatorChat, default_chat_provider
from .discovery import Discovery
from .staff_reports import RateLimited, ReportError, StaffReports
from .threats import ThreatWatch
from .backups import BackupWatch
from .cyanide import Cyanide, default_planner
from .saguaro import BadRequestError, ConflictError, Saguaro

log = logging.getLogger("sentrai.core")


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


class AssignIn(BaseModel):
    operator: str
    assignee: str
    note: Optional[str] = None


class RoutingIn(BaseModel):
    operator: str
    routing: dict[str, Any]


class ResolveIn(BaseModel):
    operator: str
    note: str


class DeliveredIn(BaseModel):
    channel: str
    message_id: Optional[Union[str, int]] = None
    to: Optional[str] = None  # the person a private message reached (direct Telegram message)


class LinkCodeIn(BaseModel):
    operator: str
    contact: str


class TelegramLinkIn(BaseModel):
    code: str
    chat_id: Union[str, int]
    username: Optional[str] = ""


class TelegramUnlinkIn(BaseModel):
    operator: str
    contact: Optional[str] = None
    chat_id: Optional[Union[str, int]] = None


class ProtectionIn(BaseModel):
    operator: str
    on: bool
    reason: Optional[str] = None


class SummaryScheduleIn(BaseModel):
    operator: str
    every: Optional[str] = None  # daily | weekly | off
    at: Optional[str] = None     # local time, HH:MM
    day: Optional[str] = None    # weekday for weekly: mon..sun
    to: Optional[str] = None     # who the summary is addressed to


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


class ThreatScanIn(BaseModel):
    operator: str = "operator"
    paths: Optional[list[str]] = None


class QuarantineIn(BaseModel):
    operator: str
    reason: str = ""


class BackupIn(BaseModel):
    operator: str = "operator"


class RestoreIn(BaseModel):
    operator: str
    in_place: bool = False
    confirm: str = ""      # the backup id, typed again, for an in-place restore
    target: Optional[str] = None


class PendingDecisionIn(BaseModel):
    operator: str
    approve: bool
    layer: Optional[str] = None
    reason: str = ""


class SetupOption(BaseModel):
    value: str
    label: str = ""


class SetupInterpretIn(BaseModel):
    question: str
    options: list[SetupOption]
    answer: str


class AITestIn(BaseModel):
    provider: str
    api_key: str = ""
    base_url: str = ""
    model: str = ""


class StaffReportIn(BaseModel):
    text: str
    reporter: str = ""
    contact: str = ""
    where: str = ""
    channel: str = "api"
    sender: str = ""  # who sent it, for the rate limit: the reporter's address or chat id, set by the channel
    host: str = ""  # the machine it is about, if known: its incident then belongs to that machine


class StaffReportUpdateIn(BaseModel):
    operator: str
    status: Optional[str] = None
    assignee: Optional[str] = None
    note: Optional[str] = None


class HeartbeatIn(BaseModel):
    collector: str


class JoinCodeIn(BaseModel):
    operator: str = "operator"
    name: Optional[str] = None  # fix the machine's name instead of letting the agent pick it


class EnrolIn(BaseModel):
    code: str
    host: str


class RevokeIn(BaseModel):
    operator: str = "operator"


class ServiceIn(BaseModel):
    name: str = Field(max_length=64)
    port: Optional[int] = Field(None, ge=0, le=65535)
    proto: Optional[str] = Field(None, max_length=8)
    process: Optional[str] = Field(None, max_length=64)


class ServicesIn(BaseModel):
    services: list[ServiceIn] = Field(default_factory=list, max_length=200)


class JobIn(BaseModel):
    host: str = Field(max_length=63)
    kind: str = Field(max_length=32)
    operator: str = Field("operator", max_length=64)


class JobResultIn(BaseModel):
    id: str = Field(max_length=32)
    ok: bool
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = Field(None, max_length=2000)


class OfflineActionIn(BaseModel):
    ip: str = Field(max_length=64)
    category: str = Field(max_length=40)
    reason: str = Field("", max_length=300)
    score: float = 0.0
    at: Optional[str] = Field(None, max_length=40)
    until: Optional[str] = Field(None, max_length=40)
    applied: bool = False
    event_ids: list[str] = Field(default_factory=list, max_length=50)


class OfflineReportIn(BaseModel):
    """What an agent did on its own while the panel was out of reach (lab/agent/offline.py)."""
    from_: Optional[str] = Field(None, alias="from", max_length=40)
    to: Optional[str] = Field(None, max_length=40)
    scored: int = Field(0, ge=0)
    actions: list[OfflineActionIn] = Field(default_factory=list, max_length=500)


# What a machine's own agent key may do (fleet.py): send its events and heartbeat, read its block list.
# It also picks up the jobs the panel queued for its own machine and reports how they went (jobs.py).
AGENT_ROUTES = frozenset({("POST", "/events"), ("POST", "/heartbeat"), ("GET", "/blocklist"), ("GET", "/fleet/me"),
                           ("POST", "/fleet/services"), ("GET", "/fleet/jobs/next"), ("POST", "/fleet/jobs/result"),
                           ("POST", "/fleet/offline-report")})


# Open without a token: the launchers' readiness check, and the list the fake portal enforces
# (it holds no personal data). A report opens with the signed link from its alert (?sig=). Every other endpoint needs "Authorization: Bearer <token>" or
# the X-SentrAI-Token header; the token is SENTRAI_API_TOKEN from the setup wizard.
OPEN_PATHS = frozenset({"/health", "/blocklist", "/docs", "/openapi.json", "/fleet/enrol"})
TOKEN_HEADER = "x-sentrai-token"
OLD_TOKEN_HEADER = "x-cactai-token"  # sent by scripts written before the CactAI -> SentrAI rename


def create_app(settings: Settings | None = None) -> FastAPI:
    # Cyanide (Claude-planned) is the default orchestrator; SENTRAI_ENGINE=saguaro keeps the fixed playbooks.
    if os.getenv("SENTRAI_ENGINE", "cyanide").lower() == "saguaro":
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

    async def threat_scanner() -> None:
        """Repeat the threat scan every threat_scan.every_minutes (off when no folders are set)."""
        while True:
            every = threats.every_s()
            await asyncio.sleep(every or 300)
            if every:
                try:
                    await asyncio.to_thread(threats.scan, "schedule")
                except Exception:
                    log.exception("threat scan failed")

    async def backup_scheduler() -> None:
        """Take a backup whenever backup.every_hours have passed since the last one (checked each minute)."""
        while True:
            await asyncio.sleep(60)
            try:
                if backups.due():
                    await asyncio.to_thread(backups.make, "schedule", "schedule")
            except Exception:
                log.exception("scheduled backup failed")

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI):
        task = asyncio.create_task(ticker()) if core.settings.background else None
        scanner = asyncio.create_task(threat_scanner()) if core.settings.background else None
        backer = asyncio.create_task(backup_scheduler()) if core.settings.background else None
        if core.remote is not None and core.settings.background:
            core.remote.start()
        yield
        for t in (task, scanner, backer):
            if t:
                t.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await t
        if core.remote is not None:
            core.remote.stop()
        core.audit.close()

    # Operator chat: read-only tools plus suggestion buttons; answers from the core's own
    # explanations when no AI key is set (or when the fixed-playbook engine runs).
    threats = ThreatWatch(core)
    backups = BackupWatch(core)
    discovery = Discovery(core, threats)
    chat = OperatorChat(core, default_chat_provider() if isinstance(core, Cyanide) else None, discovery, threats,
                        backups)
    chat.off_reason = core.ai_off_reason = ai.why_off()
    core_dir = Path(core.settings.db_path).parent  # machines/fleet.json and machines/jobs.json sit next to the database
    machines = fleet.Fleet(sentrai_paths.path("core.fleet", core_dir))
    machine_jobs = jobs.Jobs(sentrai_paths.path("core.jobs", core_dir))
    staff = StaffReports(core, lambda: chat.provider)  # follows /ai/reload

    def require_token(request: Request) -> None:
        path = request.url.path
        request.state.agent = None
        auth = request.headers.get("authorization", "")
        header = request.headers.get(TOKEN_HEADER) or request.headers.get(OLD_TOKEN_HEADER, "")
        sent = auth[7:].strip() if auth[:7].lower() == "bearer " else header
        # One machine's block list (?host=) is only for that machine's agent or the operator,
        # and an agent asking for the open list still gets only its own.
        if path in OPEN_PATHS and not (path == "/blocklist" and ("host" in request.query_params
                                                                 or sent.startswith(fleet.KEY_PREFIX))):
            return
        sig = request.query_params.get("sig", "")
        if sig and request.method == "GET" and path.startswith("/reports/") and path.endswith(".md") \
                and hmac.compare_digest(sig, sign(core.settings.api_token, path)):
            return  # the signed report link from an alert
        if sig and request.method == "GET" and path.startswith("/summary/") and path.endswith((".md", ".pdf")) \
                and hmac.compare_digest(sig, sign(core.settings.api_token,
                                                  f"{path}?until={request.query_params.get('until', '')}")):
            return  # the signed one-page summary link sent to the client
        if sent.startswith(fleet.KEY_PREFIX):
            agent = machines.check(sent)
            if agent is None:
                raise HTTPException(status_code=401, detail="unknown or revoked machine key: join the panel again",
                                    headers={"WWW-Authenticate": "Bearer"})
            if (request.method, path) not in AGENT_ROUTES or \
                    request.query_params.get("host", agent["host"]) != agent["host"]:
                raise HTTPException(status_code=403, detail="a machine key only sends its own events and reads "
                                                            "its own block list")
            machines.seen(agent)
            request.state.agent = agent
            return
        if not (sent and hmac.compare_digest(sent.encode(), core.settings.api_token.encode())):
            raise HTTPException(status_code=401, detail="missing or wrong API token "
                                "(python sentrai_config.py token shows it)",
                                headers={"WWW-Authenticate": "Bearer"})

    app = FastAPI(title="SentrAI core", version="0.1.0", lifespan=lifespan, dependencies=[Depends(require_token)])
    # The signed report link opens in a browser: no framing, no type sniffing, and the ?sig= stays
    # out of the Referer of anything the page links to.
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    app.state.core = core
    app.state.chat = chat
    app.state.discovery = discovery
    app.state.threats = threats
    app.state.backups = backups
    app.state.fleet = machines
    app.state.jobs = machine_jobs
    app.state.staff = staff

    def not_found(iid: str) -> HTTPException:
        return HTTPException(status_code=404, detail=f"incident {iid} not found")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True}

    @app.post("/events")
    def post_events(request: Request, payload: Union[list[EventIn], EventIn] = Body(...)) -> dict[str, Any]:
        items = [e.model_dump() for e in (payload if isinstance(payload, list) else [payload])]
        if request.state.agent is not None:
            for e in items:  # an agent speaks for its own machine only, whatever its logs say
                e["host"] = request.state.agent["host"]
        return core.ingest(items)

    webhook_maps = webhook.load_maps()

    @app.post("/webhook/{name}")
    def post_webhook(name: str, payload: Any = Body(...), layer: Optional[str] = Query(None),
                     host: Optional[str] = Query(None)) -> dict[str, Any]:
        """Any JSON from another tool, mapped onto the /events contract (webhook.py). Same token as /events."""
        try:
            events = webhook.to_events(payload, name, webhook_maps, layer, host)
        except webhook.WebhookError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {**core.ingest(events), "events": [e["event_id"] for e in events]}

    @app.get("/risk")
    def get_risk(history: int = Query(600, ge=0, le=3600), host: Optional[str] = Query(None)) -> dict[str, Any]:
        """The headline index, or one machine's own with ?host= (see SENTRAI_RISK_SCOPE)."""
        return core.risk(history=history, host=host)

    @app.get("/machines")
    def get_machines() -> list[dict[str, Any]]:
        return core.machines()

    @app.get("/incidents")
    def get_incidents(host: Optional[str] = Query(None)) -> list[dict[str, Any]]:
        return core.list_incidents(host=host)

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

    @app.post("/incidents/{iid}/assign")
    def post_assign(iid: str, body: AssignIn) -> dict[str, Any]:
        return _verb(core.assign, iid, body.assignee, body.operator, body.note)

    @app.post("/incidents/{iid}/resolve")
    def post_resolve(iid: str, body: ResolveIn) -> dict[str, Any]:
        return _verb(core.resolve, iid, body.operator, body.note)

    @app.get("/routing")
    def get_routing() -> dict[str, Any]:
        return core.routing_public()

    @app.post("/routing")
    def post_routing(body: RoutingIn) -> dict[str, Any]:
        """Save a whole new routing file (people, rules, follow-up) from the dashboard's map."""
        try:
            return core.routing_update(body.routing, body.operator)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except OSError as exc:
            raise HTTPException(status_code=503, detail=f"could not write the routing file: {exc}")

    # Personal Telegram alerts (telegram_links.py): a contact links their private chat with a one-time code.
    @app.post("/telegram/link-codes")
    def post_link_code(body: LinkCodeIn) -> dict[str, Any]:
        try:
            return core.telegram_link_code(body.contact, body.operator)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"no contact called {body.contact!r} in the routing file")

    @app.post("/telegram/link")
    def post_telegram_link(body: TelegramLinkIn) -> dict[str, Any]:
        try:
            return core.telegram_link(body.code, str(body.chat_id), body.username or "")
        except BadRequestError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except KeyError:
            raise HTTPException(status_code=404, detail="that contact is no longer in the routing file")

    @app.post("/telegram/unlink")
    def post_telegram_unlink(body: TelegramUnlinkIn) -> dict[str, Any]:
        try:
            return core.telegram_unlink(body.contact, None if body.chat_id is None else str(body.chat_id),
                                        body.operator)
        except KeyError:
            raise HTTPException(status_code=404, detail="no linked Telegram chat for that contact")

    @app.get("/telegram/links")
    def get_telegram_links() -> list[dict[str, Any]]:
        return core.telegram_links_public()

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

    @app.get("/audit/verify")
    def get_audit_verify(fingerprint: str = Query(..., description="a SENTRAI-FP line from an alert")) -> dict[str, Any]:
        ok, why = anchor.verify(core.audit, fingerprint, core.anchor_key)
        return {"ok": ok, "reason": why}

    @app.get("/audit/fingerprint")
    def get_audit_fingerprint() -> dict[str, Any]:
        fp = anchor.fingerprint(core.audit, core.anchor_key)
        return {"seq": fp.seq, "head": fp.head, "at": fp.at, "line": fp.line()}

    @app.get("/audit/remote-copy")
    def get_remote_copy() -> dict[str, Any]:
        """Whether the off-box copy is on, and how far it has got (remote_copy.py)."""
        if core.remote is None:
            return {"enabled": False}
        return {"enabled": True, **core.remote.status}

    # The .md and .pdf routes must be registered before the JSON route.
    @app.get("/reports/{iid}.pdf")
    def get_report_pdf(iid: str) -> Response:
        try:
            return Response(render_pdf(build_report(core, iid)), media_type="application/pdf",
                            headers={"Content-Disposition": f'attachment; filename="{iid}-evidence-report.pdf"'})
        except KeyError:
            raise not_found(iid)

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

    # One-page client summary (summary.py). The schedule routes come before /summary/{period}.
    @app.get("/summary/schedule")
    def get_summary_schedule() -> dict[str, Any]:
        return core.summary_settings()

    @app.post("/summary/schedule")
    def post_summary_schedule(body: SummaryScheduleIn) -> dict[str, Any]:
        try:
            return core.set_summary_settings(body.operator, body.every, body.at, body.day, body.to)
        except BadRequestError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/summary/send")
    def post_summary_send(body: OperatorIn) -> dict[str, Any]:
        """Send the summary to the client now (for the client's chosen period), outside the schedule."""
        return core.send_summary_now(body.operator)

    def _summary(period: str, until: Optional[int]) -> dict[str, Any]:
        try:
            return client_summary.build_summary(core, period, float(until) if until else None)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    @app.get("/summary/{period}.pdf")
    def get_summary_pdf(period: str, until: Optional[int] = None) -> Response:
        r = _summary(period, until)
        return Response(client_summary.render_pdf(r), media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{r["summary_id"]}.pdf"'})

    @app.get("/summary/{period}.md", response_class=PlainTextResponse)
    def get_summary_md(period: str, until: Optional[int] = None) -> PlainTextResponse:
        return PlainTextResponse(client_summary.render_markdown(_summary(period, until)),
                                 media_type="text/markdown; charset=utf-8")

    @app.get("/summary/{period}")
    def get_summary(period: str, until: Optional[int] = None) -> dict[str, Any]:
        return _summary(period, until)

    @app.get("/protection")
    def get_protection() -> dict[str, Any]:
        return core.protection()

    @app.get("/limits")
    def get_limits() -> dict[str, Any]:
        """Business limits on protective actions: what may run on its own, for how long, how often."""
        with core.lock:
            return core.limits()

    @app.post("/protection")
    def post_protection(body: ProtectionIn) -> dict[str, Any]:
        try:
            return core.set_protection(body.on, body.operator, body.reason)
        except BadRequestError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/blocklist")
    def get_blocklist(request: Request, host: Optional[str] = Query(None)) -> dict[str, list[str]]:
        """With ?host= in host scope, only the blocks that machine must put in place (an agent always gets its own)."""
        if request.state.agent is not None:
            host = request.state.agent["host"]
        return core.blocklist(host)

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
            return core.mark_delivered(nid, body.channel, mid, body.to)
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

    @app.post("/chat/setup/interpret")
    def post_setup_interpret(body: SetupInterpretIn) -> dict[str, Any]:
        return chat.interpret_setup(body.question, [o.model_dump() for o in body.options], body.answer)

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

    # Threat scan: read-only look inside chosen folders for web shells, miners, reverse shells and the
    # like. New critical/high findings open a "malware" incident; files are quarantined only by id.
    @app.post("/threats/scan")
    def post_threat_scan(body: Optional[ThreatScanIn] = None) -> dict[str, Any]:
        return threats.scan((body.operator if body else None) or "operator", body.paths if body else None)

    @app.get("/threats")
    def get_threats() -> dict[str, Any]:
        return threats.latest() or {"findings": [], "scanned_at": None,
                                    "every_minutes": round(threats.every_s() / 60) or None}

    @app.post("/threats/{finding_id}/quarantine")
    def quarantine_threat(finding_id: str, body: QuarantineIn) -> dict[str, Any]:
        try:
            return threats.quarantine(finding_id, body.operator, body.reason)
        except KeyError as e:
            raise HTTPException(404, str(e).strip("'\""))
        except ValueError as e:
            raise HTTPException(409, str(e))

    @app.get("/quarantine")
    def get_quarantine() -> list[dict[str, Any]]:
        return threats.quarantined()

    @app.post("/quarantine/{qid}/restore")
    def restore_quarantined(qid: str, body: OperatorIn) -> dict[str, Any]:
        try:
            return threats.restore(qid, body.operator)
        except KeyError as e:
            raise HTTPException(404, str(e).strip("'\""))
        except ValueError as e:
            raise HTTPException(409, str(e))

    # Backups: chosen folders plus SentrAI's own data, on a schedule. Restoring always needs a person;
    # by default it unpacks into a new folder and changes nothing live.
    @app.get("/backups")
    def get_backups() -> dict[str, Any]:
        return backups.status()

    @app.post("/backups")
    def post_backup(body: Optional[BackupIn] = None) -> dict[str, Any]:
        return backups.make((body.operator if body else None) or "operator", "manual")

    @app.post("/backups/{bid}/verify")
    def verify_backup(bid: str, body: Optional[BackupIn] = None) -> dict[str, Any]:
        try:
            return backups.verify(bid, (body.operator if body else None) or "operator")
        except KeyError as e:
            raise HTTPException(404, str(e).strip("'\""))

    @app.post("/backups/{bid}/restore")
    def restore_backup(bid: str, body: RestoreIn) -> dict[str, Any]:
        try:
            return backups.restore(bid, body.operator, body.in_place, body.confirm, body.target)
        except KeyError as e:
            raise HTTPException(404, str(e).strip("'\""))
        except ValueError as e:
            raise HTTPException(409, str(e))

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

    # Scout proposals (python -m scout find) wait here until an operator approves or rejects them.
    @app.get("/log-sources/pending")
    def get_pending_sources() -> list[dict[str, Any]]:
        return discovery.pending()

    @app.post("/log-sources/pending/{pid}")
    def decide_pending_source(pid: str, body: PendingDecisionIn) -> dict[str, Any]:
        try:
            return discovery.decide_pending(pid, body.operator, body.approve, body.layer, body.reason)
        except KeyError as e:
            raise HTTPException(404, str(e).strip("'\""))
        except ValueError as e:
            raise HTTPException(409, str(e))

    # Staff reports: anyone at the business reports something suspicious (from the dashboard's open
    # report page, Telegram or another channel holding the token); it is sorted, opens a "needs review"
    # incident, and is tracked until a person closes it with a note (staff_reports.py).
    @app.post("/staff-reports")
    def post_staff_report(body: StaffReportIn) -> dict[str, Any]:
        try:
            return staff.submit(body.text, body.reporter, body.contact, body.where, body.channel, body.sender,
                                body.host)
        except RateLimited as e:
            raise HTTPException(429, str(e))
        except ReportError as e:
            raise HTTPException(400, str(e))

    @app.get("/staff-reports")
    def get_staff_reports(status: Optional[str] = Query(None, description="new, reviewing, resolved, "
                                                        "not_a_threat, or open (new + reviewing)")) -> dict[str, Any]:
        return {"reports": staff.list(status), "counts": staff.counts()}

    @app.get("/staff-reports/{rid}")
    def get_staff_report(rid: str) -> dict[str, Any]:
        try:
            return staff.get(rid)
        except KeyError as e:
            raise HTTPException(404, str(e).strip("'\""))

    @app.post("/staff-reports/{rid}")
    def update_staff_report(rid: str, body: StaffReportUpdateIn) -> dict[str, Any]:
        try:
            return staff.update(rid, body.operator, body.status, body.assignee, body.note)
        except KeyError as e:
            raise HTTPException(404, str(e).strip("'\""))
        except ReportError as e:
            raise HTTPException(400, str(e))

    @app.get("/ai")
    def ai_status() -> dict[str, Any]:
        return ai.status(core, chat)

    @app.post("/ai/reload")
    def ai_reload() -> dict[str, Any]:
        return ai.reload(core, chat)

    @app.post("/ai/test")
    def ai_test(body: Optional[AITestIn] = None) -> dict[str, Any]:
        return ai.test(core, chat, body.model_dump() if body else None)

    @app.get("/integrations")
    def get_integrations() -> list[dict[str, Any]]:
        return integrations.status(core)

    @app.post("/integrations/{name}/test")
    def test_integration(name: str) -> dict[str, Any]:
        try:
            return integrations.test(core, name)
        except KeyError as e:
            raise HTTPException(404, str(e).strip("'\""))

    @app.post("/heartbeat")
    def post_heartbeat(request: Request, body: HeartbeatIn) -> dict[str, Any]:
        host = request.state.agent["host"] if request.state.agent is not None else body.collector
        core.ingest([{"source": "heartbeat", "host": host, "layer": "os", "raw": "heartbeat"}])
        return {"ok": True}

    # -- machines joining a central panel (fleet.py)
    def fleet_error(exc: fleet.FleetError) -> HTTPException:
        return HTTPException(status_code=exc.status, detail=str(exc))

    @app.post("/fleet/join-codes")
    def post_join_code(body: JoinCodeIn) -> dict[str, Any]:
        try:
            out = machines.join_code(body.operator, body.name)
        except fleet.FleetError as exc:
            raise fleet_error(exc)
        core.scribe.record(core.name, "join_code_created", {"operator": body.operator, "name": out["name"],
                                                            "expires_at": out["expires_at"]})
        return {**out, **fleet.panel_info()}

    @app.get("/fleet/panel")
    def get_fleet_panel() -> dict[str, Any]:
        """The address and certificate pin new machines use (SENTRAI_PANEL_URL, SENTRAI_PANEL_CERT)."""
        return fleet.panel_info()

    @app.post("/fleet/enrol")
    def post_enrol(body: EnrolIn) -> dict[str, Any]:
        try:
            out = machines.enrol(body.code, body.host)
        except fleet.FleetError as exc:
            raise fleet_error(exc)
        core.scribe.record(core.name, "machine_joined", {"agent_id": out["agent_id"], "host": out["host"]})
        return {**out, "risk_scope": core.settings.risk_scope}

    @app.get("/fleet/agents")
    def get_fleet_agents() -> list[dict[str, Any]]:
        return machines.agents()

    @app.post("/fleet/agents/{agent_id}/revoke")
    def post_revoke(agent_id: str, body: RevokeIn) -> dict[str, Any]:
        try:
            out = machines.revoke(agent_id, body.operator)
        except fleet.FleetError as exc:
            raise fleet_error(exc)
        core.scribe.record(core.name, "machine_revoked", {"agent_id": agent_id, "host": out["host"],
                                                          "operator": body.operator})
        machine_jobs.drop_host(out["host"], body.operator)
        return out

    @app.post("/fleet/services")
    def post_services(request: Request, body: ServicesIn, host: Optional[str] = Query(None)) -> dict[str, Any]:
        """What runs on a machine: its agent reports for itself; the operator token may name a host."""
        if request.state.agent is not None:
            host = request.state.agent["host"]
        if not host:
            raise HTTPException(status_code=400, detail="which machine? (?host=)")
        return core.set_services(host, [x.model_dump() for x in body.services])

    # -- jobs the panel asks one machine to run (jobs.py): its agent picks them up on its next call out
    def job_error(exc: jobs.JobError) -> HTTPException:
        return HTTPException(status_code=exc.status, detail=str(exc))

    def job_view(j: dict[str, Any]) -> dict[str, Any]:
        return {**{k: v for k, v in j.items() if not k.endswith("_ts")}, "summary": jobs.summary(j)}

    @app.post("/fleet/jobs")
    def post_job(body: JobIn) -> dict[str, Any]:
        if not any(a["host"] == body.host and not a.get("revoked_at") for a in machines.agents()):
            raise HTTPException(status_code=404, detail=f"no joined machine named {body.host!r}")
        try:
            job = machine_jobs.queue(body.host, body.kind, body.operator)
        except jobs.JobError as exc:
            raise job_error(exc)
        core.scribe.record(core.name, "machine_job_queued", {
            "job": job["id"], "host": body.host, "kind": body.kind, "operator": body.operator,
            "summary": f"{body.operator} asked {body.host} to run a {jobs.KINDS[body.kind].lower()}"})
        return job_view(job)

    @app.get("/fleet/jobs")
    def get_jobs(host: Optional[str] = Query(None, max_length=63)) -> list[dict[str, Any]]:
        return [job_view(j) for j in machine_jobs.list(host)]

    @app.post("/fleet/jobs/{job_id}/cancel")
    def cancel_job(job_id: str, body: OperatorIn) -> dict[str, Any]:
        try:
            return job_view(machine_jobs.cancel(job_id, body.operator))
        except jobs.JobError as exc:
            raise job_error(exc)

    @app.get("/fleet/jobs/next")
    def get_next_job(request: Request) -> dict[str, Any]:
        a = request.state.agent
        if a is None:
            raise HTTPException(status_code=400, detail="only a machine's agent key picks up jobs")
        return {"job": machine_jobs.next_for(a["host"])}

    @app.post("/fleet/jobs/result")
    def post_job_result(request: Request, body: JobResultIn) -> dict[str, Any]:
        a = request.state.agent
        if a is None:
            raise HTTPException(status_code=400, detail="only a machine's agent key reports a job")
        host = a["host"]
        kind = next((j["kind"] for j in machine_jobs.list(host) if j["id"] == body.id), None)
        result = None
        if body.ok and body.result is not None:
            result = jobs.clean_scan(body.result) if kind == "threat_scan" else jobs.clean_backup(body.result)
        try:
            job = machine_jobs.finish(host, body.id, body.ok, result, body.error)
        except jobs.JobError as exc:
            raise job_error(exc)
        new_alerts = 0
        if job["status"] == "done" and kind == "threat_scan":
            new_alerts = threats.raise_remote(host, (job["result"] or {}).get("findings") or [])
            job["result"]["new_alerts"] = new_alerts
        line = jobs.summary(job)
        core.scribe.record(core.name, "machine_job_done" if job["status"] == "done" else "machine_job_failed", {
            "job": job["id"], "host": host, "kind": kind, "by": job["requested_by"], "new_alerts": new_alerts,
            **({"sha256": job["result"].get("sha256"), "backup": job["result"].get("id")}
               if kind == "backup" and job["result"] else {}),
            "summary": f"{jobs.KINDS.get(kind, kind)} on {host}: {line}"})
        if job["status"] != "done" and kind == "backup":
            with core.lock:
                core._notify(core.clock.now(), "backup_failed", None, [core.settings.on_duty],
                             f"Backup on {host} failed", f"The backup {job['requested_by']} asked {host} to take "
                             f"failed: {line[:300]}. Until one works, {host} has no fresh copy to restore from.", [])
        return {"ok": True, "status": job["status"], "new_alerts": new_alerts}

    @app.post("/fleet/offline-report")
    def post_offline_report(request: Request, body: OfflineReportIn) -> dict[str, Any]:
        """An agent is back: what it scored and blocked on its own while the panel could not be reached.
        Its buffered logs arrive through /events as usual and are scored here; this is the record of
        the local decisions, which already expire on the machine by themselves."""
        a = request.state.agent
        if a is None:
            raise HTTPException(status_code=400, detail="only a machine's agent sends an offline report")
        report = body.model_dump(by_alias=True)
        summary = machines.offline_report(a, report)
        host = a["host"]
        for act in report["actions"]:
            core.scribe.record(core.name, "agent_local_block", {"host": host, **act})
        core.scribe.record(core.name, "agent_offline_report", {"host": host, **summary, "summary": (
            f"{host} worked alone from {summary['from'] or '?'} to {summary['to'] or '?'}: scored {summary['scored']} "
            f"events, made {summary['local_blocks']} local blocks")})
        if report["actions"]:
            ips = ", ".join(sorted({x["ip"] for x in report["actions"]})[:10])
            with core.lock:
                core._notify(core.clock.now(), "agent_offline_actions", None, [core.settings.on_duty],
                             f"{host} blocked {summary['local_blocks']} address(es) while the panel was unreachable",
                             f"While {host} could not reach the panel ({summary['from'] or '?'} to "
                             f"{summary['to'] or '?'}), its local rules blocked: {ips}. Each block expires on its own; "
                             f"the logs from that time are being scored here now.", [])
        return {"ok": True, **summary}

    @app.get("/fleet/me")
    def get_fleet_me(request: Request) -> dict[str, Any]:
        a = request.state.agent
        if a is None:
            raise HTTPException(status_code=400, detail="only a machine's agent key has a /fleet/me")
        return {"agent_id": a["agent_id"], "host": a["host"], "risk_scope": core.settings.risk_scope}

    return app


app = create_app()
