"""The web dashboard's Security Coach page and the endpoints connectors and the CLI use (coach.py has the logic).

Reading is open to every signed-in role; changing settings, people or data needs `configure` (Owner or Admin).
Settings changes, erasures, sample data and urgent moments go on the audit record. The audit entries name the
kind of action and the count, never file names.
"""
from __future__ import annotations

from typing import Any, Callable

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse

from .config import sentrai_config  # noqa: F401  (config.py puts mvp/ on sys.path)
from . import coach as cm
import sentrai_accounts as acc  # noqa: E402


def _who(request: Request, body: dict[str, Any] | None = None) -> str:
    account = getattr(request.state, "account", None)
    return (account or {}).get("email") or str((body or {}).get("operator") or "dashboard")


def _need(request: Request, what: str) -> None:
    account = getattr(request.state, "account", None)
    if account and not acc.can(account.get("role"), "configure"):
        raise HTTPException(403, f"Only an Owner or Admin can {what}.")


def install(app: FastAPI, core: Any, coach: cm.Coach, org: Callable[[], tuple[str, str]],
            after_erase: Callable[[str], dict[str, int]] | None = None) -> None:
    def fail(e: Exception) -> HTTPException:
        return HTTPException(400, str(e))

    def ingest(events: list[dict[str, Any]], who: str, sample: bool = False) -> dict[str, Any]:
        try:
            out = coach.ingest(events, sample=sample)
        except cm.CoachError as e:
            raise HTTPException(409 if "not switched on" in str(e) else 400, str(e)) from e
        for u in out["urgent"]:
            core.scribe.record(core.name, "coach_urgent", {"moment": u["id"], "kind": u["kind"], "by": who})
        return out

    @app.get("/ui/coach")
    def get_coach() -> dict[str, Any]:
        return coach.overview()

    @app.post("/ui/coach/settings")
    def post_settings(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        _need(request, "change the coach's settings")
        who = _who(request, body)
        try:
            s = coach.save_settings(body, who)
        except cm.CoachError as e:
            raise fail(e) from e
        core.scribe.record(core.name, "coach_settings_changed", {
            "operator": who, "apps_on": s["apps_on"], "kinds_on": len(s["kinds_on"]), "regions": s["regions"],
            "show_names": s["show_names"], "file_names": s["file_names"], "notice_shared": s["notice_shared"]})
        return coach.overview()

    @app.get("/ui/coach/lessons")
    def get_lessons() -> dict[str, Any]:
        return {"lessons": coach.lessons()}

    @app.post("/ui/coach/people")
    def post_person(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        _need(request, "add or change people in the coach")
        try:
            return {"person": coach.upsert_person(body)}
        except cm.CoachError as e:
            raise fail(e) from e

    @app.get("/ui/coach/people/{email}/data")
    def get_my_data(email: str) -> dict[str, Any]:
        try:
            return coach.my_data(email)
        except cm.CoachError as e:
            raise HTTPException(404, str(e)) from e

    @app.post("/ui/coach/people/{email}/erase")
    def post_erase(email: str, request: Request) -> dict[str, Any]:
        _need(request, "erase a person's coaching data")
        try:
            gone = coach.erase_person(email)
        except cm.CoachError as e:
            raise fail(e) from e
        if after_erase:  # the phone app's password, sign-ins and phone checks go too
            gone = {**gone, **{f"app_{k}": v for k, v in after_erase(email).items()}}
        core.scribe.record(core.name, "coach_person_erased", {"operator": _who(request), **gone})
        return {"erased": gone}

    @app.post("/ui/coach/events")
    def post_events(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        _need(request, "send activity to the coach")
        return ingest(body.get("events"), _who(request, body))

    @app.post("/ui/coach/moments/{moment_id}")
    def post_moment(moment_id: str, request: Request, body: dict = Body(...)) -> dict[str, Any]:
        _need(request, "answer for a person")
        try:
            m = coach.respond(moment_id, str(body.get("answer") or ""), _who(request, body))
        except cm.CoachError as e:
            raise fail(e) from e
        if m["status"] == "needs help":
            core.scribe.record(core.name, "coach_urgent", {"moment": m["id"], "kind": m["kind"],
                                                           "by": "person said it wasn't them"})
        return {"moment": m}

    @app.post("/ui/coach/lessons/{lesson_id}/answer")
    def post_answer(lesson_id: str, request: Request, body: dict = Body(...)) -> dict[str, Any]:
        _need(request, "answer for a person")
        try:
            return coach.answer_lesson(str(body.get("person") or ""), lesson_id, body.get("answers"))
        except cm.CoachError as e:
            raise fail(e) from e

    @app.post("/ui/coach/sample")
    def post_sample(request: Request, body: dict = Body(default={})) -> dict[str, Any]:
        """Add three made-up people and a day of made-up activity, or clear them ({"clear": true})."""
        _need(request, "add sample data")
        who = _who(request, body)
        if body.get("clear"):
            gone = coach.clear_sample()
            core.scribe.record(core.name, "coach_sample", {"operator": who, "cleared": gone})
            return {"cleared": gone, **coach.overview()}
        for p in cm.SAMPLE_PEOPLE:
            coach.upsert_person({**p, "notice_confirmed": True, "sample": True})
        out = ingest([{**e, "sample": True} for e in cm.sample_events(core.clock.now())], who, sample=True)
        core.scribe.record(core.name, "coach_sample", {"operator": who, "moments": out["moments"]})
        return {"added": out, **coach.overview()}

    @app.get("/ui/coach/notice.md", response_class=PlainTextResponse)
    def get_notice() -> PlainTextResponse:
        name, contact = org()
        return PlainTextResponse(cm.notice(coach.overview(), name, contact),
                                 media_type="text/markdown; charset=utf-8",
                                 headers={"Content-Disposition": 'attachment; filename="sentrai-coach-notice.md"'})
