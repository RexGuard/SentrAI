"""The web dashboard's guided setup: Cyanide asks the setup questions (mvp/setup_chat.py) one at a time.

Same script and same save as the Streamlit console's Chat page. A conversation lives in this process's memory
for the signed-in person, never in the core's chat history, because some answers are secrets (they are shown as
dots) and nothing is written to the settings file until the person confirms the summary.
"""
from __future__ import annotations

from typing import Any, Callable

from fastapi import Body, FastAPI, HTTPException, Request

import sentrai_accounts as acc  # noqa: E402
import setup_chat  # noqa: E402
from .config import sentrai_config as cfg

LOCKED = "Auditors can't change the settings. Ask an Owner or Admin to save this setup."
MOST = 50  # conversations kept at once; a person who walks away leaves one behind


def view(sc: "setup_chat.SetupChat | None") -> dict[str, Any]:
    base = {"done": cfg.setup_done(), "assistant": setup_chat.ASSISTANT}
    if sc is None:
        return {**base, "active": False}
    return {**base, "active": True, "state": sc.state, "messages": sc.messages,
            "options": [{"value": v, "label": label} for v, label in sc.options()], "secret": sc.secret}


def install(app: FastAPI, interpret_with: Callable[[str, list[dict], str], dict | None],
            reload_after_save: Callable[[], Any]) -> None:
    talks: dict[str, "setup_chat.SetupChat"] = {}

    def who(request: Request) -> tuple[str, dict | None]:
        account = getattr(request.state, "account", None)
        return (account or {}).get("email") or "dashboard", account

    def interpreter(question: str, options: list[tuple[str, str]], answer: str) -> dict | None:
        try:
            result = interpret_with(question, [{"value": v, "label": label} for v, label in options], answer)
        except Exception:  # noqa: BLE001 - no model, or it failed: the script's own help is enough
            return None
        return result if isinstance(result, dict) else None

    def save(sc: "setup_chat.SetupChat", account: dict | None) -> None:
        values = sc.values()
        if account and not acc.can(account.get("role"), "configure"):
            sc.state = "review"
            sc._say(LOCKED)
            return
        bad = [f.prompt for f in cfg.FIELDS.values() if not cfg.valid(f, values.get(f.env, f.default))]
        if bad:
            sc.state = "review"
            sc._say("I can't save yet; these values are not valid: " + "; ".join(bad)
                    + ". Fix them on the Configuration page, or start over.")
            return
        path = cfg.save(values)
        cfg.mark_setup_done("chat")
        try:
            watched = setup_chat.save_log_sources(sc, f"guided setup ({values.get('SENTRAI_OPERATOR') or 'operator'})")
        except OSError as e:
            watched = []
            sc._say(f"I couldn't add the log files to the collector's list ({e}). Add them on the Collector page instead.")
        note = f"Saved to {path.name if hasattr(path, 'name') else path}. "
        if watched:
            note += f"The collector now watches {', '.join(watched)}. "
        try:
            reload_after_save()
            note += "Cyanide and the extensions use the new settings now. Restart SentrAI (stop, then run) so the other parts pick up the rest."
        except Exception:  # noqa: BLE001 - saved is saved
            note += "Start SentrAI (run.ps1 or run.sh) and every part will use these settings."
        deploy = setup_chat.deploy_command(sc)
        if deploy:
            port = sc.notes.get("port", "8501")
            note += ("\n\nWho can open the dashboard is a firewall setting, which needs admin rights. On a Linux server, "
                     f"run this once from the `mvp` folder to apply it:\n\n```\n{deploy}\n```\n\n"
                     "It keeps everything you saved here. On Windows or a laptop the dashboard stays on this computer"
                     + (f"; start run.sh with `--dashboard-port {port}` (Windows: run.ps1 `-DashboardPort {port}`)" if port != "8501" else "") + ".")
        sc.saved(note + "\n\nYou can change anything later here or on the Configuration page.")

    @app.get("/ui/setup")
    def get_setup(request: Request) -> dict[str, Any]:
        return view(talks.get(who(request)[0]))

    @app.post("/ui/setup/start")
    def post_start(request: Request) -> dict[str, Any]:
        me = who(request)[0]
        if me not in talks and len(talks) >= MOST:
            talks.pop(next(iter(talks)))
        talks[me] = setup_chat.SetupChat()
        return view(talks[me])

    @app.post("/ui/setup/answer")
    def post_answer(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        me, account = who(request)
        sc = talks.get(me)
        if sc is None:
            raise HTTPException(409, "Guided setup is not open. Start it first.")
        sc.answer(str(body.get("text") or ""), interpret=interpreter)
        if sc.state == "save":
            save(sc, account)
        return view(sc)

    @app.post("/ui/setup/leave")
    def post_leave(request: Request) -> dict[str, Any]:
        talks.pop(who(request)[0], None)
        return view(None)
