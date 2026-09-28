"""CactAI notifier: delivers core alerts to Telegram (or the console) and relays operator decisions.

Env:
  CACTAI_CORE_URL      core API base URL (default http://127.0.0.1:8000)
  TELEGRAM_BOT_TOKEN   bot token from @BotFather  (never hardcode it)
  TELEGRAM_CHAT_ID     chat that receives alerts and is allowed to press buttons
  CACTAI_OPERATOR      fallback operator name (default "operator")
  NOTIFIER_POLL_SECONDS poll interval (default 2)
If TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is missing, runs in CONSOLE mode.

Usage:  python notifier.py [--console] [--once] [--core URL]
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from core import Core, CoreError
from formatting import (APPROVE, PERMANENT, REJECT, ROLLBACK, button_specs, format_console,
                        format_telegram, incident_id_of, parse_callback)

log = logging.getLogger("cactai.notifier")

DEFAULT_CORE = "http://127.0.0.1:8000"


# ------------------------------------------------------------------ shared delivery loop

SendFn = Callable[[dict, "dict | None", "dict | None"], str]


def process_pending(core: Core, send: SendFn, channel: str, seen: set[str] | None = None) -> list[str]:
    """Deliver every pending notification once; mark delivered. Returns delivered ids."""
    delivered: list[str] = []
    risk = core.risk()
    for n in core.pending():
        nid = str(n.get("id") or n.get("notification_id") or "")
        if not nid or (seen is not None and nid in seen):
            continue
        iid = incident_id_of(n)
        incident = core.incident(iid) if iid else None
        message_id = send(n, incident, risk)
        try:
            core.delivered(nid, channel, message_id)
        except CoreError as exc:
            log.warning("could not mark %s delivered: %s", nid, exc)
        if seen is not None:
            seen.add(nid)  # never resend in this process even if marking failed
        delivered.append(nid)
    return delivered


# ------------------------------------------------------------------ console mode

def console_sender(out=None, color: bool | None = None) -> SendFn:
    stream = out or sys.stdout
    use_color = stream.isatty() if color is None and hasattr(stream, "isatty") else bool(color)
    counter = {"n": 0}

    def send(n: dict, incident: dict | None, risk: dict | None) -> str:
        counter["n"] += 1
        stamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n🌵 [{stamp}] alert {n.get('id')} for {incident_id_of(n) or '-'}", file=stream)
        print(format_console(n, incident, risk, color=use_color), file=stream, flush=True)
        return f"console-{int(time.time())}-{counter['n']}"

    return send


def run_console(core: Core, poll: float, once: bool = False) -> None:
    print("🌵 CactAI notifier · CONSOLE mode (set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID for Telegram)")
    print(f"   polling {core.base_url}/notifications/pending every {poll:g} s. Ctrl+C to stop.")
    send = console_sender()
    seen: set[str] = set()
    down = False
    while True:
        try:
            process_pending(core, send, "console", seen)
            if down:
                print("   core reachable again.")
            down = False
        except CoreError as exc:
            if not down:
                print(f"   core unavailable ({exc}); retrying...")
            down = True
        if once:
            return
        time.sleep(poll)


# ------------------------------------------------------------------ telegram mode

def run_telegram(core: Core, token: str, chat_id: str, poll: float, fallback_operator: str) -> None:
    from telegram import ForceReply, InlineKeyboardButton, InlineKeyboardMarkup, Update
    from telegram.constants import ParseMode
    from telegram.ext import (Application, CallbackQueryHandler, CommandHandler, ContextTypes,
                              MessageHandler, filters)

    allowed_chat = str(chat_id)
    seen: set[str] = set()

    def operator_of(update: Update) -> str:
        u = update.effective_user
        if u is None:
            return fallback_operator
        return u.username or u.full_name or fallback_operator

    def is_allowed(update: Update) -> bool:
        return update.effective_chat is not None and str(update.effective_chat.id) == allowed_chat

    async def poll_loop(app: Application) -> None:
        loop = asyncio.get_running_loop()
        down = False

        def send(n: dict, incident: dict | None, risk: dict | None) -> str:
            specs = button_specs(n, incident)
            markup = InlineKeyboardMarkup([[InlineKeyboardButton(label, callback_data=data)
                                            for label, data in specs]]) if specs else None
            fut = asyncio.run_coroutine_threadsafe(
                app.bot.send_message(chat_id=allowed_chat, text=format_telegram(n, incident, risk),
                                     parse_mode=ParseMode.HTML, reply_markup=markup), loop)
            msg = fut.result(timeout=20)
            log.info("delivered %s as telegram message %s", n.get("id"), msg.message_id)
            return str(msg.message_id)

        while True:
            try:
                await asyncio.to_thread(process_pending, core, send, "telegram", seen)
                if down:
                    log.info("core reachable again")
                down = False
            except CoreError as exc:
                if not down:
                    log.warning("core unavailable: %s", exc)
                down = True
            except Exception:  # keep the bot alive whatever happens
                log.exception("poll loop error")
            await asyncio.sleep(poll)

    async def post_init(app: Application) -> None:
        app.bot_data["poller"] = asyncio.create_task(poll_loop(app))
        app.bot_data.setdefault("reject_prompts", {})
        log.info("CactAI notifier online in TELEGRAM mode, chat %s, core %s", allowed_chat, core.base_url)

    async def on_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        query = update.callback_query
        if not is_allowed(update):
            await query.answer("This chat is not authorised for CactAI.", show_alert=True)
            return
        parsed = parse_callback(query.data or "")
        if not parsed:
            await query.answer("Unknown action")
            return
        verb, iid = parsed
        op = operator_of(update)
        try:
            await asyncio.to_thread(core.ack, iid, op, "telegram")
        except CoreError as exc:
            log.warning("ack failed for %s: %s", iid, exc)
        stamp = datetime.now().strftime("%H:%M:%S")
        try:
            if verb == APPROVE:
                await asyncio.to_thread(core.decision, iid, op, "approve", "Approved via Telegram")
                result = f"✅ Approved & patch applied by @{op} at {stamp}"
            elif verb == REJECT:
                await query.answer("Reply with your justification")
                prompt = await context.bot.send_message(
                    chat_id=allowed_chat,
                    text=f"⛔ Rejecting <b>{iid}</b>. Reply to this message with your justification "
                         "(it is written to the hash-chained audit log).",
                    parse_mode=ParseMode.HTML, reply_markup=ForceReply(selective=True))
                context.bot_data.setdefault("reject_prompts", {})[prompt.message_id] = (iid, query.message.message_id)
                context.user_data["awaiting_reject"] = (iid, query.message.message_id)
                return
            elif verb == ROLLBACK:
                await asyncio.to_thread(core.rollback, iid, op, "Rolled back via Telegram")
                result = f"↩️ Rolled back by @{op} at {stamp}"
            else:  # PERMANENT
                await asyncio.to_thread(core.permanent, iid, op, "Made permanent via Telegram")
                result = f"📌 Made permanent by @{op} at {stamp}"
        except CoreError as exc:
            await query.answer("Core rejected the action", show_alert=True)
            await context.bot.send_message(chat_id=allowed_chat, text=f"❌ {iid}: {exc}")
            return
        await query.answer("Recorded")
        await query.edit_message_reply_markup(reply_markup=None)
        await query.message.reply_text(result)

    async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not is_allowed(update) or update.message is None:
            return
        prompts = context.bot_data.get("reject_prompts", {})
        target = None
        reply_to = update.message.reply_to_message
        if reply_to is not None and reply_to.message_id in prompts:
            target = prompts.pop(reply_to.message_id)
        elif context.user_data.get("awaiting_reject"):
            target = context.user_data["awaiting_reject"]
        if not target:
            return
        context.user_data.pop("awaiting_reject", None)
        iid, alert_msg_id = target
        justification = (update.message.text or "").strip()
        if not justification:
            await update.message.reply_text("A justification is required to reject.")
            return
        op = operator_of(update)
        try:
            await asyncio.to_thread(core.decision, iid, op, "reject", justification)
        except CoreError as exc:
            await update.message.reply_text(f"❌ {iid}: {exc}")
            return
        try:
            await context.bot.edit_message_reply_markup(chat_id=allowed_chat, message_id=alert_msg_id, reply_markup=None)
        except Exception:  # message may be too old to edit
            pass
        await update.message.reply_text(f"⛔ {iid} rejected by @{op}. Justification logged.")

    async def on_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await update.message.reply_text(
            f"🌵 CactAI notifier is running.\nThis chat id: {update.effective_chat.id}\n"
            + ("Alerts are delivered here." if is_allowed(update) else "This chat is NOT the configured alert chat."))

    app = Application.builder().token(token).post_init(post_init).build()
    app.add_handler(CommandHandler("start", on_start))
    app.add_handler(CallbackQueryHandler(on_button))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.run_polling(allowed_updates=Update.ALL_TYPES)


# ------------------------------------------------------------------ entry point

def main(argv: list[str] | None = None) -> int:
    sys.path.append(str(Path(__file__).resolve().parents[1]))
    import cactai_config
    cactai_config.load()  # saved settings (bot token, chat id, operator) as env defaults

    p = argparse.ArgumentParser(description="CactAI notifier")
    p.add_argument("--core", default=os.environ.get("CACTAI_CORE_URL", DEFAULT_CORE))
    p.add_argument("--console", action="store_true", help="force console mode")
    p.add_argument("--once", action="store_true", help="console mode: deliver pending once and exit")
    p.add_argument("--poll", type=float, default=float(os.environ.get("NOTIFIER_POLL_SECONDS", "2")))
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    core = Core(args.core)
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    operator = os.environ.get("CACTAI_OPERATOR", "operator")

    try:
        if args.console or args.once or not (token and chat_id):
            run_console(core, args.poll, once=args.once)
        else:
            run_telegram(core, token, chat_id, args.poll, operator)
    except KeyboardInterrupt:
        print("\nnotifier stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
