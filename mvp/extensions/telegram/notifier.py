"""Telegram extension, notifier part: the bot. Alerts arrive with Approve, Reject and Take buttons, in
the team group and in each person's own chat once they link it.

Settings (extension.json): TELEGRAM_BOT_TOKEN from @BotFather (never hardcode it), TELEGRAM_CHAT_ID, the
group chat for alerts that are not for one person and for people who have not linked their own chat yet
(its members may press buttons), and TELEGRAM_GROUP_COPY: fallback (default), the group gets an alert
only when someone it is for has no linked chat; always, the group gets a copy of every alert; off, never,
unless nobody could be reached directly (see direct.py). With the token or the chat id blank the
notifier stays in console mode.

Personal alerts: each person in the routing file links their own private chat once by sending the bot
/link CODE (the code comes from the dashboard's Incidents page). After that, alerts routed to them
arrive in that chat with the buttons, and a button pressed there is recorded under their name.
/unlink in that chat stops it. /verify checks the audit log against the last fingerprint the chat got.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Callable

from core import CoreError
from formatting import APPROVE, REJECT, ROLLBACK, TAKE, button_specs, format_telegram, parse_callback

from .direct import Target, deliver, group_mode, plan

log = logging.getLogger("sentrai.ext.telegram")

__all__ = ["Target", "deliver", "group_mode", "main_channel", "plan", "run_telegram", "telegram_links"]


def telegram_links(core: Any) -> list[dict]:
    """Private chats linked to routing contacts; [] when the core is older, unreachable or has Telegram
    removed (its routes answer 404 then)."""
    try:
        data = core.request("GET", "/telegram/links")
    except CoreError:
        return []
    return [x for x in data or [] if isinstance(x, dict)]


def main_channel(ctx: Any) -> Callable[[], None] | None:
    """The bot as the notifier's main alert channel, or None (console) while its token or chat id is blank."""
    token, chat_id = ctx.setting("TELEGRAM_BOT_TOKEN"), ctx.setting("TELEGRAM_CHAT_ID")
    if not (token and chat_id):
        log.warning("Telegram is added but %s is blank, so alerts go to the console",
                    "TELEGRAM_BOT_TOKEN" if not token else "TELEGRAM_CHAT_ID")
        return None
    return lambda: run_telegram(ctx, token, chat_id, ctx.setting("TELEGRAM_GROUP_COPY") or "fallback")


def run_telegram(ctx: Any, token: str, chat_id: str, group_copy: str = "fallback") -> None:
    """The bot, until ctx.changed() says the alert extensions changed (or the notifier is stopped)."""
    from telegram import ForceReply, InlineKeyboardButton, InlineKeyboardMarkup, Update
    from telegram.constants import ChatType, ParseMode
    from telegram.error import Forbidden
    from telegram.ext import (Application, CallbackQueryHandler, CommandHandler, ContextTypes,
                              MessageHandler, filters)

    core, poll, fallback_operator, witness = ctx.core, ctx.poll, ctx.operator, ctx.witness
    allowed_chat = str(chat_id)
    mode = group_mode(group_copy)
    seen: set[str] = set()
    email_cfg, _ = ctx.email()
    # Private chats linked to routing contacts: chat id -> the core's link (with the contact's name).
    links: dict[str, dict] = {}

    def refresh_links() -> None:
        found = {str(x.get("chat_id")): x for x in telegram_links(core) if x.get("chat_id")}
        if found or not links:  # keep the last good list when the core is briefly unreachable
            links.clear()
            links.update(found)

    def chat_of(update: Update) -> str:
        return str(update.effective_chat.id) if update.effective_chat is not None else ""

    def operator_of(update: Update) -> str:
        """In a linked private chat, the contact's name from the routing file; in the group, the Telegram user."""
        link = links.get(chat_of(update))
        if link and link.get("name"):
            return str(link["name"])
        u = update.effective_user
        if u is None:
            return fallback_operator
        return u.username or u.full_name or fallback_operator

    def is_allowed(update: Update) -> bool:
        chat = chat_of(update)
        return bool(chat) and (chat == allowed_chat or chat in links)

    def is_private(update: Update) -> bool:
        return update.effective_chat is not None and update.effective_chat.type == ChatType.PRIVATE

    async def poll_loop(app: Application) -> None:
        loop = asyncio.get_running_loop()
        down = False

        def send_one(target: Target, n: dict, incident: dict | None, risk: dict | None) -> str:
            specs = button_specs(n, incident)
            markup = InlineKeyboardMarkup([[InlineKeyboardButton(label, callback_data=data)
                                            for label, data in specs]]) if specs else None
            fut = asyncio.run_coroutine_threadsafe(
                app.bot.send_message(chat_id=target.chat_id,
                                     text=format_telegram(n, incident, risk, personal=target.direct),
                                     parse_mode=ParseMode.HTML, reply_markup=markup), loop)
            return str(fut.result(timeout=20).message_id)

        def send(n: dict, incident: dict | None, risk: dict | None) -> list[tuple[str, str, str | None]]:
            """Each linked person in their own chat, and the group when direct.plan says so."""
            out = deliver(plan(n, allowed_chat, mode), lambda t: send_one(t, n, incident, risk), allowed_chat,
                          lambda e: "blocked the bot or left the chat" if isinstance(e, Forbidden) else str(e))
            log.info("delivered %s: %s", n.get("id"),
                     ", ".join(f"{to} directly" if to else "the group" for _, _, to in out))
            return out

        send_all = ctx.with_copies(ctx.with_email(send, "telegram"))
        while True:
            try:
                await asyncio.to_thread(refresh_links)
                await asyncio.to_thread(ctx.process_pending, send_all, "telegram", seen)
                if down:
                    log.info("core reachable again")
                down = False
            except CoreError as exc:
                if not down:
                    log.warning("core unavailable: %s", exc)
                down = True
            except Exception:  # keep the bot alive whatever happens
                log.exception("poll loop error")
            if await asyncio.to_thread(ctx.changed):  # removed, or new settings: the notifier starts again
                log.info("Telegram stops: the alert extensions or their settings changed")
                while not app.running:  # still starting up, and stop_running() only stops a running bot
                    await asyncio.sleep(0.1)
                app.stop_running()
                return
            await asyncio.sleep(poll)

    async def post_init(app: Application) -> None:
        await asyncio.to_thread(refresh_links)
        app.bot_data["poller"] = asyncio.create_task(poll_loop(app))
        app.bot_data.setdefault("reject_prompts", {})
        log.info("SentrAI notifier online in TELEGRAM mode, group chat %s, %d personal chat(s) linked, "
                 "group copy: %s, core %s", allowed_chat, len(links), mode, core.base_url)
        log.info("email alerts: %s", email_cfg.describe() if email_cfg else "off (no SMTP_HOST / ALERT_EMAIL_TO)")

    async def tell_group(context: ContextTypes.DEFAULT_TYPE, update: Update, text: str) -> None:
        """A decision made in someone's private chat is also noted in the group, so the team sees it."""
        if mode == "off" or not allowed_chat or chat_of(update) == allowed_chat:
            return
        try:
            await context.bot.send_message(chat_id=allowed_chat, text=text)
        except Exception as exc:
            log.warning("could not note the decision in the group: %s", exc)

    async def on_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        query = update.callback_query
        if not is_allowed(update):
            await query.answer("This chat is not linked to SentrAI. Send /link with your code first.", show_alert=True)
            return
        parsed = parse_callback(query.data or "")
        if not parsed:
            await query.answer("Unknown action")
            return
        verb, iid = parsed
        op = operator_of(update)
        here = chat_of(update)
        try:
            await asyncio.to_thread(core.ack, iid, op, "telegram")
        except CoreError as exc:
            log.warning("ack failed for %s: %s", iid, exc)
        stamp = datetime.now().strftime("%H:%M:%S")
        try:
            if verb == TAKE:
                await asyncio.to_thread(core.assign, iid, op, op, "Taken via Telegram")
                result = f"🙋 {iid} taken by {op} at {stamp}. It is yours until it is resolved."
            elif verb == APPROVE:
                await asyncio.to_thread(core.decision, iid, op, "approve", "Approved via Telegram")
                result = f"✅ {iid} approved & patch applied by {op} at {stamp}"
            elif verb == REJECT:
                await query.answer("Reply with your justification")
                prompt = await context.bot.send_message(
                    chat_id=here,
                    text=f"⛔ Rejecting <b>{iid}</b>. Reply to this message with your justification "
                         "(it is written to the hash-chained audit log).",
                    parse_mode=ParseMode.HTML, reply_markup=ForceReply(selective=True))
                target = (iid, here, query.message.message_id)
                context.bot_data.setdefault("reject_prompts", {})[(here, prompt.message_id)] = target
                context.user_data["awaiting_reject"] = target
                return
            elif verb == ROLLBACK:
                await asyncio.to_thread(core.rollback, iid, op, "Rolled back via Telegram")
                result = f"↩️ {iid} rolled back by {op} at {stamp}"
            else:  # PERMANENT
                await asyncio.to_thread(core.permanent, iid, op, "Made permanent via Telegram")
                result = f"📌 {iid} made permanent by {op} at {stamp}"
        except CoreError as exc:
            await query.answer("Core rejected the action", show_alert=True)
            await context.bot.send_message(chat_id=here, text=f"❌ {iid}: {exc}")
            return
        await query.answer("Recorded")
        await query.edit_message_reply_markup(reply_markup=None)
        await query.message.reply_text(result)
        await tell_group(context, update, result)

    async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not is_allowed(update) or update.message is None:
            return
        here = chat_of(update)
        prompts = context.bot_data.get("reject_prompts", {})
        target = None
        reply_to = update.message.reply_to_message
        if reply_to is not None and (here, reply_to.message_id) in prompts:
            target = prompts.pop((here, reply_to.message_id))
        elif context.user_data.get("awaiting_reject"):
            target = context.user_data["awaiting_reject"]
        if not target:
            return
        context.user_data.pop("awaiting_reject", None)
        iid, alert_chat, alert_msg_id = target
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
            await context.bot.edit_message_reply_markup(chat_id=alert_chat, message_id=alert_msg_id, reply_markup=None)
        except Exception:  # message may be too old to edit
            pass
        await update.message.reply_text(f"⛔ {iid} rejected by {op}. Justification logged.")
        await tell_group(context, update, f"⛔ {iid} rejected by {op}: {justification}")

    async def link_with(update: Update, code: str) -> None:
        """/link CODE (or /start CODE from a t.me link) in a private chat: alerts for that contact come here."""
        if update.message is None:
            return
        if not is_private(update):
            await update.message.reply_text("Send /link to me in a private chat, not in a group, so alerts "
                                            "reach only you.")
            return
        u = update.effective_user
        try:
            res = await asyncio.to_thread(core.request, "POST", "/telegram/link",
                                          {"code": code, "chat_id": chat_of(update),
                                           "username": (u.username or "") if u else ""})
        except CoreError as exc:
            await update.message.reply_text("❌ " + (exc.detail or "Could not reach SentrAI. Try again in a minute."))
            return
        await asyncio.to_thread(refresh_links)
        await update.message.reply_text(
            f"✅ Linked. SentrAI alerts for {res.get('name')} now come to this chat, with the buttons to "
            "approve, reject or take them. Send /unlink to stop.")

    async def on_link(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        code = " ".join(context.args or []).strip()
        if not code:
            if update.message is not None:
                await update.message.reply_text("Send /link followed by the code from the SentrAI dashboard "
                                                "(Incidents page, Telegram for each person).")
            return
        await link_with(update, code)

    async def on_unlink(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if update.message is None or not is_private(update):
            return
        link = links.get(chat_of(update))
        if not link:
            await update.message.reply_text("This chat is not linked to anyone.")
            return
        try:
            await asyncio.to_thread(core.request, "POST", "/telegram/unlink",
                                    {"chat_id": chat_of(update), "operator": operator_of(update)})
        except CoreError as exc:
            await update.message.reply_text(f"❌ {exc}")
            return
        await asyncio.to_thread(refresh_links)
        links.pop(chat_of(update), None)
        await update.message.reply_text(f"Unlinked. Alerts for {link.get('name')} go to the team group again.")

    async def on_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if context.args:  # t.me/<bot>?start=CODE
            await link_with(update, context.args[0])
            return
        here = chat_of(update)
        if here in links:
            status = f"Alerts for {links[here].get('name')} are delivered here."
        elif here == allowed_chat:
            status = "This is the team group: alerts for people without their own linked chat come here."
        elif is_private(update):
            status = "To get your alerts here, send /link with the code from the SentrAI dashboard."
        else:
            status = "This chat is NOT the configured alert chat."
        await update.message.reply_text(f"🛡️ SentrAI notifier is running.\nThis chat id: {here}\n{status}")

    async def on_verify(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """/verify: is the audit log on the server still what the last alert witnessed?
        /verify SENTRAI-FP v1 ... checks an older line copied from this chat instead."""
        if not is_allowed(update) or update.message is None:
            return
        line = " ".join(context.args or []).strip() or witness.last()
        _, message = await asyncio.to_thread(ctx.verify, line)
        await update.message.reply_text(message)

    async def post_stop(app: Application) -> None:
        poller = app.bot_data.get("poller")
        if poller is not None and not poller.done():  # stopped by a signal: nothing may send any more
            poller.cancel()

    # A new event loop for each run, closed when the bot stops. Closing it also gives Ctrl+C and the stop
    # signal back, so the console (or this bot again, with new settings) can follow in the same process.
    asyncio.set_event_loop(asyncio.new_event_loop())
    app = Application.builder().token(token).post_init(post_init).post_stop(post_stop).build()
    app.add_handler(CommandHandler("start", on_start))
    app.add_handler(CommandHandler("link", on_link))
    app.add_handler(CommandHandler("unlink", on_unlink))
    app.add_handler(CommandHandler("verify", on_verify))
    app.add_handler(CallbackQueryHandler(on_button))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    try:
        app.run_polling(allowed_updates=Update.ALL_TYPES)
    finally:
        asyncio.set_event_loop(None)


