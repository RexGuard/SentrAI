"""SentrAI notifier: delivers core alerts to Telegram (or the console) and relays operator decisions.

Env:
  SENTRAI_CORE_URL      core API base URL (default http://127.0.0.1:8000)
  SENTRAI_API_TOKEN     core API token (default: the one saved by the setup wizard)
  TELEGRAM_BOT_TOKEN   bot token from @BotFather  (never hardcode it)
  TELEGRAM_CHAT_ID     group chat for alerts that are not for one person, and for people who have
                       not linked their own chat yet; its members may press buttons
  TELEGRAM_GROUP_COPY  fallback (default): the group gets an alert only when someone it is for has
                       no linked chat; always: the group gets a copy of every alert; off: never,
                       unless nobody could be reached directly (see direct.py)
  SENTRAI_OPERATOR      fallback operator name (default "operator")
  NOTIFIER_POLL_SECONDS poll interval (default 2)
  NOTIFIER_WITNESS_FILE where the last delivered audit fingerprint is kept (default notifier/data/last_witness.txt)
  TELEGRAM_REPORT_FROM  who may send /report <what you saw>: "alert-chat" (default, only TELEGRAM_CHAT_ID),
                       "any" (anyone who messages the bot, e.g. all staff), or a comma list of chat ids
  SMTP_HOST, ALERT_EMAIL_TO, ...  email backup channel, see emailer.py
  SLACK_WEBHOOK_URL    also post a copy of every alert to a Slack channel, see slack.py
If TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is missing, runs in CONSOLE mode.
Email is off until SMTP_HOST and ALERT_EMAIL_TO are set. Then it is sent when Telegram fails
(SENTRAI_EMAIL_MODE=backup, the default), next to every Telegram alert (always), and next to
the console in CONSOLE mode.

Usage:  python notifier.py [--console] [--once] [--core URL]
        python notifier.py --verify [LINE]   check the core's audit chain against the last witnessed
                                             fingerprint (or LINE); exit 1 if it was changed
In Telegram, /verify does the same, and /report <what you saw> sends a staff report (see staff_reports.py
in the core): the reporter gets back what to do now, and technical staff review it on the dashboard.

Personal alerts: each person in the routing file links their own private chat once by sending the
bot /link CODE (the code comes from the dashboard's Incidents page). After that, alerts routed to
them arrive in that chat with the buttons, and a button pressed there is recorded under their name.
/unlink in that chat stops it.
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
from direct import Target, deliver, group_mode, plan, receipts
from emailer import EmailConfig, email_sender
from slack import slack_from_env, with_slack
from formatting import (APPROVE, REJECT, ROLLBACK, TAKE, button_specs, format_console,
                        format_telegram, incident_id_of, parse_callback, witness_of)

log = logging.getLogger("sentrai.notifier")

DEFAULT_CORE = "http://127.0.0.1:8000"
DEFAULT_WITNESS = Path(__file__).resolve().parent / "data" / "last_witness.txt"


# ------------------------------------------------------------------ audit witness

class WitnessStore:
    """The newest audit fingerprint this notifier delivered. The same line also sits in the alert
    chat, where the server cannot change it; this copy lets /verify check it without pasting."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path or os.environ.get("NOTIFIER_WITNESS_FILE") or DEFAULT_WITNESS)

    def save(self, line: str) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(line.strip() + "\n", encoding="utf-8")
        except OSError as exc:
            log.warning("could not save the audit witness to %s: %s", self.path, exc)

    def last(self) -> str:
        try:
            return self.path.read_text(encoding="utf-8").strip()
        except OSError:
            return ""


def verify_witness(core: Core, line: str) -> tuple[bool | None, str]:
    """(ok, message): does the core's chain still hold the witnessed record? None = could not check."""
    if not line:
        return None, "No audit fingerprint has been delivered yet, so there is nothing to compare."
    try:
        res = core.verify(line)
    except CoreError as exc:
        return None, f"Could not reach the core to check: {exc}"
    ok = bool(res.get("ok"))
    why = str(res.get("reason") or "")
    return ok, ("✅ Audit log intact: " if ok else "🚨 AUDIT LOG CHANGED: ") + why


def report_allowed(chat_id: str, alert_chat: str, setting: str | None) -> bool:
    """May this chat send /report? TELEGRAM_REPORT_FROM: alert-chat (default), any, or chat ids."""
    setting = (setting or "alert-chat").strip().lower()
    if setting == "any":
        return True
    if setting == "alert-chat":
        return str(chat_id) == str(alert_chat)
    return str(chat_id) in {c.strip() for c in setting.split(",") if c.strip()} or str(chat_id) == str(alert_chat)


def staff_report_reply(core: Core, text: str, reporter: str, chat_id: str) -> str:
    """Sends /report text to the core and words the answer for the person who reported."""
    text = text.strip()
    if not text:
        return ("Tell us what you noticed after /report, in your own words. For example:\n"
                "/report I got an email asking for my password and clicked the link.")
    try:
        res = core.staff_report(text, reporter, f"telegram:{chat_id}")
    except CoreError:
        return "The report could not be sent right now. Please tell your IT contact directly."
    if res.get("error"):
        return f"⚠️ {res['error']}"
    steps = "\n".join(f"{n}. {a}" for n, a in enumerate(res.get("advice") or [], 1))
    urgent = " It is treated as urgent." if res.get("urgency") == "high" else ""
    return (f"✅ Thank you. Report {res.get('id')} reached the security team.{urgent}\n"
            f"It sounds like: {res.get('kind_label') or 'something to check'}.\n\n"
            + (f"What to do now:\n{steps}" if steps else ""))


# ------------------------------------------------------------------ shared delivery loop

# A sender returns the message id, (channel, message id) when the channel it used varies, or a list
# of (channel, message id, person) when it sent one message per person (direct.receipts).
SendFn = Callable[[dict, "dict | None", "dict | None"], "str | tuple[str, str] | list[tuple[str, str, str | None]]"]


def process_pending(core: Core, send: SendFn, channel: str, seen: set[str] | None = None,
                    witness: WitnessStore | None = None) -> list[str]:
    """Deliver every pending notification once; mark delivered. Returns delivered ids.
    The audit fingerprint each one carries is kept in `witness` once it is sent."""
    delivered: list[str] = []
    risk = core.risk()
    for n in core.pending():
        nid = str(n.get("id") or n.get("notification_id") or "")
        if not nid or (seen is not None and nid in seen):
            continue
        iid = incident_id_of(n)
        incident = core.incident(iid) if iid else None
        result = send(n, incident, risk)
        if witness is not None and witness_of(n):
            witness.save(witness_of(n))
        for used, message_id, to in receipts(result, channel):
            try:
                core.delivered(nid, used, message_id, to)
            except CoreError as exc:
                log.warning("could not mark %s delivered: %s", nid, exc)
        if seen is not None:
            seen.add(nid)  # never resend in this process even if marking failed
        delivered.append(nid)
    return delivered


# ------------------------------------------------------------------ email alongside or as fallback

def with_email(primary: SendFn, channel: str, email: SendFn | None, always: bool) -> SendFn:
    """Send by `primary`; also email when `always`, or email instead when `primary` fails.

    A failed extra email is only logged (the alert already went out). When `primary` fails and
    email fails too, the error is raised so the alert stays pending and is retried next poll.
    """
    if email is None:
        return primary

    def send(n: dict, incident: dict | None, risk: dict | None):
        try:
            result = primary(n, incident, risk)
        except Exception as exc:
            log.warning("%s delivery of %s failed (%s); sending it by email instead", channel, n.get("id"), exc)
            return "email", email(n, incident, risk)
        if isinstance(result, list):  # one message per person: the email copy is one more receipt
            if not always:
                return result
            try:
                return [*result, ("email", email(n, incident, risk), None)]
            except Exception as exc:
                log.warning("email copy of %s failed: %s", n.get("id"), exc)
                return result
        used, message_id = result if isinstance(result, tuple) else (channel, result)
        if not always:
            return used, message_id
        try:
            return f"{used}+email", f"{message_id} {email(n, incident, risk)}"
        except Exception as exc:
            log.warning("email copy of %s failed: %s", n.get("id"), exc)
            return used, message_id

    return send


def email_from_env() -> tuple[EmailConfig | None, SendFn | None]:
    cfg = EmailConfig.from_env()
    return cfg, (email_sender(cfg) if cfg else None)


# ------------------------------------------------------------------ console mode

def console_sender(out=None, color: bool | None = None) -> SendFn:
    stream = out or sys.stdout
    use_color = stream.isatty() if color is None and hasattr(stream, "isatty") else bool(color)
    counter = {"n": 0}

    def send(n: dict, incident: dict | None, risk: dict | None) -> str:
        counter["n"] += 1
        stamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n🛡️ [{stamp}] alert {n.get('id')} for {incident_id_of(n) or '-'}", file=stream)
        print(format_console(n, incident, risk, color=use_color), file=stream, flush=True)
        return f"console-{int(time.time())}-{counter['n']}"

    return send


def run_console(core: Core, poll: float, once: bool = False) -> None:
    print("🛡️ SentrAI notifier · CONSOLE mode (set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID for Telegram)")
    print(f"   polling {core.base_url}/notifications/pending every {poll:g} s. Ctrl+C to stop.")
    email_cfg, email = email_from_env()
    print(f"   email alerts to {', '.join(email_cfg.recipients)} via {email_cfg.host}" if email_cfg
          else "   email alerts off (set SMTP_HOST + ALERT_EMAIL_TO to turn them on)")
    send = with_slack(with_email(console_sender(), "console", email, always=True), slack_from_env())
    seen: set[str] = set()
    witness = WitnessStore()
    down = False
    while True:
        try:
            process_pending(core, send, "console", seen, witness)
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

def run_telegram(core: Core, token: str, chat_id: str, poll: float, fallback_operator: str,
                 group_copy: str = "fallback") -> None:
    from telegram import ForceReply, InlineKeyboardButton, InlineKeyboardMarkup, Update
    from telegram.constants import ChatType, ParseMode
    from telegram.error import Forbidden
    from telegram.ext import (Application, CallbackQueryHandler, CommandHandler, ContextTypes,
                              MessageHandler, filters)

    allowed_chat = str(chat_id)
    mode = group_mode(group_copy)
    seen: set[str] = set()
    witness = WitnessStore()
    email_cfg, email = email_from_env()
    # Private chats linked to routing contacts: chat id -> the core's link (with the contact's name).
    links: dict[str, dict] = {}

    def refresh_links() -> None:
        found = {str(x.get("chat_id")): x for x in core.telegram_links() if x.get("chat_id")}
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

        send_all = with_slack(with_email(send, "telegram", email, always=bool(email_cfg and email_cfg.mode == "always")),
                              slack_from_env())
        while True:
            try:
                await asyncio.to_thread(refresh_links)
                await asyncio.to_thread(process_pending, core, send_all, "telegram", seen, witness)
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
            res = await asyncio.to_thread(core.telegram_link, code, chat_of(update), (u.username or "") if u else "")
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
            await asyncio.to_thread(core.telegram_unlink, chat_of(update), operator_of(update))
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
        _, message = await asyncio.to_thread(verify_witness, core, line)
        await update.message.reply_text(message)

    report_from = os.environ.get("TELEGRAM_REPORT_FROM")

    async def on_report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """/report <what you saw>: a staff report. Staff can message the bot directly when
        TELEGRAM_REPORT_FROM allows their chat; the core limits how often one chat may send."""
        if update.message is None or update.effective_chat is None:
            return
        chat = str(update.effective_chat.id)
        if not report_allowed(chat, allowed_chat, report_from):
            await update.message.reply_text("This chat cannot send reports. Please tell your IT contact directly.")
            return
        text = (update.message.text or "").partition(" ")[2]
        reply = await asyncio.to_thread(staff_report_reply, core, text, operator_of(update), chat)
        await update.message.reply_text(reply)

    app = Application.builder().token(token).post_init(post_init).build()
    app.add_handler(CommandHandler("start", on_start))
    app.add_handler(CommandHandler("link", on_link))
    app.add_handler(CommandHandler("unlink", on_unlink))
    app.add_handler(CommandHandler("verify", on_verify))
    app.add_handler(CommandHandler("report", on_report))
    app.add_handler(CallbackQueryHandler(on_button))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.run_polling(allowed_updates=Update.ALL_TYPES)


# ------------------------------------------------------------------ entry point

def main(argv: list[str] | None = None) -> int:
    sys.path.append(str(Path(__file__).resolve().parents[1]))
    import sentrai_config
    sentrai_config.load()  # saved settings (bot token, chat id, operator) as env defaults

    p = argparse.ArgumentParser(description="SentrAI notifier")
    p.add_argument("--core", default=os.environ.get("SENTRAI_CORE_URL", DEFAULT_CORE))
    p.add_argument("--console", action="store_true", help="force console mode")
    p.add_argument("--once", action="store_true", help="console mode: deliver pending once and exit")
    p.add_argument("--poll", type=float, default=float(os.environ.get("NOTIFIER_POLL_SECONDS", "2")))
    p.add_argument("--verify", nargs="?", const="", metavar="LINE",
                   help="check the audit chain against the last witnessed fingerprint (or LINE) and exit")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    core = Core(args.core, token=sentrai_config.api_token())
    if args.verify is not None:
        ok, message = verify_witness(core, args.verify.strip() or WitnessStore().last())
        print(message)
        return 0 if ok else (1 if ok is False else 2)
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    operator = os.environ.get("SENTRAI_OPERATOR", "operator")

    try:
        if args.console or args.once or not (token and chat_id):
            run_console(core, args.poll, once=args.once)
        else:
            run_telegram(core, token, chat_id, args.poll, operator, os.environ.get("TELEGRAM_GROUP_COPY", "fallback"))
    except KeyboardInterrupt:
        print("\nnotifier stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
