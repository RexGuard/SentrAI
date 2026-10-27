"""SentrAI notifier: delivers core alerts to the console, email and the alert extensions, and relays
operator decisions.

Env:
  SENTRAI_CORE_URL      core API base URL (default http://127.0.0.1:8000)
  SENTRAI_API_TOKEN     core API token (default: the one saved by the setup wizard)
  SENTRAI_OPERATOR      fallback operator name (default "operator")
  NOTIFIER_POLL_SECONDS poll interval (default 2)
  NOTIFIER_WITNESS_FILE where the last delivered audit fingerprint is kept (default notifier/data/last_witness.txt)
  SMTP_HOST, ALERT_EMAIL_TO, ...  email channel, see emailer.py

Alert extensions (mvp/extensions/<name>/notifier.py) bring the other channels: Telegram runs a bot that
sends alerts with Approve / Reject buttons, Slack posts a read-only copy of each alert. Which ones run is
what the core says (GET /extensions, the dashboard's Extensions page); the notifier asks again every
15 s and switches without a restart. With no alert extension added, or Telegram's token or chat id
blank, it runs in CONSOLE mode.

Email is off until SMTP_HOST and ALERT_EMAIL_TO are set. Then it is sent when the main channel fails
(SENTRAI_EMAIL_MODE=backup, the default), next to every alert (always), and next to the console in
CONSOLE mode.

Usage:  python notifier.py [--console] [--once] [--core URL]
        python notifier.py --verify [LINE]   check the core's audit chain against the last witnessed
                                             fingerprint (or LINE); exit 1 if it was changed
In Telegram, /verify does the same.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from core import Core, CoreError
from emailer import EmailConfig, email_sender
from formatting import format_console, incident_id_of, witness_of

MVP_DIR = Path(__file__).resolve().parents[1]
if str(MVP_DIR) not in sys.path:
    sys.path.append(str(MVP_DIR))  # sentrai_config and sentrai_extensions live one level up
import sentrai_extensions as se  # noqa: E402

log = logging.getLogger("sentrai.notifier")

DEFAULT_CORE = "http://127.0.0.1:8000"
DEFAULT_WITNESS = Path(__file__).resolve().parent / "data" / "last_witness.txt"
CHECK_S = 15.0  # how often the notifier asks which alert extensions are on


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


# ------------------------------------------------------------------ shared delivery loop

# A sender returns the message id, (channel, message id) when the channel it used varies, or a list
# of (channel, message id, person) when it sent one message per person (see receipts()).
SendFn = Callable[[dict, "dict | None", "dict | None"], "str | tuple[str, str] | list[tuple[str, str, str | None]]"]


def receipts(result, channel: str) -> list[tuple[str, str, str | None]]:
    """A sender's result as (channel, message id, person) receipts, for POST /notifications/{id}/delivered.

    A sender may return a message id, (channel, message id), or a list of (channel, message id, person)."""
    if isinstance(result, list):
        return [(str(c), str(m), p) for c, m, p in result]
    if isinstance(result, tuple):
        return [(str(result[0]), str(result[1]), None)]
    return [(channel, str(result), None)]


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


# ------------------------------------------------------------------ copies (Slack, ...)

def with_copies(primary: SendFn, copies: list[tuple[str, SendFn]]) -> SendFn:
    """Send by `primary`, then a read-only copy by each of `copies` ((name, send) of the copy channels the
    alert extensions bring, such as Slack). A failed copy is only logged: the alert already went out."""
    if not copies:
        return primary

    def send(n: dict, incident: dict | None, risk: dict | None):
        result = primary(n, incident, risk)
        for name, copy in copies:
            try:
                mid = copy(n, incident, risk)
            except Exception as exc:
                log.warning("%s copy of %s failed: %s", name, n.get("id"), exc)
                continue
            if isinstance(result, list):  # one receipt per person (direct messages): the copy is one more
                result = [*result, (name, str(mid), None)]
            elif isinstance(result, tuple):
                result = (f"{result[0]}+{name}", result[1])
        return result

    return send


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


def run_console(core: Core, poll: float, once: bool = False, copies: list[tuple[str, SendFn]] | None = None,
                changed: Callable[[], bool] | None = None, seen: set[str] | None = None) -> None:
    """Prints each alert, until `changed()` says the alert extensions changed (or once, with `once`)."""
    print("🛡️ SentrAI notifier · CONSOLE mode (add the Telegram extension for alerts with buttons)")
    print(f"   polling {core.base_url}/notifications/pending every {poll:g} s. Ctrl+C to stop.")
    email_cfg, email = email_from_env()
    print(f"   email alerts to {', '.join(email_cfg.recipients)} via {email_cfg.host}" if email_cfg
          else "   email alerts off (set SMTP_HOST + ALERT_EMAIL_TO to turn them on)")
    if copies:
        print(f"   a copy of each alert goes to {', '.join(name for name, _ in copies)}")
    send = with_copies(with_email(console_sender(), "console", email, always=True), copies or [])
    seen = set() if seen is None else seen
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
        if once or (changed is not None and changed()):
            return
        time.sleep(poll)


# ------------------------------------------------------------------ alert extensions

class Context:
    """What an alert extension's notifier part gets (main_channel(ctx), copy_channel(ctx)). Use these,
    not the notifier's own functions: when the notifier runs as a script it must not be imported again."""

    def __init__(self, manifest: se.Manifest, core: Core, poll: float, operator: str,
                 changed: Callable[[], bool], environ: Mapping[str, str] | None = None) -> None:
        self.manifest = manifest
        self.name = manifest.name
        self.log = logging.getLogger(f"sentrai.ext.{manifest.name}")
        self.core = core
        self.poll = poll
        self.operator = operator  # the name a decision is recorded under when nothing better is known
        self.changed = changed  # True once the alert extensions or their settings changed: return then
        self.copies: list[tuple[str, SendFn]] = []  # the other extensions' copy channels
        self.witness = WitnessStore()
        self._environ = os.environ if environ is None else environ

    def setting(self, env: str) -> str:
        """One of its settings: the environment variable, its _FILE, or the manifest's default."""
        value = se.setting(env, self._environ)
        return value or next((s.default for s in self.manifest.settings if s.env == env), "")

    def number(self, env: str, fallback: float) -> float:
        try:
            return float(self.setting(env) or fallback)
        except ValueError:
            return fallback

    def process_pending(self, send: SendFn, channel: str, seen: set[str] | None = None) -> list[str]:
        """Delivers every pending alert once with `send`, marks it delivered and keeps its fingerprint."""
        return process_pending(self.core, send, channel, seen, self.witness)

    def verify(self, line: str) -> tuple[bool | None, str]:
        """(ok, message) for /verify: does the core's audit chain still hold this fingerprint line?"""
        return verify_witness(self.core, line)

    def email(self) -> tuple[EmailConfig | None, SendFn | None]:
        return email_from_env()

    def with_email(self, send: SendFn, channel: str) -> SendFn:
        """Email as the backup of `send`, or next to it (SENTRAI_EMAIL_MODE=always)."""
        cfg, email = email_from_env()
        return with_email(send, channel, email, always=bool(cfg and cfg.mode == "always"))

    def with_copies(self, send: SendFn) -> SendFn:
        return with_copies(send, [c for c in self.copies if c[0] != self.name])


class Channels:
    """Which alert extensions are added (the core decides; the settings when it cannot be asked), and
    whether that changed. A change of their settings counts too, so a new token takes effect."""

    def __init__(self, core: Core, environ: Mapping[str, str] | None = None, check_s: float = CHECK_S,
                 reload: Callable[[], Any] | None = None, clock: Callable[[], float] = time.monotonic) -> None:
        self.core = core
        self.environ = os.environ if environ is None else environ
        self.check_s = check_s
        self.reload = reload  # re-reads the settings file (sentrai_config.load(refresh=True))
        self.clock = clock
        self.source = ""  # where the last answer came from: core, last (core away) or settings
        self._from_core: list[str] | None = None
        self.names = self.decide()
        self.key = self._key(self.names)
        self.switch = False  # set by changed(): the runner returned because of a change
        self._next = clock() + check_s

    def parts(self) -> dict[str, se.Manifest]:
        return {n: m for n, m in se.installed(self.environ).items() if "notifier" in m.parts}

    def decide(self) -> list[str]:
        parts = self.parts()
        try:
            rows = self.core.extensions()
        except CoreError as exc:
            if exc.status not in (404, 405):  # unreachable for now: keep what it said last time
                if self._from_core is not None:
                    self.source = "last"
                    return [n for n in self._from_core if n in parts]
            rows = None  # never reached it yet, or an older core without extensions: the settings decide
        if rows is not None:
            added = {str(r.get("name")) for r in rows if r.get("added")}
            self._from_core = [n for n in parts if n in added]
            self.source = "core"
            return list(self._from_core)
        self.source = "settings"
        return [n for n, (on, _) in se.decide(parts, {}, self.environ).items() if on]

    def _key(self, names: list[str]) -> tuple[tuple[str, str], ...]:
        parts = self.parts()
        return tuple((n, se.fingerprint(parts[n], self.environ)) for n in names if n in parts)

    def changed(self) -> bool:
        """True once the added alert extensions or their settings changed. Asks at most every check_s."""
        if self.switch:
            return True
        now = self.clock()
        if now < self._next:
            return False
        self._next = now + self.check_s
        if self.reload is not None:
            try:
                self.reload()
            except Exception as exc:  # a half-written settings file: try again next time
                log.warning("could not re-read the settings: %s", exc)
        names = self.decide()
        if self._key(names) != self.key:
            log.info("alert extensions changed: %s -> %s", ", ".join(self.names) or "none", ", ".join(names) or "none")
            self.names, self.key, self.switch = names, self._key(names), True
        return self.switch

    def settle(self) -> None:
        """The runner stopped for the change: the next one runs what changed() found."""
        self.switch = False


def run(core: Core, poll: float, operator: str, console_only: bool = False, once: bool = False,
        channels: Channels | None = None) -> None:
    """Runs the main alert channel (an extension's, such as Telegram, or the console) with every added
    extension's copy channel next to it, and starts again whenever the alert extensions change."""
    channels = channels or Channels(core)
    seen: set[str] = set()  # alerts this process delivered, kept across switches
    while True:
        parts = channels.parts()
        copies: list[tuple[str, SendFn]] = []
        ctxs: list[tuple[Context, Any]] = []
        for name in channels.names:
            try:
                mod = se.load_part(parts[name], "notifier")
            except Exception as exc:  # a missing package or a broken part: the others run on
                log.error("the %s extension's notifier part could not load: %s: %s", name, type(exc).__name__, exc)
                continue
            ctx = Context(parts[name], core, poll, operator, channels.changed, channels.environ)
            ctxs.append((ctx, mod))
            make = getattr(mod, "copy_channel", None)
            try:
                copy = make(ctx) if make else None
            except Exception as exc:
                log.error("the %s extension's copy channel could not start: %s", name, exc)
                copy = None
            if copy is not None:
                copies.append((name, copy))
        main: Callable[[], Any] | None = None
        if not console_only and not once:
            for ctx, mod in ctxs:
                ctx.copies = copies
                make = getattr(mod, "main_channel", None)
                try:
                    main = make(ctx) if make else None
                except Exception as exc:
                    log.error("the %s extension could not start as the alert channel: %s", ctx.name, exc)
                    main = None
                if main is not None:
                    log.info("alerts go out through the %s extension%s", ctx.name,
                             f", with a copy to {', '.join(n for n, _ in copies if n != ctx.name)}"
                             if any(n != ctx.name for n, _ in copies) else "")
                    break
        if main is None:
            run_console(core, poll, once=once, copies=copies, changed=channels.changed, seen=seen)
        else:
            try:
                main()
            except Exception:  # a wrong token, a network failure at start: the console takes over
                log.exception("the alert channel stopped; alerts go to the console until the settings change")
                run_console(core, poll, copies=copies, changed=channels.changed, seen=seen)
        if once or not channels.switch:
            return  # stopped by Ctrl+C or a stop signal, not by a change
        channels.settle()


# ------------------------------------------------------------------ entry point

def main(argv: list[str] | None = None) -> int:
    import sentrai_config
    sentrai_config.load()  # saved settings (email, operator, the extensions' keys) as env defaults

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
    operator = os.environ.get("SENTRAI_OPERATOR", "operator")
    try:
        channels = Channels(core, reload=lambda: sentrai_config.load(refresh=True))
        run(core, args.poll, operator, console_only=args.console, once=args.once, channels=channels)
    except KeyboardInterrupt:
        print("\nnotifier stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
