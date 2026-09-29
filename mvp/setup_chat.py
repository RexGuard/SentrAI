"""Guided setup in the dashboard's Chat page: Cyanide asks the setup questions in plain words.

The same settings as the setup wizard and the Configuration page (cactai_config), asked one at a
time as a conversation, so a new user never has to open Configuration. Nothing is saved until
the user confirms the summary at the end; the dashboard then saves through cactai_config.save().

It is scripted, so it works without an AI key. Each question offers buttons, and typed answers
are matched to them (by number, label or a few plain words). When an AI model is configured, the
dashboard may pass `interpret` to map an answer the script cannot match to one of the options, or
to answer a question the user asked instead. Secrets are never passed to it.

Stdlib only; the tests drive it without Streamlit.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import cactai_config as cfg

Option = tuple[str, str]  # (value, button label)
# interpret(question, options, answer) -> {"choice": value or "", "reply": text} or None when no model
Interpret = Callable[[str, list[Option], str], "dict | None"]

HIDDEN = "••••••"
DEMO_LOGS = cfg.FIELDS["CACTAI_LAB_LOGS"].default
YES = {"yes", "y", "ok", "okay", "sure", "yep", "yeah", "sounds good", "go ahead", "do it", "fine", "correct"}
NO = {"no", "n", "none", "nope", "nothing", "skip", "no one", "nobody", "not now", "-"}
FILLER = {"and", "the", "is", "are", "our", "my", "a", "an", "account", "accounts", "user", "users", "please"}


class Retry(Exception):
    """The answer did not fit; the message says why and the question is asked again."""


@dataclass
class Step:
    key: str
    question: Callable[["SetupChat"], str]
    handle: Callable[["SetupChat", str], str]  # returns Cyanide's short acknowledgement, or raises Retry
    options: Callable[["SetupChat"], list[Option]] = lambda s: []
    when: Callable[["SetupChat"], bool] = lambda s: True
    secret: bool = False
    typed: bool = True  # False: only one of the options is a valid answer
    words: dict[str, set[str]] = field(default_factory=dict)  # extra plain words per option value


class SetupChat:
    """One guided setup conversation. `messages` is the transcript the dashboard draws."""

    def __init__(self, current: dict[str, str] | None = None) -> None:
        saved = {f.env: f.default for f in cfg.FIELDS.values()} | (cfg.read() if current is None else current)
        self.current = saved  # what is in use now, for "keep" answers and the summary
        self.answers: dict[str, str] = {}
        self.notes: dict[str, str] = {}  # choices made along the way that are not settings themselves
        self.messages: list[dict[str, str]] = []
        self.index = -1
        self.state = "asking"  # asking, review, save (the user confirmed), saved, cancelled
        self._say(f"Hi, I'm {ASSISTANT}. I'll set SentrAI up with you here, one question at a time, so you "
                  "don't need the Configuration page. Press a button or type your answer. "
                  "Nothing is saved until you confirm the summary at the end.")
        self._next()

    # ------------------------------------------------------------ state
    def value(self, env: str) -> str:
        return self.answers.get(env, self.current.get(env, ""))

    def set(self, **values: str) -> None:
        self.answers.update(values)

    @property
    def step(self) -> Step | None:
        return STEPS[self.index] if 0 <= self.index < len(STEPS) else None

    def options(self) -> list[Option]:
        if self.state == "review":
            return [("save", "Save these settings"), ("restart", "Start over"), ("cancel", "Cancel")]
        return self.step.options(self) if self.state == "asking" and self.step else []

    @property
    def secret(self) -> bool:
        return self.state == "asking" and bool(self.step and self.step.secret)

    def values(self) -> dict[str, str]:
        """Everything to save: the settings in use now with the answers on top."""
        return self.current | self.answers

    # ------------------------------------------------------------ conversation
    def answer(self, text: str, interpret: Interpret | None = None) -> None:
        """Take one answer (typed, or an option's value from a button) and move on."""
        text = (text or "").strip()
        if self.state == "review" and text:
            options = self.options()
            self._user(dict(options).get(text, text))
            self._review(self._match(text, options, {"save": YES, "restart": {"again", "redo"},
                                                     "cancel": {"stop", "quit", "exit"}}))
            return
        step = self.step
        if self.state != "asking" or step is None or not text:
            return
        options = step.options(self)
        choice = self._match(text, options, step.words)
        pressed = dict(options).get(text)  # a button sends its value; show its label
        self._user(pressed or (HIDDEN if step.secret else text))
        prefix = ""
        if choice is None and not step.typed:
            asked = interpret(step.question(self), options, text) if interpret and not step.secret else None
            if asked and asked.get("choice") in dict(options):
                choice, prefix = asked["choice"], str(asked.get("reply") or "").strip()
            else:
                reply = str((asked or {}).get("reply") or "").strip()
                self._say((reply + "\n\n" if reply else "I didn't catch that. ")
                          + "Please pick one of the buttons, or type its number.")
                return
        try:
            ack = step.handle(self, choice if choice is not None else text)
        except Retry as e:
            self._say(str(e))
            return
        self._next(" ".join(t for t in (prefix, ack) if t))

    def saved(self, note: str) -> None:
        self.state = "saved"
        self._say(note)

    def _review(self, choice: str | None) -> None:
        if choice == "save":
            self.state = "save"  # the dashboard saves, then calls saved()
        elif choice == "restart":
            self.__init__(self.current)
        elif choice == "cancel":
            self.state = "cancelled"
            self._say("Setup cancelled; nothing was saved. You can start again from the Chat page any time.")
        else:
            self._say("Please pick Save, Start over or Cancel.")

    def _next(self, ack: str = "") -> None:
        self.index += 1
        while self.step and not self.step.when(self):
            self.index += 1
        if self.step:
            q = self.step.question(self)
            self._say(f"{ack}\n\n{q}" if ack else q)
            return
        self.state = "review"
        text = (f"{ack}\n\n" if ack else "") + "Here is what I'll save:\n\n" + "\n".join(
            f"- {line}" for line in self.summary()) + "\n\nShall I save it?"
        self._say(text)

    def summary(self) -> list[str]:
        v = self.value
        lines = [f"**Security preset:** {cfg.preset_label(v(cfg.PRESET_ENV))} ("
                 + "; ".join(t for t, _ in cfg.describe(self.values())) + ")",
                 f"**Logs watched:** {'the demo lab logs' if v('CACTAI_LAB_LOGS') == DEMO_LOGS else v('CACTAI_LAB_LOGS')}",
                 f"**Never blocked:** {v('PROTECTED_IPS') or 'nothing'}",
                 f"**Never locked:** {v('PROTECTED_USERS') or 'no accounts'}",
                 f"**Your name:** {v('CACTAI_OPERATOR')}"]
        alerts = []
        if v("TELEGRAM_BOT_TOKEN") and v("TELEGRAM_CHAT_ID"):
            alerts.append(f"Telegram chat {v('TELEGRAM_CHAT_ID')}")
        if v("SMTP_HOST"):
            alerts.append(f"email to {v('ALERT_EMAIL_TO')} via {v('SMTP_HOST')}"
                          + (" as a backup" if alerts and v("CACTAI_EMAIL_MODE") == "backup" else ""))
        lines.append(f"**Alerts:** {', '.join(alerts) if alerts else 'shown in the console only'}")
        if v(cfg.cactai_llm.GENERIC_KEY_ENV):
            provider = v("CACTAI_LLM_PROVIDER")
            model = v(cfg.MODEL_ENV) or cfg.cactai_llm.DEFAULT_MODEL.get(provider) or "?"
            lines.append(f"**AI model:** {cfg.cactai_llm.LABEL.get(provider, provider)}, {model} (key set)")
        else:
            lines.append("**AI model:** none, fixed playbooks")
        if web_fields():
            lines.append(f"**Dashboard:** {dashboard_address(self)}")
        if WEB["password"] in cfg.FIELDS:
            who = f" as {v(WEB['email'])}" if WEB["email"] in cfg.FIELDS and v(WEB["email"]) else ""
            lines.append(f"**Dashboard sign-in:** {'password' + who if v(WEB['password']) else 'none'}")
        return lines

    # ------------------------------------------------------------ helpers
    def _say(self, text: str) -> None:
        self.messages.append({"role": "assistant", "text": text})

    def _user(self, text: str) -> None:
        self.messages.append({"role": "user", "text": text})

    @staticmethod
    def _match(text: str, options: list[Option], words: dict[str, set[str]]) -> str | None:
        """The option a typed answer means: its value, number, label, or one of its plain words."""
        t = text.strip().lower().rstrip(".!")
        for n, (value, label) in enumerate(options, 1):
            if t in (value.lower(), label.lower(), str(n)) or t in words.get(value, set()):
                return value
        return None


ASSISTANT = "Cyanide"


# ------------------------------------------------------------------ answers

def _keep(s: SetupChat, env: str, label: str) -> list[Option]:
    return [("keep", f"Keep {label}")] if s.current.get(env) else []


def _nonblank(text: str, what: str) -> str:
    if not text.strip():
        raise Retry(f"Please type {what}.")
    return text.strip()


def _merge_list(current: str, new: list[str]) -> str:
    items = [x.strip() for x in current.split(",") if x.strip()]
    return ",".join(dict.fromkeys(items + new))


# 1. What SentrAI guards -> suggested preset
KIND_TO_PRESET = {"sensitive": "strict", "office": "moderate", "busy": "balanced", "unsure": cfg.DEFAULT_PRESET}


def _kind(s: SetupChat, choice: str) -> str:
    s.notes["preset"] = KIND_TO_PRESET[choice]
    return ""


def _preset_question(s: SetupChat) -> str:
    name = s.notes.get("preset", cfg.DEFAULT_PRESET)
    p = cfg.PRESETS[name]
    how = "; ".join(t for t, _ in cfg.describe(p.values))
    return (f"Then I suggest the **{p.label}** preset. {p.about} In practice: {how}.\n\n"
            "Shall I use it? You can also pick another one.")


def _preset_options(s: SetupChat) -> list[Option]:
    name = s.notes.get("preset", cfg.DEFAULT_PRESET)
    return [("yes", f"Use {cfg.PRESETS[name].label}")] + [(n, p.label) for n, p in cfg.PRESETS.items() if n != name]


def _preset(s: SetupChat, choice: str) -> str:
    name = s.notes.get("preset", cfg.DEFAULT_PRESET) if choice == "yes" else choice
    s.set(**{cfg.PRESET_ENV: name}, **cfg.preset_values(name))
    return f"{cfg.PRESETS[name].label} it is."


# 2. Logs
def _logs(s: SetupChat, answer: str) -> str:
    if answer == "demo":
        s.set(CACTAI_LAB_LOGS=DEMO_LOGS)
        return "I'll watch the demo lab logs."
    if answer == "keep":
        return "I'll keep watching the same folder."
    path = Path(answer.strip().strip('"').strip("'")).expanduser()
    if not path.is_dir():
        raise Retry(f"I can't find a folder at {path} on this computer. Check the path, or use the demo logs.")
    s.set(CACTAI_LAB_LOGS=str(path.resolve()))
    return f"I'll watch {path.resolve()}."


# 3-4. What SentrAI must never touch
def _ips(s: SetupChat, answer: str) -> str:
    if answer == "none":
        return "Only this computer stays protected, as before."
    found = []
    for token in re.split(r"[\s,;]+", answer):
        token = token.strip("()[]'\".")
        try:
            found.append(str(ipaddress.ip_network(token, strict=False)) if "/" in token else str(ipaddress.ip_address(token)))
        except ValueError:
            continue
    if not found:
        raise Retry("I couldn't find an IP address in that. Type one like 192.168.1.20, or press No.")
    s.set(PROTECTED_IPS=_merge_list(s.value("PROTECTED_IPS"), found))
    return f"SentrAI will never block {', '.join(found)}."


def _users(s: SetupChat, answer: str) -> str:
    if answer == "none":
        return "No accounts are protected from locking."
    names = [w for w in re.split(r"[\s,;]+|\band\b", answer) if w and w.lower() not in FILLER]
    names = [w for w in names if re.fullmatch(r"[\w.@\\-]+", w)]
    if not names:
        raise Retry("Please type the account names, separated by commas, or press No.")
    s.set(PROTECTED_USERS=_merge_list(s.value("PROTECTED_USERS"), names))
    return f"SentrAI will never lock {', '.join(names)}."


# 5. Operator name
def _operator(s: SetupChat, answer: str) -> str:
    if answer == "keep":
        return ""
    name = _nonblank(answer, "your name")[:60]
    s.set(CACTAI_OPERATOR=name)
    if s.value("ON_DUTY") == cfg.FIELDS["ON_DUTY"].default:  # still the demo's made-up responder
        s.set(ON_DUTY=name)
    return f"Nice to meet you, {name}."


# 6. Alerts
def _alerts(s: SetupChat, choice: str) -> str:
    s.notes["alerts"] = choice
    if choice == "console":
        s.set(TELEGRAM_BOT_TOKEN="", TELEGRAM_CHAT_ID="", SMTP_HOST="")
        return "Alerts will show in the console and the dashboard only."
    if choice == "telegram":
        s.set(SMTP_HOST="")
    if choice == "email":
        s.set(TELEGRAM_BOT_TOKEN="", TELEGRAM_CHAT_ID="", CACTAI_EMAIL_MODE="always")
    if choice == "both":
        s.set(CACTAI_EMAIL_MODE="backup")
    return ""


def _wants(kind: str) -> Callable[[SetupChat], bool]:
    return lambda s: s.notes.get("alerts") in (kind, "both")


def _telegram_token(s: SetupChat, answer: str) -> str:
    if answer == "keep":
        return ""
    token = _nonblank(answer, "the bot token")
    if not re.fullmatch(r"\d+:[\w-]{20,}", token):
        raise Retry("That doesn't look like a Telegram bot token. It looks like 123456789:ABC... and comes "
                    "from @BotFather.")
    s.set(TELEGRAM_BOT_TOKEN=token)
    return "Got the token."


def _telegram_chat(s: SetupChat, answer: str) -> str:
    if answer == "keep":
        return ""
    chat = _nonblank(answer, "the chat id")
    if not re.fullmatch(r"-?\d+|@\w{4,}", chat):
        raise Retry("A chat id is a number like 123456789 (or -100... for a group), or a channel name like @mychannel.")
    s.set(TELEGRAM_CHAT_ID=chat)
    return "Telegram is set."


def _smtp_host(s: SetupChat, answer: str) -> str:
    if answer == "keep":
        return ""
    host = _nonblank(answer, "the SMTP server")
    if not re.fullmatch(r"[\w.-]+", host):
        raise Retry("Type just the server name, like smtp.gmail.com.")
    s.set(SMTP_HOST=host)
    return ""


def _smtp_port(s: SetupChat, answer: str) -> str:
    port, security = {"587": ("587", "starttls"), "465": ("465", "ssl")}.get(answer, (answer, "starttls"))
    if not port.isdigit():
        raise Retry("Please pick 587 or 465, or type the port number.")
    s.set(SMTP_PORT=port, SMTP_SECURITY=security)
    return ""


def _smtp_user(s: SetupChat, answer: str) -> str:
    if answer == "none":
        s.set(SMTP_USER="", SMTP_PASSWORD="")
    elif answer != "keep":
        s.set(SMTP_USER=_nonblank(answer, "the login"))
    return ""


def _smtp_password(s: SetupChat, answer: str) -> str:
    if answer != "keep":
        s.set(SMTP_PASSWORD=_nonblank(answer, "the password"))
    return ""


def _email_to(s: SetupChat, answer: str) -> str:
    if answer == "keep":
        return "Email is set."
    to = [a for a in re.split(r"[\s,;]+", answer) if a]
    if not to or not all(re.fullmatch(r"[^@\s]+@[^@\s]+\.\w+", a) for a in to):
        raise Retry("Please type one or more email addresses, separated by commas.")
    s.set(ALERT_EMAIL_TO=",".join(to))
    return "Email is set."


# 7. AI model
def _ai_options(s: SetupChat) -> list[Option]:
    keep = []
    if s.current.get(cfg.cactai_llm.GENERIC_KEY_ENV):
        provider = s.current.get("CACTAI_LLM_PROVIDER", "")
        keep = [("keep", f"Keep {cfg.cactai_llm.LABEL.get(provider, provider)}")]
    return keep + [(p, cfg.cactai_llm.LABEL[p]) for p in cfg.cactai_llm.PROVIDERS] + [("none", "No key, skip")]


def _ai(s: SetupChat, choice: str) -> str:
    s.notes["ai"] = choice
    if choice == "none":
        s.set(**{cfg.cactai_llm.GENERIC_KEY_ENV: ""})
        return "No problem: I'll run on fixed playbooks, and chat answers from the core's own explanations."
    if choice != "keep":
        s.set(CACTAI_LLM_PROVIDER=choice)
        if s.current.get("CACTAI_LLM_PROVIDER") != choice:
            s.set(**{cfg.MODEL_ENV: "", "CACTAI_LLM_BASE_URL": "", cfg.cactai_llm.GENERIC_KEY_ENV: ""})
    return ""


def _picked_ai(s: SetupChat) -> bool:
    return s.notes.get("ai") not in (None, "none", "keep")


def _ai_key(s: SetupChat, answer: str) -> str:
    s.set(**{cfg.cactai_llm.GENERIC_KEY_ENV: _nonblank(answer, "the API key")})
    return "Got the key."


def _base_url(s: SetupChat, answer: str) -> str:
    url = _nonblank(answer, "the base URL")
    if not re.match(r"https?://", url):
        raise Retry("The base URL starts with https://, like https://llm.example.com/v1.")
    s.set(CACTAI_LLM_BASE_URL=url)
    return ""


def _model_options(s: SetupChat) -> list[Option]:
    default = cfg.cactai_llm.DEFAULT_MODEL.get(s.value("CACTAI_LLM_PROVIDER"))
    return [("default", f"Use {default}")] if default else []


def _model(s: SetupChat, answer: str) -> str:
    s.set(**{cfg.MODEL_ENV: "" if answer == "default" else _nonblank(answer, "the model name")})
    return "The AI model is set; I'll switch to it as soon as you save."


# 8. Web dashboard access. The field names come from cactai_config; a question is asked only when
# the settings file has that field, so this follows whatever the login and deploy code defines.
WEB = {"host": "CACTAI_DASHBOARD_HOST", "port": "CACTAI_DASHBOARD_PORT", "url": "CACTAI_PUBLIC_URL",
       "email": "CACTAI_DASHBOARD_EMAIL", "password": cfg.PASSWORD_ENV}


def web_fields() -> bool:
    return WEB["host"] in cfg.FIELDS or WEB["port"] in cfg.FIELDS


def _has(name: str) -> Callable[[SetupChat], bool]:
    return lambda s: WEB[name] in cfg.FIELDS


def dashboard_address(s: SetupChat) -> str:
    if s.value(WEB["url"]):
        return s.value(WEB["url"])
    host = s.value(WEB["host"]) or "127.0.0.1"
    where = "this computer only" if host in ("127.0.0.1", "localhost", "::1") else "other computers too"
    return f"port {s.value(WEB['port']) or '8501'}, {where}"


def _web_host(s: SetupChat, choice: str) -> str:
    s.notes["web"] = choice
    s.set(**{WEB["host"]: "127.0.0.1" if choice == "local" else "0.0.0.0"})
    return "" if choice != "local" else "Only this computer will reach the dashboard."


def _web_port(s: SetupChat, answer: str) -> str:
    port = (s.value(WEB["port"]) or "8501") if answer == "keep" else answer
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise Retry("A port is a number from 1 to 65535, like 8501.")
    s.set(**{WEB["port"]: port})
    return ""


def _web_url(s: SetupChat, answer: str) -> str:
    if answer == "none":
        s.set(**{WEB["url"]: ""})
        return ""
    url = _nonblank(answer, "the address").rstrip("/")
    if not re.match(r"https?://", url):
        url = "https://" + url
    if not re.fullmatch(r"https?://[\w.-]+(:\d+)?(/.*)?", url):
        raise Retry("Type an address like console.example.com or https://console.example.com.")
    s.set(**{WEB["url"]: url})
    return f"The dashboard will be at {url}."


def _web_email(s: SetupChat, answer: str) -> str:
    if answer != "keep":
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.\w+", answer.strip()):
            raise Retry("Please type an email address, like admin@example.com.")
        s.set(**{WEB["email"]: answer.strip()})
    return ""


def _web_password(s: SetupChat, answer: str) -> str:
    if answer == "keep":
        return "The dashboard sign-in stays as it is."
    if answer == "none":
        s.set(**{WEB["password"]: ""})
        return "The dashboard opens without a sign-in."
    if len(answer) < 8:
        raise Retry("Please use at least 8 characters.")
    s.set(**{WEB["password"]: answer})  # the dashboard hashes it on save when the config code can
    return "The dashboard sign-in is set."


def _password_options(s: SetupChat) -> list[Option]:
    keep = [("keep", "Keep the current password")] if s.current.get(WEB["password"]) else []
    return keep + ([] if s.notes.get("web") == "network" else [("none", "No sign-in on this computer")])


STEPS: tuple[Step, ...] = (
    Step("kind", lambda s: "First, what does SentrAI guard here?", _kind,
         lambda s: [("sensitive", "Sensitive records (students, patients, payments)"),
                    ("office", "A typical small office or tuition centre"),
                    ("busy", "A busy public site where downtime hurts most"), ("unsure", "Not sure")],
         typed=False, words={"sensitive": {"school", "clinic", "hospital", "bank", "records"},
                             "office": {"office", "small business", "tuition", "tuition centre"},
                             "busy": {"shop", "store", "website", "ecommerce", "busy"},
                             "unsure": {"dunno", "don't know", "not sure", "idk"}}),
    Step("preset", _preset_question, _preset, _preset_options, typed=False,
         words={"yes": YES, **{n: {n} for n in cfg.PRESETS}}),
    Step("logs", lambda s: "Which logs should I watch? Type the folder where your web and login logs are, "
                           "or use the demo lab logs.", _logs,
         lambda s: [("demo", "Use the demo lab logs")] + (
             [("keep", "Keep the current folder")] if s.current.get("CACTAI_LAB_LOGS") != DEMO_LOGS else []),
         words={"demo": {"demo", "lab", "default"}}),
    Step("ips", lambda s: "Is there an IP address SentrAI must never block, like your own admin computer? "
                          "This computer is always protected.", _ips,
         lambda s: [("none", "No, just this computer")], words={"none": NO}),
    Step("users", lambda s: "Are there accounts SentrAI must never lock, like the one you sign in with?", _users,
         lambda s: [("none", "No")], words={"none": NO}),
    Step("operator", lambda s: "What name should appear on your approvals?", _operator,
         lambda s: [("keep", f"Keep \"{s.current['CACTAI_OPERATOR']}\"")]),
    Step("alerts", lambda s: "How should I alert you when something happens?", _alerts,
         lambda s: [("telegram", "Telegram"), ("email", "Email"), ("both", "Telegram, email as backup"),
                    ("console", "Just the dashboard")], typed=False,
         words={"console": {"none", "no", "dashboard", "console"}}),
    Step("tg_token", lambda s: "Paste your Telegram bot token (from @BotFather).", _telegram_token,
         lambda s: _keep(s, "TELEGRAM_BOT_TOKEN", "the saved token"), when=_wants("telegram"), secret=True),
    Step("tg_chat", lambda s: "Which Telegram chat should get the alerts? Type its chat id.", _telegram_chat,
         lambda s: _keep(s, "TELEGRAM_CHAT_ID", s.current.get("TELEGRAM_CHAT_ID", "")), when=_wants("telegram")),
    Step("smtp_host", lambda s: "Which email server sends the alerts? For Gmail it's smtp.gmail.com.", _smtp_host,
         lambda s: _keep(s, "SMTP_HOST", s.current.get("SMTP_HOST", "")), when=_wants("email")),
    Step("smtp_port", lambda s: "Which port does it use? 587 is the usual one.", _smtp_port,
         lambda s: [("587", "587 (STARTTLS)"), ("465", "465 (SSL)")], when=_wants("email")),
    Step("smtp_user", lambda s: "What login does the email server need? Usually your email address.", _smtp_user,
         lambda s: _keep(s, "SMTP_USER", s.current.get("SMTP_USER", "")) + [("none", "No login")],
         when=_wants("email"), words={"none": NO}),
    Step("smtp_password", lambda s: "And its password (for Gmail, an app password).", _smtp_password,
         lambda s: _keep(s, "SMTP_PASSWORD", "the saved password"),
         when=lambda s: _wants("email")(s) and bool(s.value("SMTP_USER")), secret=True),
    Step("email_to", lambda s: "Who should get the alert emails?", _email_to,
         lambda s: _keep(s, "ALERT_EMAIL_TO", s.current.get("ALERT_EMAIL_TO", "")), when=_wants("email")),
    Step("ai", lambda s: "Do you have an AI key? With one I plan responses for your system and answer "
                         "questions in chat; without one SentrAI uses fixed playbooks.", _ai, _ai_options,
         typed=False, words={"none": NO | {"no key"}, "anthropic": {"claude"}}),
    Step("ai_key", lambda s: f"Paste your {cfg.cactai_llm.LABEL[s.value('CACTAI_LLM_PROVIDER')]} API key.",
         _ai_key, when=_picked_ai, secret=True),
    Step("ai_url", lambda s: "What is the service's base URL?", _base_url,
         when=lambda s: _picked_ai(s) and s.value("CACTAI_LLM_PROVIDER") == "compatible"),
    Step("ai_model", lambda s: "Which model should I use?" + (
        "" if _model_options(s) else " This provider has no default, so type its name."), _model, _model_options,
         when=_picked_ai, words={"default": {"default", "yes", "ok"}}),
    Step("web_host", lambda s: "Who should be able to open this dashboard?", _web_host,
         lambda s: [("local", "Only this computer"), ("network", "Other computers too")], when=_has("host"),
         typed=False, words={"local": {"me", "just me", "local", "localhost"},
                             "network": {"network", "everyone", "lan", "internet", "remote"}}),
    Step("web_port", lambda s: "Which port should it use?", _web_port,
         lambda s: [("keep", f"Keep {s.value(WEB['port']) or '8501'}")], when=_has("port")),
    Step("web_url", lambda s: "Does it have a web address people will use, like console.example.com?", _web_url,
         lambda s: [("none", "No web address")], when=lambda s: _has("url")(s) and s.notes.get("web") == "network",
         words={"none": NO}),
    Step("web_email", lambda s: "What email will you sign in to the dashboard with?", _web_email,
         lambda s: _keep(s, WEB["email"], s.current.get(WEB["email"], "")), when=_has("email")),
    Step("web_password", lambda s: "Choose a password for the dashboard sign-in (at least 8 characters).",
         _web_password, _password_options, when=_has("password"), secret=True),
)
