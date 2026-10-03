"""SentrAI settings file and first-run setup wizard.

Every component already reads its settings from environment variables. This module keeps
those values in one JSON file per machine and, on `load()`, sets each variable that is not
already set. An explicit environment variable therefore always wins over the file.

A machine is "new" when it has no settings file yet. There, `ensure()` walks the user
through one short section per part of the pipeline (collector, classifier, responder,
notifications). Pressing Enter keeps the default, which is exactly what the demo uses.

The security values (when an event counts as an attack, when SentrAI acts, for how long) come
from a preset: Strict, Moderate or Balanced, or Advanced to set each value yourself. The saved
file keeps the preset's name and every value. Values that no longer match their preset are saved
as Advanced (see `settle_preset()`).

Run (any venv, stdlib only):
    python cactai_config.py              set up if this is a new machine, then show settings
    python cactai_config.py setup        run the wizard again (current values as defaults)
    python cactai_config.py get NAME     print one value, for scripts
    python cactai_config.py token        print the core API token (made and saved on first use)
    python cactai_config.py admin        make the dashboard sign-in if there is none (prints the password once)
    python cactai_config.py admin --email you@example.com --reset   new email and a new password
    python cactai_config.py admin --password-stdin                  set the password read from stdin
"""
from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import cactai_llm

MVP_DIR = Path(__file__).resolve().parent


def config_path() -> Path:
    return Path(os.environ.get("CACTAI_CONFIG") or Path.home() / ".cactai" / "config.json")


@dataclass(frozen=True)
class Field:
    env: str  # the environment variable the components already read
    prompt: str
    default: str = ""
    kind: type = str  # str, int or float; used only to validate the answer
    secret: bool = False
    choices: tuple[str, ...] = ()  # when set, the answer must be one of these
    generated: bool = False  # never asked: the wizard keeps the saved value or makes a new one
    hashed: bool = False  # a password: asked, but only its salted hash is saved


@dataclass(frozen=True)
class Section:
    key: str
    title: str
    about: str
    fields: tuple[Field, ...]


PRESET_ENV = "CACTAI_PRESET"
DEFAULT_PRESET = "moderate"  # the values the demo was built and recorded with


@dataclass(frozen=True)
class Preset:
    label: str
    about: str
    values: dict[str, str]


# Ordered from most to least cautious. Each preset sets every field listed in PRESET_FIELDS.
PRESETS = {
    "strict": Preset("Strict", "Acts early and holds longer. For sensitive data; expect more alerts and "
                     "some false positives.", {
        "BRUTE_FORCE_COUNT": "3", "BRUTE_FORCE_WINDOW_S": "120", "EXPORT_ROWS_THRESHOLD": "50",
        "RISK_THRESHOLD": "65", "HOTPATCH_TTL_HOURS": "4", "SLA_HOURS": "1", "NEEDLE_MIN_CONFIDENCE": "0.5"}),
    "moderate": Preset("Moderate", "The recommended default: clear attacks are contained quickly, "
                       "unclear ones wait for a person.", {
        "BRUTE_FORCE_COUNT": "5", "BRUTE_FORCE_WINDOW_S": "60", "EXPORT_ROWS_THRESHOLD": "100",
        "RISK_THRESHOLD": "80", "HOTPATCH_TTL_HOURS": "2", "SLA_HOURS": "2", "NEEDLE_MIN_CONFIDENCE": "0.6"}),
    "balanced": Preset("Balanced", "Puts day-to-day operations first: acts only on strong evidence, "
                       "blocks briefly and gives people more time.", {
        "BRUTE_FORCE_COUNT": "8", "BRUTE_FORCE_WINDOW_S": "60", "EXPORT_ROWS_THRESHOLD": "250",
        "RISK_THRESHOLD": "90", "HOTPATCH_TTL_HOURS": "1", "SLA_HOURS": "4", "NEEDLE_MIN_CONFIDENCE": "0.75"}),
}
PRESET_FIELDS = tuple(PRESETS[DEFAULT_PRESET].values)
ADVANCED = "advanced"  # not a preset: every value is set by hand
ADVANCED_ABOUT = "Set each detection and response value yourself."
PRESET_CHOICES = (*PRESETS, ADVANCED)

SECTIONS = (
    Section("preset", "Security preset", "One choice sets the detection and response values below.", (
        Field(PRESET_ENV, "Preset", DEFAULT_PRESET, choices=PRESET_CHOICES),
    )),
    Section("collector", "1. Collector", "Where the logs are and where to send events.", (
        Field("CACTAI_LAB_LOGS", "Logs directory", str(MVP_DIR / "lab" / "logs")),
        Field("CACTAI_LOG_ACCESS", "Web access log file name", "access.jsonl"),
        Field("CACTAI_LOG_AUTH", "Login log file name", "auth.jsonl"),
        Field("CACTAI_LOG_DB", "Database log file name", "db.jsonl"),
        Field("CACTAI_LOG_OS", "OS / process log file name", "os.jsonl"),
        Field("CACTAI_CORE_URL", "Core URL", "http://127.0.0.1:8000"),
    )),
    Section("classifier", "2. Classifier", "When an event counts as an attack.", (
        Field("BRUTE_FORCE_COUNT", "Failed logins that count as brute force", "5", int),
        Field("BRUTE_FORCE_WINDOW_S", "...within how many seconds", "60", float),
        Field("EXPORT_ROWS_THRESHOLD", "Rows in one export that count as bulk exfiltration", "100", int),
        Field("TYPESAFE_API_KEY", "TypeSafe (Jev) API key, blank to use rules only", secret=True),
    )),
    Section("responder", "3. Responder", "When SentrAI acts, for how long, and what it never touches.", (
        Field("RISK_THRESHOLD", "Risk index (0-100) at which temporary blocks start", "80", int),
        Field("HOTPATCH_TTL_HOURS", "Hours before an automatic block expires", "2", float),
        Field("SLA_HOURS", "Hours a human has to respond before escalation", "2", float),
        Field("NEEDLE_MIN_CONFIDENCE", "AI confidence (0-1) needed before acting without a person", "0.6", float),
        Field("PROTECTED_IPS", "IPs never to block (comma-separated)", "127.0.0.1,::1,localhost"),
        Field("PROTECTED_USERS", "Accounts never to lock (comma-separated)"),
        Field("ON_DUTY", "On-duty responder shown in alerts", "John Doe (SEC-409) / Shift Bravo"),
    )),
    Section("notifications", "4. Notifications", "Telegram alerts, with email as the backup. "
            "Leave both blank to print alerts to the console.", (
        Field("TELEGRAM_BOT_TOKEN", "Telegram bot token", secret=True),
        Field("TELEGRAM_CHAT_ID", "Telegram chat id"),
        Field("CACTAI_OPERATOR", "Your name, as shown on approvals", "operator"),
        Field("SMTP_HOST", "Email: SMTP server, blank for no email alerts"),
        Field("SMTP_PORT", "Email: SMTP port (587 STARTTLS, 465 SSL)", "587", int),
        Field("SMTP_SECURITY", "Email: connection security", "starttls", choices=("starttls", "ssl", "none")),
        Field("SMTP_USER", "Email: SMTP login, blank if none"),
        Field("SMTP_PASSWORD", "Email: SMTP password or app password", secret=True),
        Field("ALERT_EMAIL_FROM", "Email: sender address, blank to use the login"),
        Field("ALERT_EMAIL_TO", "Email: recipients (comma-separated)"),
        Field("CACTAI_EMAIL_MODE", "Email: send when Telegram fails, or always", "backup",
              choices=("backup", "always")),
    )),
    Section("ai", "5. AI model", "Cyanide and Scout. Pick a provider and paste its key; "
            "leave the key blank to run on fixed playbooks.", (
        Field("CACTAI_LLM_PROVIDER", "Provider", "anthropic", choices=cactai_llm.PROVIDERS),
        Field("CACTAI_LLM_API_KEY", "API key", secret=True),
        Field("CACTAI_LLM_BASE_URL", "Base URL (only for another OpenAI-compatible service)"),
        Field("CACTAI_LLM_MODEL", "Model name, blank for the provider's default"),
    )),
    Section("access", "6. Access", "Who may use the core API and the dashboard.", (
        Field("CACTAI_API_TOKEN", "Core API token (shared by the collector, dashboard and Telegram bot)",
              secret=True, generated=True),
        Field("CACTAI_DASHBOARD_EMAIL", "Dashboard sign-in email", "admin@sentrai.local"),
        Field("CACTAI_DASHBOARD_PASSWORD_HASH", "Dashboard password (blank keeps it, or makes one on a new machine)",
              secret=True, hashed=True),
    )),
)
FIELDS = {f.env: f for s in SECTIONS for f in s.fields}
EMAIL_FIELDS = ("SMTP_PORT", "SMTP_SECURITY", "SMTP_USER", "SMTP_PASSWORD", "ALERT_EMAIL_FROM", "ALERT_EMAIL_TO",
                "CACTAI_EMAIL_MODE")  # asked only when SMTP_HOST is set
MODEL_ENV = "CACTAI_LLM_MODEL"
TOKEN_ENV = "CACTAI_API_TOKEN"
PASSWORD_ENV = "CACTAI_DASHBOARD_PASSWORD"  # before the sign-in had an email: a plain password (still accepted)
EMAIL_ENV = "CACTAI_DASHBOARD_EMAIL"
HASH_ENV = "CACTAI_DASHBOARD_PASSWORD_HASH"
LOGIN_ENV = "CACTAI_DASHBOARD_LOGIN"  # "off" opens the dashboard without signing in (local testing only)
MIN_PASSWORD = 8
_ITERATIONS = 600_000


def hash_password(password: str) -> str:
    """A salted PBKDF2-SHA256 hash, stored as pbkdf2_sha256$iterations$salt$hash (hex)."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return f"pbkdf2_sha256${_ITERATIONS}${salt.hex()}${digest.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt, digest = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got.hex(), digest)


def new_password() -> str:
    return secrets.token_urlsafe(12)


def _migrate_password(values: dict[str, str]) -> dict[str, str]:
    """Settings saved with a plain dashboard password: keep only its hash."""
    plain = values.pop(PASSWORD_ENV, "")
    if plain and not values.get(HASH_ENV):
        values[HASH_ENV] = hash_password(plain)
    return values


def _one_ai_key(values: dict[str, str]) -> dict[str, str]:
    """Settings saved before the AI section had one key field: keep the key of the provider in use."""
    legacy = {p: values.pop(env) for p, env in cactai_llm.KEY_ENV.items()
              if env != cactai_llm.GENERIC_KEY_ENV and env in values}
    legacy = {p: k for p, k in legacy.items() if k}
    provider = values.get("CACTAI_LLM_PROVIDER", "")
    if provider in cactai_llm.PROVIDERS and provider != "compatible" and provider in legacy:
        values[cactai_llm.GENERIC_KEY_ENV] = legacy[provider]
    elif provider in ("", "auto"):
        if legacy:  # what "auto" used to pick: the first provider with a key
            provider = next(iter(legacy))
            values[cactai_llm.GENERIC_KEY_ENV] = legacy[provider]
        elif values.get(cactai_llm.GENERIC_KEY_ENV):
            provider = "compatible"
        values["CACTAI_LLM_PROVIDER"] = provider if provider != "auto" else FIELDS["CACTAI_LLM_PROVIDER"].default
    return values


def preset_values(name: str) -> dict[str, str]:
    """The values a preset sets (the default preset's for an unknown name)."""
    return dict(PRESETS.get(name, PRESETS[DEFAULT_PRESET]).values)


def _same(a: str, b: str) -> bool:
    try:
        return float(a) == float(b)
    except ValueError:
        return a.strip() == b.strip()


def preset_label(name: str) -> str:
    return PRESETS[name].label if name in PRESETS else "Advanced"


def overrides(values: dict[str, str]) -> dict[str, str]:
    """The preset-controlled values that differ from the chosen preset ({} for Advanced, which has none)."""
    name = values.get(PRESET_ENV, DEFAULT_PRESET)
    if name == ADVANCED:
        return {}
    base = preset_values(name)
    return {env: values[env] for env in PRESET_FIELDS if env in values and not _same(values[env], base[env])}


def settle_preset(values: dict[str, str]) -> dict[str, str]:
    """Name the preset Advanced when its values were changed by hand (or were saved before presets existed)."""
    if values.get(PRESET_ENV) not in PRESET_CHOICES:
        values[PRESET_ENV] = DEFAULT_PRESET
    if overrides(values):
        values[PRESET_ENV] = ADVANCED
    return values


def describe(values: dict[str, str]) -> list[tuple[str, tuple[str, ...]]]:
    """The preset-controlled values in plain words, each with the fields it shows, for summaries."""
    v = {env: values.get(env, FIELDS[env].default) for env in PRESET_FIELDS}
    return [
        (f"brute force at {v['BRUTE_FORCE_COUNT']} failed logins in {v['BRUTE_FORCE_WINDOW_S']} s",
         ("BRUTE_FORCE_COUNT", "BRUTE_FORCE_WINDOW_S")),
        (f"bulk export at {v['EXPORT_ROWS_THRESHOLD']} rows", ("EXPORT_ROWS_THRESHOLD",)),
        (f"acts at risk {v['RISK_THRESHOLD']}", ("RISK_THRESHOLD",)),
        (f"blocks last {v['HOTPATCH_TTL_HOURS']} h", ("HOTPATCH_TTL_HOURS",)),
        (f"people have {v['SLA_HOURS']} h to respond", ("SLA_HOURS",)),
        (f"acts alone only at {v['NEEDLE_MIN_CONFIDENCE']} AI confidence or more", ("NEEDLE_MIN_CONFIDENCE",)),
    ]


def read() -> dict[str, str]:
    """The saved values as a flat {ENV_NAME: value} dict ({} on a new machine)."""
    try:
        data = json.loads(config_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    values = {k: str(v) for key, section in data.items() if isinstance(section, dict) and key != APPEARANCE_KEY
              for k, v in section.items()}
    return settle_preset(_one_ai_key(_migrate_password(values))) if values else values


def save(values: dict[str, str]) -> Path:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    values = settle_preset(dict(values))
    for keep in (TOKEN_ENV, HASH_ENV):  # a form that leaves the token or password out must not wipe it
        if not values.get(keep):
            values[keep] = read().get(keep, "")
    data = {s.key: {f.env: values.get(f.env, f.default) for f in s.fields} for s in SECTIONS}
    for keep in (SETUP_DONE_KEY, APPEARANCE_KEY):  # not settings (read() skips them), so carry them over
        if _raw().get(keep):
            data[keep] = _raw()[keep]
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


SETUP_DONE_KEY = "setup_done"  # top-level marker: how setup was finished (wizard, dashboard or chat)
APPEARANCE_KEY = "appearance"  # the console's theme and accent: only the dashboard reads it


def appearance() -> dict[str, str]:
    """{"theme": "dark" | "light", "accent": "mono" | a preset name | "#rrggbb"}; {} until one is saved."""
    saved = _raw().get(APPEARANCE_KEY)
    return {k: str(v) for k, v in saved.items() if k in ("theme", "accent")} if isinstance(saved, dict) else {}


def save_appearance(theme: str, accent: str) -> Path:
    """Saved at once, without touching the other settings."""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _raw()
    data[APPEARANCE_KEY] = {"theme": theme, "accent": accent}
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def _raw() -> dict:
    try:
        data = json.loads(config_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def setup_done() -> bool:
    """True once someone has set this machine up: the wizard, the Configuration page or the Chat page
    saved, or the saved values differ from the defaults (files written before the marker existed).
    The access section does not count: the launchers fill it in by themselves (API token, sign-in)."""
    if _raw().get(SETUP_DONE_KEY):
        return True
    values = read()
    return any(not _same(values.get(f.env, f.default), f.default)
               for s in SECTIONS if s.key != "access" for f in s.fields if f.env in values)


def mark_setup_done(how: str) -> None:
    path = config_path()
    data = _raw()
    if not data:
        save({})
        data = _raw()
    data[SETUP_DONE_KEY] = how
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


_LOADED: dict[str, str] = {}  # what load() put into os.environ, so a reload can replace it


def load(refresh: bool = False) -> dict[str, str]:
    """Copy saved values into os.environ, without overriding anything already set.

    refresh=True first takes back the values an earlier load() copied in (unless something else
    changed them since), so edits saved while SentrAI runs win over the old saved values.
    """
    if refresh:
        for name, value in _LOADED.items():
            if os.environ.get(name) == value:
                del os.environ[name]
        _LOADED.clear()
    values = read()
    for name, value in values.items():
        if value != "" and name not in os.environ:
            os.environ[name] = _LOADED[name] = value
    return values


def new_token() -> str:
    return secrets.token_urlsafe(32)


def api_token() -> str:
    """The token every client sends to the core, and the core requires.

    An explicit CACTAI_API_TOKEN wins. Otherwise the saved one is used, and a machine without
    one gets a new token saved to the settings file, so every component finds the same value.
    """
    token = os.environ.get(TOKEN_ENV, "").strip()
    if token:
        return token
    values = read()
    if not values.get(TOKEN_ENV):
        values[TOKEN_ENV] = new_token()
        save(values)
        values = read()  # another component may have saved one at the same moment; use what is on disk
    return values[TOKEN_ENV]


def _own_env(name: str) -> str:
    """An environment variable set outside the settings file ("" when load() copied it from the file)."""
    value = os.environ.get(name, "")
    return "" if value and _LOADED.get(name) == value else value


def dashboard_login() -> dict[str, str]:
    """Who may sign in to the dashboard, read fresh so a changed password applies without a restart.

    Returns {"email", "hash", "plain"}; "plain" is a CACTAI_DASHBOARD_PASSWORD set in the environment.
    An environment variable wins over the settings file, as everywhere else.
    """
    values = read()
    return {"email": _own_env(EMAIL_ENV) or values.get(EMAIL_ENV) or FIELDS[EMAIL_ENV].default,
            "hash": _own_env(HASH_ENV) or values.get(HASH_ENV, ""),
            "plain": _own_env(PASSWORD_ENV)}


def login_required() -> bool:
    return os.environ.get(LOGIN_ENV, "").strip().lower() not in ("off", "0", "no", "false")


def ensure_admin(email: str = "", reset: bool = False, password: str = "") -> tuple[str, str]:
    """Make sure the dashboard has a sign-in. Returns (email, new password), password "" when one was kept.

    A given password (at least MIN_PASSWORD characters, else ValueError) is saved as a hash and
    returned. Otherwise a new machine or reset=True gets a random one. Any setup flow (the wizard,
    install.sh, a chat) can call this with what it asked for.
    """
    if password and len(password) < MIN_PASSWORD:
        raise ValueError(f"the password needs at least {MIN_PASSWORD} characters")
    if email and "@" not in email:
        raise ValueError("the sign-in email needs an @")
    values = {f.env: f.default for f in FIELDS.values()} | read()
    changed = False
    if email and email != values.get(EMAIL_ENV):
        values[EMAIL_ENV], changed = email, True
    if password or reset or not values.get(HASH_ENV):
        password = password or new_password()
        values[HASH_ENV], changed = hash_password(password), True
    if changed or not config_path().exists():
        save(values)
    return values[EMAIL_ENV], password


def valid(field: Field, answer: str) -> bool:
    """True when the answer parses as the field's type and is one of its choices, if it has any."""
    if field.choices and answer not in field.choices:
        return False
    try:
        field.kind(answer)
        return True
    except ValueError:
        return False


def fetch_models(values: dict[str, str]) -> list[str]:
    """The models the chosen provider offers for the key in these settings (raises LLMError)."""
    return cactai_llm.list_models(values.get("CACTAI_LLM_PROVIDER", ""), values.get(cactai_llm.GENERIC_KEY_ENV, ""),
                                  values.get("CACTAI_LLM_BASE_URL") or None)


def wizard(ask: Callable[[str], str] | None = None, ask_secret: Callable[[str], str] | None = None,
           say: Callable[[str], None] = print, models: Callable[[dict[str, str]], list[str]] = fetch_models,
           ) -> dict[str, str]:
    """Ask for every setting, one section per part. Enter keeps the value shown in brackets.

    A field with choices shows a numbered list; the model question takes "?" to list the
    models the key can use. `models` is replaceable for tests.

    A preset fills the detection and response values without asking them; Advanced asks each
    one, offering the values in use now.
    """
    ask, ask_secret = ask or input, ask_secret or getpass.getpass
    current = {f.env: f.default for f in FIELDS.values()} | read()
    say("\nSentrAI setup. Press Enter to keep the value in [brackets].")
    values: dict[str, str] = {}
    preset, advanced = preset_values(DEFAULT_PRESET), False
    for section in SECTIONS:
        say(f"\n{section.title}: {section.about}")
        for f in section.fields:
            if f.env in PRESET_FIELDS and not advanced:
                values[f.env] = preset[f.env]
                continue
            if f.env in EMAIL_FIELDS and not values.get("SMTP_HOST"):
                values[f.env] = current[f.env]  # no SMTP server, so the other email questions are skipped
                continue
            if f.generated:
                values[f.env] = current[f.env] or new_token()
                say(f"  {f.prompt}: {'kept' if current[f.env] else 'generated'} (python cactai_config.py token shows it)")
                continue
            if f.hashed:
                values[f.env] = _ask_password(f, current[f.env], ask_secret, say)
                continue
            shown = ("set" if current[f.env] else "not set") if f.secret else current[f.env]
            prompt = f.prompt
            if f.choices:
                for n, choice in enumerate(f.choices, 1):
                    if f.env == PRESET_ENV:
                        say(f"    {n}. {preset_label(choice)}: {PRESETS[choice].about if choice in PRESETS else ADVANCED_ABOUT}")
                    else:
                        say(f"    {n}. {cactai_llm.LABEL.get(choice, choice)}")
                prompt += " (number)"
            listed: list[str] = []
            if f.env == MODEL_ENV:
                prompt += ", or ? to list the available models"
            while True:
                answer = (ask_secret if f.secret else ask)(f"  {prompt} [{shown}]: ").strip()
                if f.env == MODEL_ENV and answer == "?":
                    try:
                        listed = models(values)
                    except cactai_llm.LLMError as e:
                        say(f"    Could not list the models: {e}.")
                        continue
                    for n, name in enumerate(listed, 1):
                        say(f"    {n}. {name}")
                    if not listed:
                        say("    The service listed no models; type the model name.")
                    continue
                answer = answer or current[f.env]
                options = f.choices or tuple(listed)
                if answer.isdigit() and options and 1 <= int(answer) <= len(options):
                    answer = options[int(answer) - 1]
                if valid(f, answer):
                    break
                say("    Please pick one of the numbers above." if f.choices else "    Please enter a number.")
            values[f.env] = answer
            if f.env == PRESET_ENV:
                advanced = answer == ADVANCED
                if not advanced:
                    preset = preset_values(answer)
                    say("    " + "; ".join(text for text, _ in describe(preset)) + ".")
    return values


def _ask_password(field: Field, stored: str, ask_secret: Callable[[str], str], say: Callable[[str], None]) -> str:
    """Ask for a new password twice; blank keeps the saved one or makes one. Returns the hash to save."""
    while True:
        typed = ask_secret(f"  {field.prompt} [{'set' if stored else 'not set'}]: ")
        if not typed:
            if stored:
                return stored
            made = new_password()
            say(f"    Generated password: {made}  (write it down; it is saved only as a hash)")
            return hash_password(made)
        if len(typed) < MIN_PASSWORD:
            say(f"    Use at least {MIN_PASSWORD} characters.")
            continue
        if ask_secret("  Type it again: ") != typed:
            say("    The two passwords differ; try again.")
            continue
        return hash_password(typed)


def ensure(interactive: bool | None = None) -> dict[str, str]:
    """Run the wizard on a new machine (when someone is at the keyboard), then load()."""
    if interactive is None:
        interactive = sys.stdin.isatty()
    if interactive and not config_path().exists():
        print(f"[cactai] No settings found at {config_path()}; this looks like a new machine.")
        setup()
        print("[cactai] Change them any time with: python cactai_config.py setup")
    return load()


def setup() -> None:
    """Run the wizard and save. Ctrl+C saves nothing and exits."""
    try:
        values = wizard()
    except (KeyboardInterrupt, EOFError):
        print("\nSetup cancelled; nothing saved.")
        raise SystemExit(1)
    print(f"[cactai] Saved to {save(values)}.")
    mark_setup_done("wizard")


def main(argv: list[str]) -> int:
    if argv[:1] == ["get"] and len(argv) == 2:
        field = FIELDS.get(argv[1])
        print(os.environ.get(argv[1]) or read().get(argv[1]) or (field.default if field else ""))
        return 0
    if argv == ["token"]:
        print(api_token())
        return 0
    if argv[:1] == ["admin"]:
        rest, email, reset, typed = argv[1:], "", False, ""
        while rest:
            if rest[0] == "--email" and len(rest) > 1 and "@" in rest[1]:
                email, rest = rest[1].strip(), rest[2:]
            elif rest[0] == "--reset":
                reset, rest = True, rest[1:]
            elif rest[0] == "--password-stdin":
                typed, rest = sys.stdin.readline().rstrip("\r\n"), rest[1:]
            else:
                print("usage: python cactai_config.py admin [--email you@example.com] [--reset | --password-stdin]")
                return 2
        try:
            email, password = ensure_admin(email, reset, typed)
        except ValueError as e:
            print(f"Dashboard sign-in not changed: {e}.", file=sys.stderr)
            return 2
        if typed:
            print(f"Dashboard sign-in: {email}  (the password you chose)")
        elif password:
            print(f"Dashboard sign-in: {email}  password: {password}")
            print("  (shown once: write it down. Only its hash is saved; admin --reset makes a new one)")
        else:
            print(f"Dashboard sign-in: {email}  (password already set; admin --reset makes a new one)")
        return 0
    if argv[:1] == ["setup"]:
        setup()
        return 0
    if argv:
        print(__doc__)
        return 2
    ensure()
    values = read()
    print(f"SentrAI settings ({config_path()}):")
    for f in FIELDS.values():
        value = values.get(f.env, f.default)
        print(f"  {f.env:<22} {('***' if value else '') if f.secret else value}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
