"""CactAI settings file and first-run setup wizard.

Every component already reads its settings from environment variables. This module keeps
those values in one JSON file per machine and, on `load()`, sets each variable that is not
already set. An explicit environment variable therefore always wins over the file.

A machine is "new" when it has no settings file yet. There, `ensure()` walks the user
through one short section per part of the pipeline (collector, classifier, responder,
notifications). Pressing Enter keeps the default, which is exactly what the demo uses.

Run (any venv, stdlib only):
    python cactai_config.py              set up if this is a new machine, then show settings
    python cactai_config.py setup        run the wizard again (current values as defaults)
    python cactai_config.py get NAME     print one value, for scripts
"""
from __future__ import annotations

import getpass
import json
import os
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


@dataclass(frozen=True)
class Section:
    key: str
    title: str
    about: str
    fields: tuple[Field, ...]


SECTIONS = (
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
    Section("responder", "3. Responder", "When CactAI acts, for how long, and what it never touches.", (
        Field("RISK_THRESHOLD", "Risk index (0-100) at which temporary blocks start", "80", int),
        Field("HOTPATCH_TTL_HOURS", "Hours before an automatic block expires", "2", float),
        Field("SLA_HOURS", "Hours a human has to respond before escalation", "2", float),
        Field("PROTECTED_IPS", "IPs never to block (comma-separated)", "127.0.0.1,::1,localhost"),
        Field("PROTECTED_USERS", "Accounts never to lock (comma-separated)"),
        Field("ON_DUTY", "On-duty responder shown in alerts", "John Doe (SEC-409) / Shift Bravo"),
    )),
    Section("notifications", "4. Notifications", "Telegram alerts. Leave blank to print alerts to the console.", (
        Field("TELEGRAM_BOT_TOKEN", "Telegram bot token", secret=True),
        Field("TELEGRAM_CHAT_ID", "Telegram chat id"),
        Field("CACTAI_OPERATOR", "Your name, as shown on approvals", "operator"),
    )),
    Section("ai", "5. AI model", "Cyanide and Scout. Pick a provider and paste its key; "
            "leave the key blank to run on fixed playbooks.", (
        Field("CACTAI_LLM_PROVIDER", "Provider", "anthropic", choices=cactai_llm.PROVIDERS),
        Field("CACTAI_LLM_API_KEY", "API key", secret=True),
        Field("CACTAI_LLM_BASE_URL", "Base URL (only for another OpenAI-compatible service)"),
        Field("CACTAI_LLM_MODEL", "Model name, blank for the provider's default"),
    )),
)
FIELDS = {f.env: f for s in SECTIONS for f in s.fields}
MODEL_ENV = "CACTAI_LLM_MODEL"


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


def read() -> dict[str, str]:
    """The saved values as a flat {ENV_NAME: value} dict ({} on a new machine)."""
    try:
        data = json.loads(config_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    values = {k: str(v) for section in data.values() if isinstance(section, dict) for k, v in section.items()}
    return _one_ai_key(values) if values else values


def save(values: dict[str, str]) -> Path:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {s.key: {f.env: values.get(f.env, f.default) for f in s.fields} for s in SECTIONS}
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


_LOADED: dict[str, str] = {}  # what load() put into os.environ, so a reload can replace it


def load(refresh: bool = False) -> dict[str, str]:
    """Copy saved values into os.environ, without overriding anything already set.

    refresh=True first takes back the values an earlier load() copied in (unless something else
    changed them since), so edits saved while CactAI runs win over the old saved values.
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
    """
    ask, ask_secret = ask or input, ask_secret or getpass.getpass
    current = {f.env: f.default for f in FIELDS.values()} | read()
    say("\nCactAI setup. Press Enter to keep the value in [brackets].")
    values = {}
    for section in SECTIONS:
        say(f"\n{section.title}: {section.about}")
        for f in section.fields:
            shown = ("set" if current[f.env] else "not set") if f.secret else current[f.env]
            prompt = f.prompt
            if f.choices:
                for n, choice in enumerate(f.choices, 1):
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
    return values


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


def main(argv: list[str]) -> int:
    if argv[:1] == ["get"] and len(argv) == 2:
        field = FIELDS.get(argv[1])
        print(os.environ.get(argv[1]) or read().get(argv[1]) or (field.default if field else ""))
        return 0
    if argv[:1] == ["setup"]:
        setup()
        return 0
    if argv:
        print(__doc__)
        return 2
    ensure()
    values = read()
    print(f"CactAI settings ({config_path()}):")
    for f in FIELDS.values():
        value = values.get(f.env, f.default)
        print(f"  {f.env:<22} {('***' if value else '') if f.secret else value}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
