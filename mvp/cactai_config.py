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
    Section("ai", "5. AI model", "Cyanide and Scout. Set at least one key; leave all blank to run on fixed playbooks.", (
        Field("CACTAI_LLM_PROVIDER", "Provider: auto, anthropic, openai, deepseek, commandcode or compatible", "auto"),
        Field("ANTHROPIC_API_KEY", "Anthropic (Claude) API key", secret=True),
        Field("OPENAI_API_KEY", "OpenAI API key", secret=True),
        Field("DEEPSEEK_API_KEY", "DeepSeek API key", secret=True),
        Field("COMMANDCODE_API_KEY", "Command Code API key (also set the model name below)", secret=True),
        Field("CACTAI_LLM_API_KEY", "Other OpenAI-compatible service: API key", secret=True),
        Field("CACTAI_LLM_BASE_URL", "Other OpenAI-compatible service: base URL"),
        Field("CACTAI_LLM_MODEL", "Model name, blank for the provider's default"),
    )),
)
FIELDS = {f.env: f for s in SECTIONS for f in s.fields}


def read() -> dict[str, str]:
    """The saved values as a flat {ENV_NAME: value} dict ({} on a new machine)."""
    try:
        data = json.loads(config_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    return {k: str(v) for section in data.values() if isinstance(section, dict) for k, v in section.items()}


def save(values: dict[str, str]) -> Path:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {s.key: {f.env: values.get(f.env, f.default) for f in s.fields} for s in SECTIONS}
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def load() -> dict[str, str]:
    """Copy saved values into os.environ, without overriding anything already set."""
    values = read()
    for name, value in values.items():
        if value != "":
            os.environ.setdefault(name, value)
    return values


def valid(field: Field, answer: str) -> bool:
    """True when the answer parses as the field's type (always true for text)."""
    try:
        field.kind(answer)
        return True
    except ValueError:
        return False


def wizard(ask: Callable[[str], str] | None = None, ask_secret: Callable[[str], str] | None = None,
           say: Callable[[str], None] = print) -> dict[str, str]:
    """Ask for every setting, one section per part. Enter keeps the value shown in brackets."""
    ask, ask_secret = ask or input, ask_secret or getpass.getpass
    current = {f.env: f.default for f in FIELDS.values()} | read()
    say("\nCactAI setup. Press Enter to keep the value in [brackets].")
    values = {}
    for section in SECTIONS:
        say(f"\n{section.title}: {section.about}")
        for f in section.fields:
            shown = ("set" if current[f.env] else "not set") if f.secret else current[f.env]
            while True:
                answer = (ask_secret if f.secret else ask)(f"  {f.prompt} [{shown}]: ").strip()
                answer = answer or current[f.env]
                if valid(f, answer):
                    break
                say("    Please enter a number.")
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
