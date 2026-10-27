import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.append(str(ROOT.parent))  # sentrai_config and sentrai_extensions, as notifier.py does
os.environ["SENTRAI_CONFIG"] = str(ROOT / "tests" / "no-config.json")  # ignore this machine's saved settings
os.environ["SENTRAI_API_TOKEN"] = "test-token"  # never generate (and save) a real token from tests
for _name in ("SLACK_WEBHOOK_URL", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "SENTRAI_EXTENSIONS",
              "SENTRAI_EXTENSIONS_DIR"):
    os.environ.pop(_name, None)  # never reach a real Telegram or Slack, nor this machine's extension choices
FAKE = ROOT.parent / "dashboard" / "dev" / "fake_core.py"
# fake_core needs fastapi/uvicorn, which live in the dashboard venv (not the notifier's).
FAKE_PY = ROOT.parent / "dashboard" / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


@pytest.fixture(scope="module")
def fake_core():
    if not FAKE.exists() or not FAKE_PY.exists():
        pytest.skip("dashboard venv / fake_core.py not available")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = {**os.environ, "FAKE_CORE_PORT": str(port), "FAKE_AUTOPLAY": "0"}
    proc = subprocess.Popen([str(FAKE_PY), str(FAKE)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if requests.get(url + "/health", timeout=0.5).ok:
                break
        except requests.RequestException:
            time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("fake core did not start")
    yield url
    proc.kill()
    proc.wait()
