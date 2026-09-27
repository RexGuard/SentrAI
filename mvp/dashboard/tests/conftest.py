import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def fake_core():
    """Start dev/fake_core.py on a free port with autoplay off; yield its base URL."""
    port = _free_port()
    env = {**__import__("os").environ, "FAKE_CORE_PORT": str(port), "FAKE_AUTOPLAY": "0"}
    proc = subprocess.Popen([sys.executable, str(ROOT / "dev" / "fake_core.py")], env=env,
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
