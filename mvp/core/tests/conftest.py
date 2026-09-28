import os
import tempfile
from pathlib import Path

# Must run before app.main is imported (it builds a module-level app).
_TMP = Path(tempfile.mkdtemp(prefix="cactai-test-"))
os.environ["CACTAI_DB"] = str(_TMP / "import.db")
os.environ["CACTAI_BACKGROUND"] = "0"
os.environ["CACTAI_CONFIG"] = str(Path(_TMP) / "no-config.json")  # ignore this machine's saved settings
os.environ.pop("TYPESAFE_API_KEY", None)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture
def client(tmp_path):
    settings = Settings(db_path=tmp_path / "cactai.db", background=False, demo_speed=60.0)
    app = create_app(settings)
    with TestClient(app) as c:
        c.core = app.state.core  # type: ignore[attr-defined]
        yield c


def ev(n, raw, ip="203.0.113.45", user="admin", layer="web", crit=1.5, host="web-01", source="flask_auth"):
    return {
        "event_id": f"evt-test-{n}",
        "timestamp": "2026-09-29T14:00:%02d+08:00" % (n % 60),
        "host": host,
        "layer": layer,
        "source": source,
        "src_ip": ip,
        "user": user,
        "raw": raw,
        "asset_criticality": crit,
    }


def brute_force(client, ip="203.0.113.45", start=0, count=5):
    return [client.post("/events", json=ev(start + i, f"POST /login 401 user=admin", ip=ip)).json() for i in range(count)]
