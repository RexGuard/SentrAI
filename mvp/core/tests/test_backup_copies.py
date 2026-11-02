"""Backup copies on other machines: sealed, relayed by the panel, kept by machines that cannot open them."""

import base64
import json
import sys
import tarfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import backup_copies, sealed
from app.config import Settings
from app.main import create_app

from .conftest import AUTH
from .test_fleet import as_agent, join

try:  # the agent's side runs here against the real panel; the core's venv has no requests (not needed for this)
    import requests  # noqa: F401
except ImportError:
    import types

    _stub = types.ModuleType("requests")
    _stub.RequestException = type("RequestException", (Exception,), {})
    _stub.Session = object
    sys.modules["requests"] = _stub
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lab"))
from agent import tasks  # noqa: E402


# ------------------------------------------------------------------ sealing
def test_seal_round_trip_and_recovery_code(tmp_path):
    src = tmp_path / "b.tar.gz"
    src.write_bytes(bytes(range(256)) * 9000)  # over one block
    key = sealed.new_key()
    sealed_sha = sealed.seal(src, tmp_path / "b.sbk", key)
    assert sealed_sha == sealed.sha256_file(tmp_path / "b.sbk")
    assert src.read_bytes()[:4096] not in (tmp_path / "b.sbk").read_bytes()
    code = sealed.to_code(key)
    assert len(code.replace("-", "")) == 52 and sealed.from_code(code.lower()) == key
    sealed.unseal(tmp_path / "b.sbk", tmp_path / "out.tar.gz", sealed.from_code(code))
    assert (tmp_path / "out.tar.gz").read_bytes() == src.read_bytes()


def test_changed_copy_or_wrong_key_unpacks_nothing(tmp_path):
    src = tmp_path / "b.tar.gz"
    src.write_bytes(b"secret site files " * 1000)
    key = sealed.new_key()
    sealed.seal(src, tmp_path / "b.sbk", key)
    with pytest.raises(sealed.SealError, match="another key"):
        sealed.unseal(tmp_path / "b.sbk", tmp_path / "x", sealed.new_key())
    raw = bytearray((tmp_path / "b.sbk").read_bytes())
    raw[100] ^= 1
    (tmp_path / "b.sbk").write_bytes(bytes(raw))
    with pytest.raises(sealed.SealError, match="changed"):
        sealed.unseal(tmp_path / "b.sbk", tmp_path / "x", key)
    (tmp_path / "b.sbk").write_bytes(bytes(raw[:200]))
    with pytest.raises(sealed.SealError):
        sealed.unseal(tmp_path / "b.sbk", tmp_path / "x", key)
    assert not (tmp_path / "x").exists()


def test_cli_opens_a_copy(tmp_path, capsys):
    src = tmp_path / "b.tar.gz"
    src.write_bytes(b"x" * 5000)
    key = sealed.new_key()
    sealed.seal(src, tmp_path / "b.sbk", key)
    assert sealed.main(["open", str(tmp_path / "b.sbk"), str(tmp_path / "o.tar.gz"), "--code", sealed.to_code(key)]) == 0
    assert (tmp_path / "o.tar.gz").read_bytes() == src.read_bytes()
    assert sealed.main(["open", str(tmp_path / "b.sbk"), str(tmp_path / "p"), "--code", "AAAA"]) == 1


def test_holders_are_stable_and_skip_the_owner():
    hosts = ["web-01", "db-01", "office-pc", "game-01"]
    first = backup_copies.rank("web-01", hosts)
    assert "web-01" not in first and first == backup_copies.rank("web-01", list(reversed(hosts)))
    # a new machine only takes over part of the work: the others keep their order
    assert [h for h in backup_copies.rank("web-01", hosts + ["new-01"]) if h != "new-01"] == first


# ------------------------------------------------------------------ the panel
@pytest.fixture
def panel(tmp_path, monkeypatch):
    site = tmp_path / "www"
    site.mkdir()
    (site / "index.php").write_text("<?php echo 'hello';")
    monkeypatch.setenv("SENTRAI_BACKUP_PATHS", str(site))
    monkeypatch.delenv("SENTRAI_BACKUP_DIR", raising=False)  # each part's backups next to its own data
    monkeypatch.delenv("SENTRAI_BACKUP_REPLICAS", raising=False)
    settings = Settings(db_path=tmp_path / "core" / "sentrai.db", background=False, demo_speed=60.0, risk_scope="host")
    app = create_app(settings)
    with TestClient(app, headers=AUTH) as c:
        c.core = app.state.core  # type: ignore[attr-defined]
        c.copies = app.state.copies  # type: ignore[attr-defined]
        c.tmp = tmp_path
        yield c


class _Resp:
    def __init__(self, r):
        self.r, self.status_code, self.text = r, r.status_code, r.text

    def json(self):
        return self.r.json()

    def iter_content(self, n):
        data = self.r.content
        for i in range(0, len(data), n):
            yield data[i:i + n]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class AgentSession:
    """The agent's requests session, answered by the panel's test client."""

    def __init__(self, client):
        self.c = client

    def get(self, url, params=None, headers=None, **_):
        return _Resp(self.c.get(url.removeprefix("http://panel"), params=params, headers=headers))

    def post(self, url, json=None, params=None, data=None, headers=None, **_):
        body = data.read() if hasattr(data, "read") else data
        return _Resp(self.c.post(url.removeprefix("http://panel"), json=json, params=params, content=body,
                                 headers=headers))


def machine(panel, host, tmp_path, monkeypatch, files=None):
    """A joined machine with its own data folder and (optionally) a folder it backs up."""
    key = join(panel, host)["key"]
    data_dir = tmp_path / host / "agent"
    data_dir.mkdir(parents=True)
    return {"panel": "http://panel", "key": key, "host": host, "dir": data_dir}


def sync(panel, m, monkeypatch):
    return tasks.CopySync(m, AgentSession(panel), True, m["dir"], lambda s: None).run()


def agent_backup(m, monkeypatch, site):
    monkeypatch.setenv("SENTRAI_BACKUP_PATHS", str(site))
    out = tasks.run_backup(m["dir"])
    assert out["ok"], out
    return out


def test_a_machines_backup_ends_up_on_two_other_machines(panel, tmp_path, monkeypatch):
    web, db, office = (machine(panel, h, tmp_path, monkeypatch) for h in ("web-01", "db-01", "office-pc"))
    site = tmp_path / "web-site"
    site.mkdir()
    (site / "shop.php").write_text("<?php // the shop")
    b = agent_backup(web, monkeypatch, site)
    out = sync(panel, web, monkeypatch)
    assert out["sent"] == b["id"] and not out.get("error"), out
    assert panel.copies.has_key("web-01")
    # the panel keeps a sealed copy it can open; the machines picked keep one they cannot
    for m in (db, office):
        got = sync(panel, m, monkeypatch)
        assert got["fetched"] == [f"web-01/{b['id']}"], got
        held = m["dir"] / "backups" / "copies" / "web-01" / f"{b['id']}.sbk"
        assert held.is_file() and b"the shop" not in held.read_bytes()
    summary = panel.get("/backups/copies").json()
    web_entry = next(e for e in summary["machines"] if e["owner"] == "web-01")
    assert web_entry["key_kept"] and sorted(web_entry["copies"][0]["held_on"]) == ["db-01", "office-pc"]
    # sending again sends nothing new
    assert sync(panel, web, monkeypatch)["sent"] is None
    # web-01 is lost: the panel unlocks its copy with the key it kept
    r = panel.post("/backups/copies/unlock", json={"owner": "web-01", "id": b["id"], "operator": "erick"})
    assert r.status_code == 200, r.text
    restored = list((panel.core.settings.db_path.parent / "restores").glob(f"web-01-{b['id']}.tar.gz"))
    with tarfile.open(restored[0]) as tar:
        assert tar.extractfile("files/0/shop.php").read() == b"<?php // the shop"
    types = [r["type"] for r in panel.core.audit.records()]
    assert {"backup_key_kept", "backup_copy_received", "backup_copy_unlocked"} <= set(types)


def test_the_panels_own_backup_is_kept_on_machines(panel, tmp_path, monkeypatch):
    web, db = (machine(panel, h, tmp_path, monkeypatch) for h in ("web-01", "db-01"))
    sync(panel, web, monkeypatch)  # sends web-01's key before the panel's backup is made
    b = panel.post("/backups", json={"operator": "erick"}).json()
    assert b["ok"] and b["sealed"]["ok"], b
    for m in (web, db):
        assert sync(panel, m, monkeypatch)["fetched"] == [f"_panel/{b['id']}"]
    status = panel.get("/backups").json()
    assert sorted(status["backups"][0]["held_on"]) == ["db-01", "web-01"]
    # the panel is lost: the owner's recovery code opens any machine's copy
    code = panel.copies.recovery_code()
    held = web["dir"] / "backups" / "copies" / "_panel" / f"{b['id']}.sbk"
    sealed.unseal(held, tmp_path / "panel.tar.gz", sealed.from_code(code))
    with tarfile.open(tmp_path / "panel.tar.gz") as tar:
        names = tar.getnames()
    assert "files/0/index.php" in names
    assert "sentrai/data/machines/backup-keys.json" in names  # the machines' keys come back with it
    assert panel.get("/backups/copies").json()["recovery_code_shown"]


def test_no_machines_no_panel_copy(panel):
    b = panel.post("/backups", json={"operator": "erick"}).json()
    assert b["ok"] and b.get("sealed") is None


def test_only_picked_machines_get_a_copy_and_nothing_unchecked_is_kept(panel, tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRAI_BACKUP_REPLICAS", "1")
    hosts = ["web-01", "db-01", "office-pc"]
    ms = {h: machine(panel, h, tmp_path, monkeypatch) for h in hosts}
    site = tmp_path / "s"
    site.mkdir()
    (site / "a.txt").write_text("a")
    b = agent_backup(ms["web-01"], monkeypatch, site)
    sync(panel, ms["web-01"], monkeypatch)
    picked = panel.copies.holders("web-01")
    assert len(picked) == 1
    other = next(h for h in hosts if h not in picked and h != "web-01")
    r = panel.get("/fleet/backup-copies/file", params={"owner": "web-01", "id": b["id"]}, headers=as_agent(ms[other]["key"]))
    assert r.status_code == 403
    # a copy without the key, or with the wrong fingerprint, is refused
    key = ms["db-01"]["key"]
    blob = tmp_path / "x.sbk"
    sha = sealed.seal(site / "a.txt", blob, sealed.new_key())
    r = panel.post("/fleet/backup-copies", params={"id": "b-20261102-120000", "sealed_sha256": sha},
                   content=blob.read_bytes(), headers=as_agent(key))
    assert r.status_code == 409 and "no key" in r.json()["detail"]
    r = panel.post("/fleet/backup-copies", params={"id": "b-20261102-120000", "sealed_sha256": "0" * 64},
                   content=blob.read_bytes(), headers=as_agent(key))
    assert r.status_code == 409 and "damaged" in r.json()["detail"]
    r = panel.post("/fleet/backup-copies", params={"id": "../../etc", "sealed_sha256": sha},
                   content=b"x", headers=as_agent(key))
    assert r.status_code == 400
    assert not list((panel.copies.root() / "db-01").glob("*.sbk")) if (panel.copies.root() / "db-01").exists() else True
    # the operator token cannot pose as a machine
    assert panel.post("/fleet/backup-key", json={"key": base64.b64encode(b"k" * 32).decode()}).status_code == 400


def test_a_machine_keeps_only_its_newest_copies_and_never_deletes_on_command(panel, tmp_path, monkeypatch):
    web, db = (machine(panel, h, tmp_path, monkeypatch) for h in ("web-01", "db-01"))
    site = tmp_path / "s"
    site.mkdir()
    ids = []
    for n in range(3):
        (site / "a.txt").write_text(str(n))
        b = agent_backup(web, monkeypatch, site)
        ids.append(b["id"])
        sync(panel, web, monkeypatch)
        sync(panel, db, monkeypatch)
        import time as _t
        _t.sleep(1.05)  # backup ids are by the second
    held = sorted(p.stem for p in (db["dir"] / "backups" / "copies" / "web-01").glob("*.sbk"))
    assert held == sorted(ids[-2:])
    # the panel losing its copies does not make the machine drop the ones it holds
    for f in (panel.copies.root() / "web-01").iterdir():
        f.unlink()
    sync(panel, db, monkeypatch)
    assert sorted(p.stem for p in (db["dir"] / "backups" / "copies" / "web-01").glob("*.sbk")) == sorted(ids[-2:])
    state = json.loads((web["dir"] / "backups" / "copies" / "state.json").read_text())
    assert state["sent"] == ids[-1]


def test_team_cli_shows_the_recovery_code_and_copies(panel, tmp_path, monkeypatch):
    from .test_cli import run

    web = machine(panel, "web-01", tmp_path, monkeypatch)
    code, out = run(panel, "backups", "now")
    assert code == 0 and out.startswith("Backup b-")
    sync(panel, web, monkeypatch)
    code, out = run(panel, "backups", "copies")
    assert code == 0 and "this panel" in out and "web-01" in out and "never shown" in out
    code, out = run(panel, "backups", "key")
    assert code == 0
    shown = next(line.strip() for line in out.splitlines() if line.count("-") >= 10)
    assert sealed.from_code(shown) == panel.copies.panel_key()
    assert "never shown" not in run(panel, "backups", "copies")[1]
    assert any(r["type"] == "backup_recovery_code_shown" and shown not in json.dumps(r["data"])
               for r in panel.core.audit.records())
    code, out = run(panel, "backups", "list")
    assert code == 0 and "web-01" in out
