"""Process scan: read-only discovery, privacy filtering, and approval of log files by id."""

import json

import cactai_llm
import pytest
from app import procscan
from app.chat import OperatorChat
from app.discovery import Discovery

from .test_chat import FakeProvider, call


@pytest.fixture
def machine(tmp_path, monkeypatch):
    """A Windows-shaped computer in a temp folder: the CactAI lab, nginx, MySQL, and things to hide."""
    lab = tmp_path / "mvp" / "lab"
    (lab / ".venv" / "Scripts").mkdir(parents=True)
    (lab / "logs").mkdir()
    (lab / "logs" / "access.jsonl").write_text('{"src_ip": "203.0.113.45"}\n')
    (lab / "logs" / "auth.jsonl").write_text("{}\n")
    nginx = tmp_path / "nginx-1.27"
    (nginx / "logs").mkdir(parents=True)
    (nginx / "logs" / "access.log").write_text("203.0.113.45 - - GET /\n")
    (nginx / "logs" / "error.log").write_text("\n")
    data = tmp_path / "ProgramData" / "MySQL" / "MySQL Server 8.0" / "Data"
    data.mkdir(parents=True)
    (data / "DB-01.err").write_text("Access denied for user 'root'\n")
    monkeypatch.setenv("ProgramData", str(tmp_path / "ProgramData"))
    monkeypatch.setattr(procscan, "_homes", lambda: [str(tmp_path / "Users" / "erick")])
    home_app = tmp_path / "Users" / "erick" / "app"
    (home_app / "logs").mkdir(parents=True)
    (home_app / "logs" / "app.log").write_text("x\n")
    ps = {
        "processes": [
            {"ProcessId": 4, "Name": "System", "ExecutablePath": None, "CommandLine": None},
            {"ProcessId": 612, "Name": "lsass.exe", "ExecutablePath": r"C:\Windows\System32\lsass.exe",
             "CommandLine": None},
            {"ProcessId": 700, "Name": "KeePass.exe", "ExecutablePath": r"C:\KeePass\KeePass.exe",
             "CommandLine": "KeePass.exe C:\\vault.kdbx"},
            {"ProcessId": 1200, "Name": "python.exe", "ExecutablePath": str(lab / ".venv" / "Scripts" / "python.exe"),
             "CommandLine": f'"{lab}\\.venv\\Scripts\\python.exe" -m target_app'},
            {"ProcessId": 1300, "Name": "nginx.exe", "ExecutablePath": str(nginx / "nginx.exe"),
             "CommandLine": "nginx.exe"},
            {"ProcessId": 1400, "Name": "mysqld.exe", "ExecutablePath": r"C:\Program Files\MySQL\bin\mysqld.exe",
             "CommandLine": "mysqld.exe --defaults-file=my.ini --password=hunter2"},
            {"ProcessId": 1500, "Name": "node.exe", "ExecutablePath": r"C:\node\node.exe",
             "CommandLine": f"node.exe {home_app}\\server.js --log-file {home_app / 'logs' / 'app.log'} "
                            "--db postgres://svc:s3cret@db-01/app"},
        ],
        "services": [{"Name": "MySQL80", "ProcessId": 1400, "StartName": "NT AUTHORITY\\NetworkService"}],
    }
    procs = procscan._windows(lambda cmd: json.dumps(ps))
    return {"procs": procs, "lab": lab, "tmp": tmp_path}


def scan(machine, profile=None, watched=()):
    return procscan.scan(profile or {}, set(watched), system="Windows", processes=machine["procs"])


def test_windows_scan_finds_log_folders_per_program(machine):
    r = scan(machine, watched=[str(machine["lab"] / "logs" / "access.jsonl"),
                               str(machine["lab"] / "logs" / "auth.jsonl")])
    by_program = {s["program"]: s for s in r["suggestions"]}
    assert set(by_program) >= {"CactAI lab: fake student portal", "nginx web server", "MySQL / MariaDB database",
                               "Node.js app"}
    lab = by_program["CactAI lab: fake student portal"]
    assert lab["already_watched"] and lab["reasons"] == ["logs folder of the app"] and lab["format"] == "jsonl"
    nginx = by_program["nginx web server"]
    assert nginx["layer"] == "web" and nginx["reasons"] == ["next to the program"]
    assert sorted(f["name"] for f in nginx["files"]) == ["access.log", "error.log"]
    mysql = by_program["MySQL / MariaDB database"]
    assert mysql["layer"] == "db" and mysql["files"][0]["name"].endswith("DB-01.err")
    assert r["suggestions"][-1]["already_watched"]  # new finds first
    assert any("log_error_verbosity" in n for n in r["notes"])


def test_protected_and_private_details_are_hidden(machine):
    r = scan(machine, profile={"process_scan": {"skip_processes": ["node*"]}})
    names = [p["name"] for p in r["processes"]]
    assert "lsass.exe" not in names and "KeePass.exe" not in names and "node.exe" not in names
    assert r["skipped_protected"] == 3
    assert "Node.js app" not in {s["program"] for s in r["suggestions"]}
    mysql = next(p for p in r["processes"] if p["name"] == "mysqld.exe")
    assert mysql["account"] == "NT AUTHORITY\\NetworkService" and mysql["service"] == "MySQL80"
    assert "hunter2" not in json.dumps(r)


def test_command_line_log_options_are_followed_with_secrets_masked(machine):
    r = scan(machine)
    node = next(p for p in r["processes"] if p["name"] == "node.exe")
    assert len(node["log_options"]) == 1 and node["log_options"][0].startswith("~")
    s = next(s for s in r["suggestions"] if s["program"] == "Node.js app")
    assert s["path"].startswith("~") and "erick" not in s["path"]
    assert "named on its command line" in s["reasons"]
    assert "s3cret" not in json.dumps(r)
    assert procscan.mask("postgres://svc:s3cret@db/x --api-key=abc token: xyz") == \
        "postgres://[hidden]@db/x --api-key=[hidden] token: [hidden]"
    assert procscan.account("erick") == "(user)" and procscan.account("www-data") == "www-data"


def test_scan_can_be_turned_off_in_the_profile(machine):
    r = scan(machine, profile={"process_scan": {"enabled": False}})
    assert r["enabled"] is False and r["suggestions"] == []


def test_linux_scan_of_this_machine_is_read_only_and_works():
    r = procscan.scan({})
    assert r["error"] is None and r["scanned"] > 0


def test_approve_by_id_writes_the_collector_list_and_audits(client, machine, tmp_path, monkeypatch):
    monkeypatch.setenv("CACTAI_SCOUT_SOURCES", str(tmp_path / "sources.json"))
    d = Discovery(client.core)
    monkeypatch.setattr(procscan, "list_processes", lambda system=None: machine["procs"])
    monkeypatch.setattr(procscan.platform, "system", lambda: "Windows")
    r = d.scan("erick")
    assert all("real_path" not in s and "path" not in s["files"][0] for s in r["suggestions"])
    nginx = next(s for s in r["suggestions"] if s["program"] == "nginx web server")
    fid = next(f["id"] for f in nginx["files"] if f["name"] == "access.log")
    out = d.approve(fid, "erick")
    assert out["ok"] and out["file"] == "access.log"
    saved = json.loads((tmp_path / "sources.json").read_text())
    assert saved[0]["path"].endswith("access.log") and saved[0]["layer"] == "web"
    assert saved[0]["confirmed_by"] == "erick"
    with pytest.raises(KeyError):
        d.approve("s99f1", "erick")  # only files from the latest scan
    with pytest.raises(ValueError):
        d.approve(fid, "erick", layer="mars")
    types = [rec["type"] for rec in client.core.audit.records()]
    assert "system_scan" in types and "log_source_added" in types


def test_scan_and_approve_over_http(client, tmp_path, monkeypatch):
    monkeypatch.setenv("CACTAI_SCOUT_SOURCES", str(tmp_path / "sources.json"))
    log = tmp_path / "srv" / "logs"
    log.mkdir(parents=True)
    (log / "app.log").write_text("hello\n")
    procs = [procscan.Proc(42, "python3", "/usr/bin/python3", ["python3", "app.py"], "www-data", str(tmp_path / "srv"))]
    monkeypatch.setattr(procscan, "list_processes", lambda system=None: procs)
    assert client.get("/system/scan").json()["scanned_at"] is None
    r = client.post("/system/scan", json={"operator": "erick"}).json()
    fid = r["suggestions"][0]["files"][0]["id"]
    assert client.get("/system/scan").json()["suggestions"][0]["files"][0]["id"] == fid
    assert client.post("/log-sources", json={"operator": "erick", "file_id": "nope"}).status_code == 404
    ok = client.post("/log-sources", json={"operator": "erick", "file_id": fid})
    assert ok.status_code == 200
    assert client.get("/log-sources").json()[0]["path"].endswith("app.log")


def test_cyanide_scans_and_suggests_a_log_but_cannot_add_it(client, machine, tmp_path, monkeypatch):
    monkeypatch.setenv("CACTAI_SCOUT_SOURCES", str(tmp_path / "sources.json"))
    monkeypatch.setattr(procscan, "list_processes", lambda system=None: machine["procs"])
    monkeypatch.setattr(procscan.platform, "system", lambda: "Windows")
    d = Discovery(client.core)
    first = d.scan()
    nginx = next(s for s in first["suggestions"] if s["program"] == "nginx web server")
    fid = next(f["id"] for f in nginx["files"] if f["name"] == "access.log")
    provider = FakeProvider([
        cactai_llm.Turn(tool_calls=[call("scan_system")], stop="tool_use"),
        cactai_llm.Turn(tool_calls=[call("suggest_log_source", file_id=fid, reason="Web requests to the portal")],
                        stop="tool_use"),
        cactai_llm.Turn(texts=["nginx is running; press the button to watch its access log."]),
    ])
    reply = OperatorChat(client.core, provider, d).ask("erick", "what should I monitor?")
    assert reply["looked_at"] == ["running processes"]
    assert reply["suggestions"] == [{"kind": "watch_log", "file_id": fid, "layer": "web",
                                     "label": "Watch access.log (nginx web server)",
                                     "reason": "Web requests to the portal"}]
    tool_out = provider.convos[0].results[0][0][1]
    assert "nginx web server" in tool_out and "lsass" not in tool_out and "real_path" not in tool_out
    assert not (tmp_path / "sources.json").exists()  # nothing watched until the operator presses


def test_chat_without_a_key_scans_when_asked(client, machine, monkeypatch):
    monkeypatch.setattr(procscan, "list_processes", lambda system=None: machine["procs"])
    monkeypatch.setattr(procscan.platform, "system", lambda: "Windows")
    reply = OperatorChat(client.core, None, Discovery(client.core)).ask("erick", "Scan the running processes")
    assert reply["source"] == "fallback" and "recognised" in reply["text"]
    assert any(s.get("kind") == "watch_log" for s in reply["suggestions"])


def test_latest_scan_shows_an_approved_file_as_watched(client, tmp_path, monkeypatch):
    monkeypatch.setenv("CACTAI_SCOUT_SOURCES", str(tmp_path / "sources.json"))
    (tmp_path / "srv" / "logs").mkdir(parents=True)
    (tmp_path / "srv" / "logs" / "app.log").write_text("x\n")
    procs = [procscan.Proc(7, "python3", "/usr/bin/python3", ["python3", "app.py"], "root", str(tmp_path / "srv"))]
    monkeypatch.setattr(procscan, "list_processes", lambda system=None: procs)
    d = Discovery(client.core)
    fid = d.scan()["suggestions"][0]["files"][0]["id"]
    d.approve(fid, "erick")
    s = d.latest()["suggestions"][0]
    assert s["files"][0]["watched"] and s["already_watched"]
