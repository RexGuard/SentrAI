"""The collector reports a log that shrinks, vanishes or is swapped with no rotated copy to explain it."""

from __future__ import annotations

import os
import time

from collector.collector import DiscoveredLogSource, Tailer


def _write(path, text):
    path.write_text(text)


def test_truncated_in_place_with_no_rotated_copy(tmp_path):
    log = tmp_path / "auth.log"
    _write(log, "one\ntwo\nthree\n")
    t = Tailer(log)
    assert t.read_new_lines() == ["one", "two", "three"]
    with open(log, "w") as fh:  # ': > auth.log' then the attacker's next line
        fh.write("x\n")
    assert t.read_new_lines() == ["x"]
    assert len(t.notices) == 1 and t.notices[0].startswith("truncated:") and "from 14 to 2 bytes" in t.notices[0]


def test_copytruncate_rotation_is_not_tampering(tmp_path):
    log = tmp_path / "access.log"
    _write(log, "one\ntwo\n")
    t = Tailer(log)
    t.read_new_lines()
    _write(tmp_path / "access.log.1", "one\ntwo\n")  # logrotate copytruncate: copy, then empty in place
    with open(log, "w"):
        pass
    t.read_new_lines()
    assert t.notices == []


def test_deleted_with_no_rotated_copy(tmp_path):
    log = tmp_path / "secure"
    _write(log, "one\n")
    t = Tailer(log)
    t.read_new_lines()
    log.unlink()
    assert t.read_new_lines() == []
    assert len(t.notices) == 1 and t.notices[0].startswith("deleted:")
    _write(log, "new\n")  # recreated afterwards: one notice, not two
    assert t.read_new_lines() == ["new"]
    assert len(t.notices) == 1


def test_rename_rotation_is_not_tampering(tmp_path):
    log = tmp_path / "access.log"
    _write(log, "one\n")
    t = Tailer(log)
    t.read_new_lines()
    os.replace(log, tmp_path / "access.log.1")
    _write(log, "two\n")
    assert t.read_new_lines() == ["two"]
    assert t.notices == []


def test_an_old_rotated_copy_does_not_excuse_a_wipe(tmp_path):
    log = tmp_path / "syslog"
    old = tmp_path / "syslog.1"
    _write(old, "last week\n")
    week_ago = time.time() - 7 * 86400
    os.utime(old, (week_ago, week_ago))
    _write(log, "one\ntwo\n")
    t = Tailer(log)
    t.read_new_lines()
    with open(log, "w"):
        pass
    t.read_new_lines()
    assert len(t.notices) == 1


def test_swapped_for_a_new_file(tmp_path):
    log = tmp_path / "auth.log"
    _write(log, "one\ntwo\n")
    t = Tailer(log)
    t.read_new_lines()
    tmp = tmp_path / "edited"
    _write(tmp, "one\n")  # 'sed -i' writes a new file and renames it over the old one
    os.replace(tmp, log)
    t.read_new_lines()
    assert len(t.notices) == 1 and t.notices[0].startswith("replaced:")


def test_source_sends_one_log_integrity_event_per_notice(tmp_path):
    log = tmp_path / "auth.log"
    _write(log, "Oct  2 10:00:00 web-01 sshd[1]: Accepted publickey for deploy from 192.0.2.5 port 22 ssh2\n")
    src = DiscoveredLogSource(log, "os", "syslog")
    assert len(src.poll()) == 1
    with open(log, "w"):
        pass
    events = src.poll()
    assert len(events) == 1
    ev = events[0]
    assert ev["source"] == "log_integrity" and ev["layer"] == "os"
    assert ev["raw"].startswith("log-integrity truncated:") and str(log) in ev["raw"]
    assert src.poll() == []  # reported once
