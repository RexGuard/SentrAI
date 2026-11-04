"""Every alert carries the audit witness, the notifier keeps the newest one, and /verify checks it."""

from emailer import format_email
from formatting import format_console, format_telegram
from notifier import WitnessStore, process_pending, verify_witness

LINE = "SENTRAI-FP v1 seq=42 head=" + "ab" * 32 + " at=2026-10-19T10:00:00Z sig=" + "cd" * 16
ALERT = {"id": "ntf-0001", "incident": "RSK-2026-081", "kind": "incident_opened", "title": "t", "text": "x",
         "risk_index": 53, "witness": LINE}
NOTICE = {"id": "ntf-0002", "incident": None, "kind": "watchdog", "title": "Collector silent: web", "text": "silent",
          "witness": LINE}


def test_alerts_and_notices_show_the_witness():
    assert f"<code>{LINE}</code>" in format_telegram(ALERT)
    assert f"<code>{LINE}</code>" in format_telegram(NOTICE)
    assert "Witness:" in format_console(ALERT, color=False)
    _, text, html_body = format_email(ALERT)
    assert LINE in text and LINE in html_body
    assert LINE not in format_telegram({**ALERT, "witness": "not a fingerprint"})


class FakeCore:
    def __init__(self, ok=True):
        self.ok, self.checked = ok, []

    def risk(self):
        return None

    def pending(self):
        return [ALERT]

    def incident(self, iid):
        return None

    def delivered(self, *a):
        pass

    def verify(self, line):
        self.checked.append(line)
        return {"ok": self.ok, "reason": "records 1 to 42 are exactly as they were" if self.ok else "record 42 changed"}


def test_delivered_witness_is_kept_and_verified(tmp_path):
    store = WitnessStore(tmp_path / "w.txt")
    assert store.last() == ""
    core = FakeCore()
    process_pending(core, lambda n, i, r: "m1", "console", set(), store)
    assert store.last() == LINE
    ok, msg = verify_witness(core, store.last())
    assert ok is True and msg.startswith("✅") and core.checked == [LINE]
    ok, msg = verify_witness(FakeCore(ok=False), LINE)
    assert ok is False and "CHANGED" in msg
    assert verify_witness(core, "")[0] is None
