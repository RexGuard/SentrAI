"""Demo clock: real time plus an optional offset, converted to demo hours via DEMO_SPEED."""

from __future__ import annotations

import time
from datetime import datetime


class DemoClock:
    def __init__(self, demo_speed: float) -> None:
        self.demo_speed = demo_speed if demo_speed > 0 else 60.0
        self._offset = 0.0

    def now(self) -> float:
        return time.time() + self._offset

    def advance_demo_hours(self, hours: float) -> None:
        """Fast-forward the clock (used by tests and the /demo/advance helper)."""
        self._offset += hours * 3600.0 / self.demo_speed

    def demo_hours(self, start_ts: float, end_ts: float | None = None) -> float:
        end = self.now() if end_ts is None else end_ts
        return max(0.0, (end - start_ts) * self.demo_speed / 3600.0)

    def real_seconds(self, demo_hours: float) -> float:
        return demo_hours * 3600.0 / self.demo_speed

    @staticmethod
    def iso(ts: float) -> str:
        return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")

    def now_iso(self) -> str:
        return self.iso(self.now())


def fmt_demo_hours(hours: float) -> str:
    total_min = int(round(hours * 60))
    h, m = divmod(total_min, 60)
    return f"{h} hrs {m} mins"


def fmt_offset(hours: float) -> str:
    total_min = int(round(hours * 60))
    h, m = divmod(total_min, 60)
    return f"T+{h}h{m:02d}m"
