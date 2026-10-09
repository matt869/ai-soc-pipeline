"""Daily spend cap for continuous triage.

A honeypot's alert volume is set by attackers, not by you: one busy botnet can
multiply a day's cases. With a cap set (``TRIAGE_DAILY_BUDGET_USD`` or
``--daily-budget``), triage stops calling the API once the day's estimated spend
reaches it. Alerts left untriaged are stored with an error, so they show up as
"needs manual review" and are retried after midnight UTC.

Spend is estimated from each response's token usage at list prices
(``triage.pricing``) and persisted in the SQLite store, so restarts don't reset
it. Parallel workers can overshoot the cap by at most one request each.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import Any

from triage.pricing import cost_usd


def _today() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


class DailyBudget:
    def __init__(self, limit_usd: float, store=None, clock=_today):
        self.limit = float(limit_usd)
        self.store = store
        self.clock = clock
        self._lock = threading.Lock()
        self._memory: dict[str, float] = {}

    def spent(self) -> float:
        day = self.clock()
        return self.store.spend(day) if self.store is not None else self._memory.get(day, 0.0)

    def allow(self) -> bool:
        return self.spent() < self.limit

    def record(self, usage: dict[str, Any] | None, model: str | None) -> float:
        usd = cost_usd(usage, model)
        day = self.clock()
        with self._lock:
            if self.store is not None:
                self.store.add_spend(day, usd)
            else:
                self._memory[day] = self._memory.get(day, 0.0) + usd
        return usd

    def describe(self) -> str:
        return f"${self.spent():.2f} of ${self.limit:.2f} today"
