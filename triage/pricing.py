"""Token prices and cost accounting, shared by the budget guard and the evaluation."""

from __future__ import annotations

from typing import Any

# USD per million tokens: input, output, cache read, cache write (5-minute TTL).
PRICES: dict[str, tuple[float, float, float, float]] = {
    "claude-opus-5-5": (4.00, 20.00, 0.20, 5.00),
    "claude-sonnet-5-5": (2.00, 10.00, 0.20, 2.50),
    "claude-opus-5": (5.00, 25.00, 0.50, 6.25),
    "claude-opus-4-8": (5.00, 25.00, 0.50, 6.25),
    "claude-haiku-4-5": (1.00, 5.00, 0.10, 1.25),
}
# Unknown models (e.g. a new fallback target) are costed at the most expensive known rate,
# so a budget errs on the side of stopping early.
_WORST_CASE = max(PRICES.values(), key=lambda p: p[1])


def cost_usd(usage: dict[str, Any] | None, model: str | None) -> float:
    if not usage:
        return 0.0
    price = PRICES.get(model or "", _WORST_CASE)
    return (usage.get("input_tokens", 0) * price[0] + usage.get("output_tokens", 0) * price[1]
            + usage.get("cache_read_input_tokens", 0) * price[2]
            + usage.get("cache_creation_input_tokens", 0) * price[3]) / 1e6
