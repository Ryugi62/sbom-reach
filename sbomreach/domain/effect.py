"""효과 추정 — 모든 입력이 가정이다. 출력 첫 머리에 「가정」을 붙인다."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Effect:
    label: str
    minutes_saved: float
    cost_saved: float


def estimate(total_alerts: int, reached: int, minutes_per_alert: float, hourly_cost: float) -> Effect:
    """도달이 아닌 경보는 1차 분류(건당 분)에서 뒤로 미뤄진다고 가정 — 하한은 0(전부 도달이면 절감 0)."""
    skipped = max(total_alerts - reached, 0)
    minutes = skipped * minutes_per_alert
    return Effect("가정: 건당 %.0f분 · 시간당 %.0f원은 실측이 아니라 입력값" % (minutes_per_alert, hourly_cost),
                  minutes, minutes / 60 * hourly_cost)
