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


@dataclass(frozen=True)
class SensitivityRow:
    minutes: float
    all_hours: float        # 전체 경보를 모두 열 때
    first_hours: float      # 먼저 열 경보 N건만 열 때
    deferred_hours: float   # 뒤로 미뤄지는 몫(= 전체 - 먼저). 미룬 경보가 안전하다는 뜻이 아니다
    label: str


def sensitivity(total_alerts: int, first_open: int, minutes=(5, 10, 20)):
    """건당 처리 시간 가정값마다 시간으로 환산한다. 모든 입력이 가정이므로 줄마다 「가정」을 붙인다(S16)."""
    rows = []
    for m in minutes:
        a, f = total_alerts * m / 60, min(first_open, total_alerts) * m / 60
        rows.append(SensitivityRow(m, round(a, 1), round(f, 1), round(max(a - f, 0.0), 1),
                                   "가정: 건당 %g분은 실측이 아니라 입력값 — 뒤로 미룬 경보가 안전하다는 뜻은 아님" % m))
    return rows
