"""정답(Gold)과 도구 판정의 일치율."""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Tuple

Key = Tuple[str, str]


@dataclass
class Agreement:
    total: int
    matched: int
    confusion: Counter
    per_repo: Dict[str, Tuple[int, int]]
    reached_precision: float
    reached_recall: float

    @property
    def rate(self) -> float:
        return self.matched / self.total if self.total else 0.0


def agreement(gold: Dict[Key, str], pred: Dict[Key, str]) -> Agreement:
    conf: Counter = Counter()
    per: Dict[str, list] = {}
    matched = 0
    tp = fp = fn = 0
    for k, g in gold.items():
        p = pred.get(k, "MISSING")
        conf[(g, p)] += 1
        ok = g == p
        matched += ok
        r = per.setdefault(k[0], [0, 0])
        r[0] += ok
        r[1] += 1
        if p == "REACHED" and g == "REACHED":
            tp += 1
        elif p == "REACHED":
            fp += 1
        elif g == "REACHED":
            fn += 1
    return Agreement(len(gold), matched, conf, {k: (v[0], v[1]) for k, v in per.items()},
                     tp / (tp + fp) if tp + fp else 0.0, tp / (tp + fn) if tp + fn else 0.0)


def wilson(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    """이항 비율의 윌슨 95% 구간(표본이 작을 때 일치율이 얼마나 흔들리는지)."""
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)
