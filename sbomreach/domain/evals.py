"""정답(Gold)과 도구 판정의 일치율."""
from __future__ import annotations

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
