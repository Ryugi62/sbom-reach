"""정답(Gold)과 도구 판정의 일치율."""
from __future__ import annotations

import math
import re
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


@dataclass
class FlagTable:
    reached: int
    tp: int
    unflagged_reached: int
    unflagged_tp: int
    flagged_reached: int
    flagged_tp: int

    @staticmethod
    def _p(tp: int, n: int) -> float:
        return tp / n if n else 0.0

    @property
    def precision(self) -> float:
        return self._p(self.tp, self.reached)

    @property
    def unflagged_precision(self) -> float:
        return self._p(self.unflagged_tp, self.unflagged_reached)


def precision_by_flag(gold: Dict[Key, str], pred: Dict[Key, str], flagged) -> FlagTable:
    """도달로 판정된 것 중 정답도 도달인 비율을, 「사람 확인 필요」 표시 전(전체)과 후(표시 없는 것만)로 나란히."""
    r = tp = ur = utp = fr = ftp = 0
    for k, p in pred.items():
        if p != "REACHED" or k not in gold:
            continue
        hit = gold[k] == "REACHED"
        r += 1
        tp += hit
        if k in flagged:
            fr += 1
            ftp += hit
        else:
            ur += 1
            utp += hit
    return FlagTable(r, tp, ur, utp, fr, ftp)


def cohen_kappa(pairs) -> float:
    """두 판정자의 라벨 쌍 [(a, b), ...] 의 Cohen kappa. 우연히 일치할 몫을 뺀 일치도."""
    n = len(pairs)
    if n == 0:
        return 0.0
    po = sum(1 for a, b in pairs if a == b) / n
    ca, cb = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    pe = sum((ca[k] / n) * (cb[k] / n) for k in set(ca) | set(cb))
    if pe >= 1.0:
        return 1.0
    return (po - pe) / (1 - pe)


FP_WEAK = "약한 근거(같은 이름 메서드, 받는 쪽 타입 모름)"
FP_CLASS = "클래스 이름 참조(취약 멤버 호출 아님)"
FP_NAME = "함수·속성 이름 일치"
_MATCHED = re.compile(r"(?:취약 심볼|가져온 클래스) (.+?) (?:의|를) ")


def classify_false_positive(alert: dict) -> str:
    """도달로 판정됐지만 정답이 도달이 아닌 경보를 결정적 규칙으로 유형에 넣는다(S15). 판정 이유 문장에 적힌 일치 이름만 본다."""
    if alert.get("weak"):
        return FP_WEAK
    m = _MATCHED.search(alert.get("reason") or "")
    names = [n.strip() for n in m.group(1).split(",")] if m else []
    if any(n[:1].isupper() for n in names):
        return FP_CLASS
    return FP_NAME


@dataclass
class FpRow:
    type: str
    count: int
    flagged: int
    share: float


def fp_breakdown(gold: Dict[Key, str], alerts: Dict[Key, tuple]) -> list:
    """alerts: 키 -> (경보 dict, 「사람 확인 필요」 표시 여부). 오탐 = 도구 도달 ∧ 정답 도달 아님. 큰 유형부터."""
    cnt: Counter = Counter()
    flg: Counter = Counter()
    for k, g in gold.items():
        a = alerts.get(k)
        if not a or a[0].get("verdict") != "REACHED" or g == "REACHED":
            continue
        t = classify_false_positive(a[0])
        cnt[t] += 1
        flg[t] += bool(a[1])
    total = sum(cnt.values())
    return [FpRow(t, n, flg[t], n / total) for t, n in sorted(cnt.items(), key=lambda x: (-x[1], x[0]))]
