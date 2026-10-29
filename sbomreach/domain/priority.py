from __future__ import annotations

from typing import List

from .models import Judgement, Ranked, Verdict

SEVERITY_WEIGHT = {"CRITICAL": 10.0, "HIGH": 7.0, "MODERATE": 4.0, "MEDIUM": 4.0, "LOW": 1.0, "UNKNOWN": 3.0}
REACH_WEIGHT = {Verdict.REACHED: 1.0, Verdict.USED: 0.35, Verdict.UNSEEN: 0.1}


def score(severity: str, verdict: Verdict) -> float:
    return round(SEVERITY_WEIGHT.get(severity.upper(), 3.0) * REACH_WEIGHT[verdict], 4)


def rank(judgements: List[Judgement]) -> List[Ranked]:
    scored = [(score(j.alert.advisory.severity, j.verdict), i, j) for i, j in enumerate(judgements)]
    scored.sort(key=lambda t: (-t[0], t[1]))  # 동점은 입력 순서 유지
    return [Ranked(rank=n + 1, score=s, judgement=j) for n, (s, _, j) in enumerate(scored)]
