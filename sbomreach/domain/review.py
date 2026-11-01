"""판정 보조 표시 — REACHED 중 근거가 약해 보이는 것을 골라낸다. 판정을 바꾸지 않는다(SPEC S12)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import AbstractSet, List

from .models import Judgement, Verdict
from .reach import GENERIC

NOISY_SYMBOLS = 8   # 자동 추출 후보 심볼이 이 수를 넘으면 본문 속 예시·변경 기록이 섞였을 가능성이 크다


@dataclass(frozen=True)
class ReviewFlag:
    """LLM이 근거 줄을 읽고 낸 표시. 판정(verdict) 필드가 없다 — 표시는 판정을 만들 수도 올릴 수도 없다."""
    flagged: bool
    reasons: tuple
    llm: str      # CONFIRM | DOUBT | ERROR
    note: str = ""


def review_reasons(j: Judgement, common: AbstractSet[str] = frozenset()) -> List[str]:
    if j.verdict is not Verdict.REACHED:
        return []
    out: List[str] = []
    a = j.alert.advisory
    if j.weak:
        out.append("약한 근거(타입 추론 없이 메서드 이름만 일치)")
    title = a.summary.lower()
    if j.matched and not any(m.lower() in title for m in j.matched):
        out.append("맞은 취약 심볼이 경보 제목에 없음")
    def qualified(m: str) -> bool:   # 어드바이저리가 `모듈.이름`으로 특정했으면 일반 이름이어도 근거로 인정
        return any(x.endswith("." + m) and x.count(".") == 1 for x in a.symbols)
    if any((m.lower() in GENERIC or m.lower() in common) and not qualified(m) for m in j.matched):
        out.append("일반 이름 심볼로 맞음")
    if a.symbol_source == "auto" and len(a.symbols) > NOISY_SYMBOLS:
        out.append(f"후보 심볼 {len(a.symbols)}개(본문 속 예시가 섞였을 수 있음)")
    return out
