"""LLM 판정 보조: 후보 REACHED만 LLM에 보내 「사람 확인 필요」 표시를 받는다. 판정은 건드리지 않는다."""
from __future__ import annotations

from typing import AbstractSet, Dict, List

from ..domain import guardrails
from ..domain.models import Judgement
from ..domain.review import ReviewFlag, review_reasons
from .ports import LlmPort, TracePort


def _prompt(j: Judgement, reasons: List[str]) -> str:
    a = j.alert.advisory
    ev = "\n".join(f"- {e.path}:{e.line}  {e.text[:160]}" for e in j.evidence[:3])
    return guardrails.mask_secrets(
        "당신은 코드 보안 검토 보조입니다. 아래 경보의 「취약한 기능」을 저장소 코드가 실제로 호출하는지, 근거 줄만 읽고 판단하세요.\n"
        "근거 줄이 경보 제목이 말하는 취약 기능을 쓰는 것이 아니라, 이름만 같거나 설명문 예시에 나온 기능이면 DOUBT입니다.\n"
        "답은 첫 단어를 CONFIRM 또는 DOUBT 로 쓰고, 이어서 한국어 한 문장 이유를 쓰세요. 다른 말은 쓰지 마세요.\n"
        f"패키지 {j.alert.component.name} {j.alert.component.version}\n경보 제목: {a.summary}\n"
        f"후보 심볼: {', '.join(a.symbols[:8])}\n맞은 심볼: {', '.join(j.matched)}\n근거 줄:\n{ev}\n표시 이유: {'; '.join(reasons)}")


def review_reached(judgements: List[Judgement], llm: LlmPort, trace: TracePort,
                   common: AbstractSet[str] = frozenset()) -> Dict[tuple, ReviewFlag]:
    """후보(REACHED이면서 약한 근거 이유가 있는 것)만 LLM에 묻는다. 반환값에는 판정이 없다. 실패하면 표시를 붙인다(안전 쪽)."""
    out: Dict[tuple, ReviewFlag] = {}
    for j in judgements:
        reasons = review_reasons(j, common)
        if not reasons:
            continue
        try:
            text = llm.complete(_prompt(j, reasons)).strip()
        except Exception as e:  # 429·키 없음 등 — 확인이 안 되면 사람이 보게 한다
            trace.record({"tool": "fallback", "stage": "review", "why": type(e).__name__, "status": getattr(e, "status", None),
                          "detail": str(getattr(e, "body", e))[:160]})
            out[j.alert.key] = ReviewFlag(True, tuple(reasons), "ERROR", "LLM 확인 실패 — 사람이 확인")
            continue
        head = text.split()[0].upper().strip("*:.,") if text.split() else ""
        note = text[len(text.split()[0]):].strip() if text.split() else ""
        confirmed = head == "CONFIRM"
        trace.record({"tool": "llm_review", "package": j.alert.component.name, "advisory": j.alert.advisory.id,
                      "answer": "CONFIRM" if confirmed else "DOUBT"})
        out[j.alert.key] = ReviewFlag(not confirmed, tuple(reasons), "CONFIRM" if confirmed else "DOUBT", note[:200])
    return out
