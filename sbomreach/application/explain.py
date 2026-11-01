"""조치안 문장 — LLM은 문장만 쓰고, 가드레일을 못 넘으면 템플릿으로 대체한다. 판정·버전은 건드릴 수 없다."""
from __future__ import annotations

import time
from dataclasses import replace
from typing import Optional

from ..domain import guardrails
from ..domain.models import Remediation, Verdict
from .ports import LlmPort, TracePort


def template_text(r: Remediation, verdict: Verdict) -> str:
    if not r.target:
        return f"{r.package} {r.current}: 고쳐진 버전이 공개되지 않았습니다 — 대체 패키지 또는 취약 호출 우회를 검토하세요. (판정 {verdict.ko}, 경보 {len(r.advisory_ids)}건)"
    how = "package.json 직접 선언을 올립니다" if r.direct and r.ecosystem == "npm" else \
        "requirements 고정 버전을 올립니다" if r.ecosystem == "PyPI" else "overrides로 전이 의존 버전을 고정합니다"
    return f"{r.package} {r.current} → {r.target}: {how}. 경보 {len(r.advisory_ids)}건({', '.join(r.advisory_ids[:3])}{' 외' if len(r.advisory_ids) > 3 else ''}) 해소 대상, 판정 {verdict.ko}."


def explain(r: Remediation, llm: Optional[LlmPort], verdict: Verdict, trace: TracePort, context: str = "") -> Remediation:
    base = template_text(r, verdict)
    if llm is None or not r.target:
        return replace(r, text=base, text_source="template")
    prompt = guardrails.mask_secrets(
        "당신은 보안 운영 담당에게 조치안을 설명하는 도우미입니다. 아래 사실만 사용해 한국어 두 문장 이내로 쓰세요. "
        "버전 숫자는 주어진 것만 쓰고 버전 이동은 「올립니다」로 표현하세요. 판정 단어(도달·사용·미확인)를 바꾸거나 안전하다고 단정하지 마세요.\n"
        f"패키지 {r.package} · 현재 {r.current} · 목표 {r.target} · 판정 {verdict.ko} · 경보 {', '.join(r.advisory_ids)}\n{context}")
    t0 = time.time()
    try:
        text = llm.complete(prompt).strip()
    except Exception as e:  # 네트워크·429·키 없음 등 — 문장 생성은 보조라 템플릿으로 계속
        trace.record({"tool": "fallback", "stage": "llm", "why": type(e).__name__, "status": getattr(e, "status", None),
                      "detail": str(getattr(e, "body", e))[:160]})
        return replace(r, text=base, text_source="template")
    chk = guardrails.check_llm_text(text, {r.current, r.target}, verdict)
    if not chk.ok:
        trace.record({"tool": "guardrail_block", "rule": chk.rule, "why": chk.why, "package": r.package})
        return replace(r, text=base, text_source="template")
    trace.record({"tool": "llm_explain", "package": r.package, "ms": round((time.time() - t0) * 1000), "chars": len(text)})
    return replace(r, text=text, text_source="llm")
