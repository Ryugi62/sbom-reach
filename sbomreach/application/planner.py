"""계획 단계 사용 사례: LLM이 도구를 고르고(plan), 화이트리스트 검증을 거쳐(validate), 결정적 도구가 실행된다(execute).
LLM은 판정을 읽지도 쓰지도 않는다 — 입력은 개수와 키 목록뿐이다."""
from __future__ import annotations

from typing import Callable, Dict, List, Optional

from ..domain.planning import MAX_CALLS, RADIUS, SCOPES, Plan, PlanContext, default_plan, parse_llm_text, validate_plan
from .ports import LlmPort, TracePort


def build_prompt(ctx: PlanContext) -> str:
    return (
        "당신은 SBOM 도달성 스캔 에이전트의 계획 담당입니다. 스캔과 판정은 이미 코드가 끝냈고 당신은 판정을 바꿀 수 없습니다. "
        f"다음에 부를 도구를 최대 {MAX_CALLS}건 고르세요. 답은 JSON 한 개만: "
        '{"calls":[{"tool":"...","args":{...}}]}\n'
        "도구:\n"
        f"- select_adapter {{ecosystem}}: 어댑터를 돌릴 순서. ecosystem은 {list(ctx.detected)} 중에서만.\n"
        f"- inspect_context {{alert, radius}}: 약한 근거 경보의 근거 줄 주변을 연다. alert는 아래 목록의 키 그대로, radius는 {RADIUS[0]}~{RADIUS[1]} 정수.\n"
        f"- rescan {{scope}}: 조치 뒤 재스캔 범위. scope는 {list(SCOPES)} 중 하나. 조치할 패키지가 {ctx.remediation_count}개입니다"
        f"{'(0이면 부르지 마세요)' if ctx.remediation_count <= 0 else ''}.\n"
        f"약한 근거 경보({len(ctx.weak_keys)}건, 많이 의심되는 순서가 아니라 목록 순서):\n"
        + "\n".join(f"  {k}" for k in ctx.weak_keys[:30]) + "\n"
        "다른 필드(판정·버전 등)를 쓰면 버려집니다.")


class Planner:
    def __init__(self, llm: Optional[LlmPort], trace: TracePort):
        self.llm, self.trace = llm, trace

    def _fallback(self, ctx: PlanContext, why: str, **kw) -> Plan:
        self.trace.record({"tool": "fallback", "stage": "plan", "why": why, **kw})
        p = default_plan(ctx)
        self.trace.record({"tool": "plan", "source": "default", "calls": len(p.calls), "violations": 0})
        return p

    def plan(self, ctx: PlanContext) -> Plan:
        if self.llm is None:
            return self._fallback(ctx, "LLM 없음")
        try:
            text = self.llm.complete(build_prompt(ctx))
        except Exception as e:   # 429·키 없음·네트워크 — 계획이 없어도 스캔은 선다
            return self._fallback(ctx, type(e).__name__, status=getattr(e, "status", None),
                                  detail=str(getattr(e, "body", e))[:160])
        raw = parse_llm_text(text)
        if raw is None:
            return self._fallback(ctx, "계획 JSON 파싱 실패", detail=text[:120])
        p = validate_plan(raw, ctx, "llm")
        self.trace.record({"tool": "plan", "source": "llm", "calls": len(p.calls), "violations": len(p.violations)})
        for v in p.violations:
            self.trace.record({"tool": "plan_violation", "detail": v})
        return p


def execute(plan: Plan, tools: Dict[str, Callable[..., dict]], trace: TracePort) -> List[dict]:
    out = []
    for i, c in enumerate(plan.calls, 1):
        args = dict(c.args)
        ev = {"tool": "plan_step", "step": i, "call": c.tool, "args": args}
        try:
            res = tools[c.tool](**args)
            ev["ok"] = True
            ev["result"] = res
        except Exception as e:
            ev["ok"] = False
            ev["error"] = f"{type(e).__name__}: {e}"[:160]
            res = {"error": ev["error"]}
        trace.record(ev)
        out.append({"tool": c.tool, "args": args, **({"result": res} if ev["ok"] else res)})
    return out
