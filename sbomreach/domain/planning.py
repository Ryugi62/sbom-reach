"""에이전트 계획 단계 — 모델이 「다음에 부를 도구」를 고르는 자리의 규칙(SPEC S18).
판정·버전·우선순위는 이 모듈의 어떤 객체에도 필드가 없다 = 계획이 바꿀 수 없다."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

MAX_CALLS = 6
RADIUS = (1, 5)
SCOPES = ("reached", "reached+used")
# 도구 이름 -> 허용 인자 이름 집합. 값의 범위는 _check_args가 본다.
TOOLS: Dict[str, Tuple[str, ...]] = {
    "select_adapter": ("ecosystem",),
    "inspect_context": ("alert", "radius"),
    "rescan": ("scope",),
}
ECOSYSTEMS = ("PyPI", "npm", "Maven")


@dataclass(frozen=True)
class Call:
    tool: str
    args: Tuple[Tuple[str, object], ...]

    def arg(self, name: str):
        return dict(self.args)[name]


@dataclass(frozen=True)
class PlanContext:
    detected: Tuple[str, ...]        # 감지된 생태계(고정 순서)
    weak_keys: Tuple[str, ...]       # 약한 근거 REACHED 경보 키
    remediation_count: int           # 조치할 패키지 수


@dataclass(frozen=True)
class Plan:
    calls: Tuple[Call, ...]
    source: str                      # llm | default
    violations: Tuple[str, ...] = ()


def _mk(tool: str, **kw) -> Call:
    return Call(tool, tuple(sorted(kw.items())))


def _check(tool: str, args: dict, ctx: PlanContext) -> Optional[str]:
    """위반 사유를 돌려준다. None이면 통과."""
    extra = sorted(set(args) - set(TOOLS[tool]))
    if extra:
        return f"{tool}: 허용되지 않은 인자 {extra}"
    if set(args) != set(TOOLS[tool]):
        return f"{tool}: 인자 부족 {sorted(set(TOOLS[tool]) - set(args))}"
    if tool == "select_adapter":
        e = args["ecosystem"]
        if e not in ctx.detected:
            return f"select_adapter: 감지되지 않은 생태계 {e!r}"
    elif tool == "inspect_context":
        r = args["radius"]
        if not isinstance(r, int) or isinstance(r, bool) or not RADIUS[0] <= r <= RADIUS[1]:
            return f"inspect_context: radius {r!r} 범위 밖({RADIUS[0]}~{RADIUS[1]} 정수)"
        if args["alert"] not in ctx.weak_keys:
            return f"inspect_context: 약한 근거 경보가 아님 {args['alert']!r}"
    elif tool == "rescan":
        if args["scope"] not in SCOPES:
            return f"rescan: scope {args['scope']!r} 허용 밖"
        if ctx.remediation_count <= 0:
            return "rescan: 조치할 패키지가 없음"
    return None


def validate_plan(raw: object, ctx: PlanContext, source: str = "llm") -> Plan:
    violations: List[str] = []
    items = []
    if isinstance(raw, dict):
        for k in raw:
            if k != "calls":
                violations.append(f"계획 최상위의 허용되지 않은 필드 {k!r}(판정·버전은 계획이 정하지 않는다)")
        items = raw.get("calls") if isinstance(raw.get("calls"), list) else []
    seen, kept = set(), []
    for it in items:
        if not isinstance(it, dict) or it.get("tool") not in TOOLS:
            violations.append(f"허용 목록에 없는 도구 {it.get('tool') if isinstance(it, dict) else it!r}")
            continue
        args = it.get("args") if isinstance(it.get("args"), dict) else {}
        why = _check(it["tool"], args, ctx)
        if why:
            violations.append(why)
            continue
        c = _mk(it["tool"], **args)
        if c in seen:
            violations.append(f"중복 호출 {it['tool']}")
            continue
        seen.add(c)
        kept.append(c)
    covered = {c.arg("ecosystem") for c in kept if c.tool == "select_adapter"}
    for e in ctx.detected:           # 누락 불가: 감지된 생태계는 전부 들어간다
        if e not in covered:
            kept.append(_mk("select_adapter", ecosystem=e))
    if ctx.remediation_count > 0 and not any(c.tool == "rescan" for c in kept):
        violations.append("rescan 누락 — 조치할 패키지가 있어 기본 rescan을 덧붙임")
        kept.append(_mk("rescan", scope="reached"))
    if len(kept) > MAX_CALLS:
        violations.append(f"호출 {len(kept)}건 > 상한 {MAX_CALLS} — 잘라냄")
        # 잘라내도 어댑터 커버리지·rescan은 지킨다: 필수 호출을 먼저 남긴다
        must = [c for c in kept if c.tool in ("select_adapter", "rescan")]
        rest = [c for c in kept if c.tool == "inspect_context"]
        kept = (must + rest)[:MAX_CALLS]
    return Plan(tuple(kept), source, tuple(violations))


def default_plan(ctx: PlanContext) -> Plan:
    calls = [_mk("select_adapter", ecosystem=e) for e in ctx.detected]
    calls += [_mk("inspect_context", alert=k, radius=2) for k in ctx.weak_keys[:3]]
    if ctx.remediation_count > 0:
        calls.append(_mk("rescan", scope="reached"))
    return Plan(tuple(calls[:MAX_CALLS]), "default")


def parse_llm_text(text: str) -> Optional[dict]:
    """응답에서 첫 JSON 객체를 꺼낸다. 객체가 아니면 None."""
    s = text.strip()
    start = s.find("{")
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    v = json.loads(s[start:i + 1])
                except ValueError:
                    return None
                return v if isinstance(v, dict) else None
    return None
