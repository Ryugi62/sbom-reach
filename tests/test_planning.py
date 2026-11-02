"""S18: 에이전트 계획 단계 — 도구 선택만, 판정 불변, 화이트리스트·상한·기본 경로 폴백."""
import json

from sbomreach.application.planner import Planner, build_prompt, execute
from sbomreach.domain.models import Advisory, Alert, Component, Evidence, Judgement, Verdict
from sbomreach.domain.planning import MAX_CALLS, Call, PlanContext, default_plan, parse_llm_text, validate_plan

CTX = PlanContext(detected=("PyPI", "npm"), weak_keys=("a@1|G1", "b@2|G2", "c@3|G3"), remediation_count=2)
NOREM = PlanContext(detected=("PyPI",), weak_keys=("a@1|G1",), remediation_count=0)


def calls(plan):
    return [(c.tool, dict(c.args)) for c in plan.calls]


def raw(*cs):
    return {"calls": [{"tool": t, "args": a} for t, a in cs]}


class Tr:
    def __init__(self):
        self.events = []

    def record(self, e):
        self.events.append(e)


class FakeLlm:
    def __init__(self, answer="", fail=None):
        self.answer, self.fail, self.prompts = answer, fail, []

    def complete(self, prompt):
        self.prompts.append(prompt)
        if self.fail:
            raise self.fail
        return self.answer


def test_unknown_tool_is_dropped_with_violation():
    p = validate_plan(raw(("delete_repo", {}), ("rescan", {"scope": "reached"})), CTX)
    assert [c[0] for c in calls(p)].count("delete_repo") == 0
    assert any("delete_repo" in v for v in p.violations)


def test_adapter_for_undetected_ecosystem_is_dropped():
    p = validate_plan(raw(("select_adapter", {"ecosystem": "Rust"})), CTX)
    assert ("select_adapter", {"ecosystem": "Rust"}) not in calls(p)
    assert any("Rust" in v for v in p.violations)


def test_inspect_only_weak_alerts():
    p = validate_plan(raw(("inspect_context", {"alert": "zzz@9|G9", "radius": 2}),
                          ("inspect_context", {"alert": "a@1|G1", "radius": 2})), CTX)
    assert ("inspect_context", {"alert": "a@1|G1", "radius": 2}) in calls(p)
    assert all(a.get("alert") != "zzz@9|G9" for _, a in calls(p))


def test_radius_must_be_int_in_range():
    for bad in (0, 6, "3", 2.5, True):
        p = validate_plan(raw(("inspect_context", {"alert": "a@1|G1", "radius": bad})), CTX)
        assert not [c for c in calls(p) if c[0] == "inspect_context" and c[1]["radius"] == bad], bad


def test_extra_argument_keys_are_rejected_verdict_cannot_be_smuggled():
    p = validate_plan(raw(("inspect_context", {"alert": "a@1|G1", "radius": 2, "verdict": "REACHED"})), CTX)
    assert not any("verdict" in a for _, a in calls(p))
    assert any("verdict" in v for v in p.violations)
    p2 = {"calls": [], "verdict": "REACHED", "version": "9.9.9"}
    assert any("verdict" in v for v in validate_plan(p2, CTX).violations)


def test_call_cap():
    many = [("inspect_context", {"alert": k, "radius": r}) for k in CTX.weak_keys for r in (1, 2, 3)]
    assert len(many) > MAX_CALLS
    assert len(validate_plan(raw(*many), CTX).calls) <= MAX_CALLS


def test_rescan_is_forced_when_there_is_something_to_fix():
    p = validate_plan(raw(("select_adapter", {"ecosystem": "PyPI"})), CTX)
    assert any(t == "rescan" for t, _ in calls(p))
    assert any("rescan" in v for v in p.violations)


def test_rescan_dropped_when_nothing_to_fix():
    p = validate_plan(raw(("rescan", {"scope": "reached"})), NOREM)
    assert not any(t == "rescan" for t, _ in calls(p))


def test_every_detected_ecosystem_is_covered_even_if_llm_omits_it():
    p = validate_plan(raw(("select_adapter", {"ecosystem": "npm"})), CTX)
    ecos = [a["ecosystem"] for t, a in calls(p) if t == "select_adapter"]
    assert sorted(ecos) == ["PyPI", "npm"] and ecos[0] == "npm"   # LLM이 정한 순서는 존중


def test_duplicates_dropped():
    p = validate_plan(raw(("select_adapter", {"ecosystem": "PyPI"}), ("select_adapter", {"ecosystem": "PyPI"})), CTX)
    assert [t for t, _ in calls(p)].count("select_adapter") == 2   # PyPI 1 + npm 보충 1


def test_default_plan_is_deterministic_and_valid():
    a, b = default_plan(CTX), default_plan(CTX)
    assert a == b and a.source == "default"
    again = validate_plan({"calls": [{"tool": c.tool, "args": dict(c.args)} for c in a.calls]}, CTX)
    assert again.violations == () and calls(again) == calls(a)


def test_parse_llm_text():
    assert parse_llm_text('```json\n{"calls": []}\n```') == {"calls": []}
    assert parse_llm_text('설명 {"calls": [{"tool": "rescan", "args": {"scope": "reached"}}]} 끝')["calls"][0]["tool"] == "rescan"
    assert parse_llm_text("not json") is None
    assert parse_llm_text("[1, 2]") is None


def test_planner_uses_valid_llm_plan_and_traces_it():
    tr = Tr()
    ans = json.dumps(raw(("select_adapter", {"ecosystem": "npm"}), ("select_adapter", {"ecosystem": "PyPI"}),
                         ("inspect_context", {"alert": "b@2|G2", "radius": 3}), ("rescan", {"scope": "reached+used"})))
    p = Planner(FakeLlm(ans), tr).plan(CTX)
    assert p.source == "llm" and p.violations == ()
    assert any(e["tool"] == "plan" and e["source"] == "llm" and e["calls"] == 4 for e in tr.events)


def test_planner_falls_back_when_llm_raises():
    tr = Tr()
    p = Planner(FakeLlm(fail=RuntimeError("HTTP 429")), tr).plan(CTX)
    assert p == default_plan(CTX) or (p.source == "default" and p.calls == default_plan(CTX).calls)
    assert any(e["tool"] == "fallback" and e["stage"] == "plan" for e in tr.events)


def test_planner_falls_back_on_garbage_and_without_llm():
    tr = Tr()
    assert Planner(FakeLlm("모르겠습니다"), tr).plan(CTX).source == "default"
    assert Planner(None, tr).plan(CTX).source == "default"
    assert sum(1 for e in tr.events if e["tool"] == "fallback") == 2


def test_prompt_lists_only_whitelisted_tools_and_candidates():
    pr = build_prompt(CTX)
    for t in ("select_adapter", "inspect_context", "rescan"):
        assert t in pr
    assert "a@1|G1" in pr and "PyPI" in pr and str(MAX_CALLS) in pr
    assert "판정" in pr   # 판정은 바꿀 수 없다는 문장


def test_execute_runs_tools_traces_each_and_survives_tool_errors():
    tr = Tr()
    plan = validate_plan(raw(("select_adapter", {"ecosystem": "PyPI"}), ("inspect_context", {"alert": "a@1|G1", "radius": 2}),
                             ("rescan", {"scope": "reached"})), CTX)

    def boom(**kw):
        raise OSError("disk")
    out = execute(plan, {"select_adapter": lambda ecosystem: {"components": 3},
                         "inspect_context": boom, "rescan": lambda scope: {"required": True}}, tr)
    assert [o["tool"] for o in out][:3] == ["select_adapter", "inspect_context", "rescan"]
    steps = [e for e in tr.events if e["tool"] == "plan_step"]
    assert len(steps) == len(plan.calls) and any(e.get("error") for e in steps)


def test_plan_and_execute_never_change_judgements():
    a = Alert(Component("pkg", "1", "PyPI"), Advisory("G1", (), "s", "HIGH", ("2",), ("f",), "auto"))
    js = (Judgement(a, Verdict.REACHED, (Evidence("x.py", 1, "f()"),), "r", weak=True, matched=("f",)),)
    before = tuple(js)
    tr = Tr()
    plan = Planner(FakeLlm(json.dumps({"calls": [], "verdict": "UNSEEN"})), tr).plan(CTX)
    execute(plan, {"select_adapter": lambda ecosystem: {}, "inspect_context": lambda alert, radius: {}, "rescan": lambda scope: {}}, tr)
    assert js == before and js[0].verdict is Verdict.REACHED
    assert not hasattr(plan, "verdict") and not any(k in dict(c.args) for c in plan.calls for k in ("verdict", "version"))
