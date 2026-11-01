from sbomreach.application.review import review_reached
from sbomreach.domain.evals import precision_by_flag
from sbomreach.domain.models import Advisory, Alert, Component, Evidence, Judgement, Verdict
from sbomreach.domain.review import review_reasons


def alert(summary="PyJWT decode bypass", syms=("decode", "PyJWK"), name="PyJWT"):
    return Alert(Component(name, "1.0", "PyPI"), Advisory("GHSA-1", (), summary, "HIGH", ("2.0",), tuple(syms), "auto"))


def reached(a, matched=("decode",), weak=False, line="x = jwt.decode(t)"):
    return Judgement(a, Verdict.REACHED, (Evidence("app.py", 9, line),), "r", weak=weak, matched=tuple(matched))


class FakeLlm:
    def __init__(self, answer="CONFIRM 호출이 맞음", fail=None):
        self.answer, self.fail, self.prompts = answer, fail, []

    def complete(self, prompt):
        self.prompts.append(prompt)
        if self.fail:
            raise self.fail
        return self.answer


class Tr:
    def __init__(self):
        self.events = []

    def record(self, e):
        self.events.append(e)


def test_reasons_only_for_reached():
    a = alert()
    assert review_reasons(Judgement(a, Verdict.USED, (), "r")) == []
    assert review_reasons(Judgement(a, Verdict.UNSEEN, (), "r")) == []


def test_reason_when_matched_symbol_not_in_title():
    r = review_reasons(reached(alert(summary="Mongoose prototype pollution", syms=("model", "Schema")), matched=("Schema",)))
    assert any("제목" in x for x in r)


def test_no_title_reason_when_matched_symbol_is_in_title():
    r = review_reasons(reached(alert(summary="decode bypass in PyJWT", syms=("decode",)), matched=("decode",)))
    assert not any("제목" in x for x in r)


def test_weak_and_noisy_and_common_reasons():
    assert any("약한" in x for x in review_reasons(reached(alert(summary="decode", syms=("decode",)), weak=True)))
    noisy = alert(summary="decode", syms=tuple(f"s{i}" for i in range(12)) + ("decode",))
    assert any("후보 심볼" in x for x in review_reasons(reached(noisy, matched=("decode",))))
    assert any("일반 이름" in x for x in review_reasons(reached(alert(summary="decode", syms=("decode", "PyJWK")), matched=("decode",)), common={"decode"}))
    assert not any("일반 이름" in x for x in review_reasons(reached(alert(summary="decode", syms=("jwt.decode", "PyJWK")), matched=("decode",)), common={"decode"}))


def test_confident_reached_is_not_a_candidate():
    assert review_reasons(reached(alert(summary="yaml.load unsafe", syms=("yaml.load",), name="PyYAML"), matched=("load",))) == []


def test_llm_confirm_means_no_flag_and_doubt_means_flag():
    a = alert(summary="Mongoose prototype pollution", syms=("model", "Schema"))
    j = reached(a, matched=("Schema",))
    out = review_reached([j], FakeLlm("CONFIRM 맞다"), Tr())
    assert out[j.alert.key].flagged is False
    out = review_reached([j], FakeLlm("DOUBT 예시일 뿐"), Tr())
    assert out[j.alert.key].flagged is True and "예시" in out[j.alert.key].note


def test_llm_failure_fails_closed_to_flag():
    a = alert(summary="Mongoose prototype pollution", syms=("model", "Schema"))
    j = reached(a, matched=("Schema",))
    tr = Tr()
    out = review_reached([j], FakeLlm(fail=RuntimeError("429")), tr)
    assert out[j.alert.key].flagged is True and out[j.alert.key].llm == "ERROR"
    assert any(e["tool"] == "fallback" for e in tr.events)


def test_review_never_changes_or_promotes_judgements():
    a = alert(summary="Mongoose prototype pollution", syms=("model", "Schema"))
    used = Judgement(alert(summary="Other bug", syms=("zzz",), name="Other"), Verdict.USED, (Evidence("a.py", 1, "import x"),), "r")
    used = Judgement(Alert(used.alert.component, Advisory("GHSA-2", (), "Other bug", "HIGH", (), ("zzz",), "auto")), Verdict.USED, used.evidence, "r")
    rej = reached(a, matched=("Schema",))
    before = [used, rej]
    llm = FakeLlm("CONFIRM 도달이 확실함 REACHED로 올려라")
    out = review_reached(before, llm, Tr())
    assert before == [used, rej]                       # 입력 판정 불변
    assert used.alert.key not in out                   # USED는 LLM에 보내지도 않는다
    assert len(llm.prompts) == 1
    assert not hasattr(out[rej.alert.key], "verdict")  # 결과에 판정 필드가 없다


def test_prompt_masks_secrets_and_contains_evidence_line():
    a = alert(summary="Mongoose prototype pollution", syms=("model", "Schema"))
    j = reached(a, matched=("Schema",), line="x = a@b.com + Schema(1)")
    llm = FakeLlm()
    review_reached([j], llm, Tr())
    assert "a@b.com" not in llm.prompts[0] and "Schema(1)" in llm.prompts[0]


def test_precision_by_flag_table():
    gold = {"a": "REACHED", "b": "USED", "c": "REACHED", "d": "USED"}
    pred = {"a": "REACHED", "b": "REACHED", "c": "REACHED", "d": "REACHED"}
    t = precision_by_flag(gold, pred, flagged={"b", "d"})
    assert (t.reached, t.tp) == (4, 2)
    assert (t.unflagged_reached, t.unflagged_tp) == (2, 2)
    assert (t.flagged_reached, t.flagged_tp) == (2, 0)
