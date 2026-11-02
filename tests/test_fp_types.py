from sbomreach.domain.evals import classify_false_positive, fp_breakdown


def A(**kw):
    base = {"package": "p", "version": "1", "advisory": "X", "verdict": "REACHED", "weak": False, "symbols": ["Foo.bar"],
            "reason": "취약 심볼 bar 의 참조·호출 근거 줄이 있음", "evidence": [{"path": "a.py", "line": 1, "text": "x.bar()"}]}
    base.update(kw)
    return base


def test_weak_evidence_is_its_own_type():
    assert classify_false_positive(A(weak=True, reason="(약한 근거) 패키지 import가 있고 …")) == "약한 근거(같은 이름 메서드, 받는 쪽 타입 모름)"


def test_capitalized_only_match_is_class_reference_type():
    a = A(reason="취약 심볼 Schema 의 참조·호출 근거 줄이 있음", symbols=["Schema.path", "Schema"])
    assert classify_false_positive(a) == "클래스 이름 참조(취약 멤버 호출 아님)"


def test_lowercase_match_is_function_name_type():
    assert classify_false_positive(A()) == "함수·속성 이름 일치"


def test_mixed_case_match_counts_as_class_reference():
    a = A(reason="취약 심볼 Schema, schema 의 참조·호출 근거 줄이 있음")
    assert classify_false_positive(a) == "클래스 이름 참조(취약 멤버 호출 아님)"


def test_breakdown_counts_only_false_positives_sorted_largest_first_with_flag_counts():
    gold = {("r", "a@1|X"): "USED", ("r", "b@1|Y"): "USED", ("r", "c@1|Z"): "USED", ("r", "d@1|W"): "REACHED", ("r", "e@1|V"): "USED"}
    alerts = {
        ("r", "a@1|X"): (A(weak=True), True),
        ("r", "b@1|Y"): (A(), False),
        ("r", "c@1|Z"): (A(), False),
        ("r", "d@1|W"): (A(), False),                  # 정답도 도달 -> 오탐 아님
        ("r", "e@1|V"): (A(verdict="USED"), False),   # 도구가 도달이라 하지 않음 -> 오탐 아님
    }
    rows = fp_breakdown(gold, alerts)
    assert [r.type for r in rows] == ["함수·속성 이름 일치", "약한 근거(같은 이름 메서드, 받는 쪽 타입 모름)"]
    assert rows[0].count == 2 and rows[0].flagged == 0 and round(rows[0].share, 3) == round(2 / 3, 3)
    assert rows[1].count == 1 and rows[1].flagged == 1
    assert sum(r.count for r in rows) == 3


def test_breakdown_empty_when_no_false_positive():
    assert fp_breakdown({("r", "a@1|X"): "REACHED"}, {("r", "a@1|X"): (A(), False)}) == []
