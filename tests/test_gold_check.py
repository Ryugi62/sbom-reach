import pytest

from sbomreach.application.gold_check import build_prompt, context_lines, parse_label
from sbomreach.domain.evals import cohen_kappa


def test_kappa_perfect_none_and_partial():
    assert cohen_kappa([("A", "A"), ("B", "B"), ("C", "C"), ("A", "A")]) == pytest.approx(1.0)
    # 우연 수준: 한 쪽이 항상 A 만 말하면 kappa = 0
    assert cohen_kappa([("A", "A"), ("B", "A"), ("A", "A"), ("B", "A")]) == pytest.approx(0.0)
    k = cohen_kappa([("A", "A"), ("A", "A"), ("B", "B"), ("B", "A"), ("C", "C"), ("A", "A")])
    assert 0.0 < k < 1.0


def test_kappa_all_same_label_is_defined():
    assert cohen_kappa([("A", "A"), ("A", "A")]) == pytest.approx(1.0)
    assert cohen_kappa([]) == 0.0


def test_parse_label_takes_first_known_word_and_reason():
    assert parse_label("USED — import만 있음") == ("USED", "import만 있음")
    assert parse_label("**REACHED**: 호출 확인") == ("REACHED", "호출 확인")
    assert parse_label("잘 모르겠음")[0] == "UNPARSED"


def test_context_lines_are_plain_text_search_not_tool_verdict():
    files = {"a.py": "import yaml\nx = yaml.load(s)\n# nothing\n", "b.py": "print(1)\n"}
    lines = context_lines(files, modules=["yaml"], names=["load"], limit=10)
    assert any("a.py:1" in l for l in lines) and any("a.py:2" in l for l in lines)
    assert not any("b.py" in l for l in lines)


def test_prompt_contains_definitions_and_hides_other_labels():
    p = build_prompt("PyYAML", "5.1", "yaml.load unsafe", ["yaml.load"], ["a.py:1: import yaml"])
    assert "REACHED" in p and "USED" in p and "UNSEEN" in p and "a.py:1" in p
    assert "정답" not in p and "도구" not in p      # 다른 판정자의 결과를 알려주지 않는다
