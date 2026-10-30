import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "docs"))


def alltext():
    import build_docs as b
    return "".join(b.SOL) + b.SUM + b.CAP + b.SVG_TEXT


def test_docs_have_no_internal_marks_and_label_assumptions():
    text = alltext()
    for bad in ("[[", "projects/", "메인 판단", "TODO", "[확인", "{{", "}}", "REPO_URL", "/Users/", "~/"):
        assert bad not in text, bad
    assert "가정" in text
    assert "사람이 아니라 AI" in text   # 정답 작성 주체를 사람이라 주장하지 않음


def test_repo_url_is_real_and_has_no_company_name():
    import build_docs as b
    assert re.fullmatch(r"https://github\.com/Ryugi62/[a-z0-9-]+", b.REPO)
    assert not re.search(r"lotte|롯데", b.REPO, re.I)
    assert b.REPO in alltext()


def test_holdout_is_not_called_pre_frozen_representative_and_both_values_are_shown():
    text = alltext()
    assert "대표값" not in text and "사전 동결한 홀드아웃" not in text
    assert "78.4%" in text and "81.1%" in text and "사후 수정" in text
    assert "22건" in text and "68.2%" in text and "95%" in text and "Wilson" in text


def test_ai_vs_code_split_and_trace_truth():
    text = alltext()
    assert "429" not in text           # trace에는 429가 없고 HTTPError뿐
    assert "HTTPError" in text
    assert "고칠 버전" in text and "코드가" in text and "설명 문장" in text


def test_test_count_is_computed_from_pytest_not_hardcoded():
    import build_docs as b
    assert isinstance(b.TESTS, int) and b.TESTS >= 130
    assert "120+" not in alltext() and f"{b.TESTS}건" in alltext()


def test_cost_wording_and_missed_reach_item():
    text = alltext()
    assert "절감" not in text
    assert "1차 분류 순서 조정" in text and "놓친 도달" in text


def test_repro_section_mentions_four_repo_steps_and_stdlib_vs_pytest():
    text = alltext()
    for s in ("clone_targets.py", "targets.json", "osv-snapshot", "표준 라이브러리", "pytest"):
        assert s in text, s
    assert "Java" in text and "교육용" in text


def test_private_count_is_declared_as_exception_in_header():
    import build_docs as b
    assert "비공개·건수만" in b.CAP.split("<h2>1.")[0]


def test_615_534_difference_is_explained():
    text = alltext()
    assert "615" in text and "534" in text


def test_repro_commands_extract_snapshot_into_data_and_note_syft_difference():
    text = alltext()
    assert "-C data" in text and "235" in text and "315" in text
