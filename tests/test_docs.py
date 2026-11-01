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


def test_v12_subtitle_matches_announcement_wording():
    text = alltext()
    assert "조치안 도출·개선" not in text
    assert "조치안 도출 및 개선" in text


def test_v12_first_paragraph_cites_task_and_repo_url_with_number():
    import build_docs as b
    lede = re.search(r"<p class=lede>(.*?)</p>", b.SOL[0], re.S).group(1)
    assert b.REPO in lede and "연결 구조 설계" in lede and "조치안 도출 및 개선" in lede
    assert re.search(r"\d", lede)


def test_v12_comparison_table_names_issuer_product_with_source_types():
    import build_docs as b
    p1 = b.SOL[0]
    assert "롯데이노베이트 자사" in p1 and "찾지 못" in p1
    for t in ("뉴스", "특허", "채용공고", "정부과제", "제품 소개"):
        assert t in p1, t


def test_v12_schedule_has_dates_and_three_numeric_targets():
    import build_docs as b
    p4 = b.SOL[3]
    for d in ("2026-11-03", "2026-11-04", "2026-11-24", "2026-11-25"):
        assert d in p4, d
    assert "80%" in p4 and "20건" in p4 and "재스캔" in p4


def test_v12_has_screen_figure_from_real_ranking_file():
    import build_docs as b
    p3 = b.SOL[2]
    assert "그림 2" in p3 and "routes/index.js:270" in p3 and "mongoose-db.js:3" in p3


def test_v12_capability_sheet_has_live_urls_with_facts():
    import build_docs as b
    assert "ryugi62.github.io/justenough" in b.CAP and "ryugi62.github.io/trifecta-gate" in b.CAP
    assert "2026-11-02" in b.CAP and "HTTP 200" in b.CAP


def test_v12_version_label():
    import build_docs as b
    assert b.VER == "v1.2"
