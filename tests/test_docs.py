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


def test_v13_representative_value_is_holdout2_first_run_with_v12_comparison():
    import build_docs as b
    text = alltext()
    assert "첫 실행(대표값)" in text and "v1.2 판정기" in text and "사후 수정" in text
    assert f"{b.H2_FIRST['reached_precision']}%" in text and f"{b.H2_V12['reached_precision']}%" in text
    assert "Cohen kappa" in text and "정답 독립성" in text
    assert "78.4%" in text and "81.1%" in text           # 홀드아웃1은 오염된 이력으로만 언급


def test_ai_role_truth_and_failure_cause_with_status_code():
    text = alltext()
    assert "429" in text and "RESOURCE_EXHAUSTED" in text and "HTTPError" in text
    assert "코드 파이프라인" in text and "고칠 버전" in text and "설명 문장" in text and "사람 확인 필요" in text
    assert "판정을 올리지 못함" in text or "올리지 못" in text


def test_main_metric_is_alerts_to_open_not_money():
    text = alltext()
    assert "절감" not in text and "50,000원" not in text and "건당 15분" not in text
    assert "열어 볼 경보 수" in text and "precision@" in text


def test_test_count_is_computed_from_pytest_not_hardcoded():
    import build_docs as b
    assert isinstance(b.TESTS, int) and b.TESTS >= 130
    assert "120+" not in alltext() and f"{b.TESTS}건" in alltext()


def test_repro_section_mentions_four_repo_steps_and_stdlib_vs_pytest():
    text = alltext()
    for s in ("clone_targets.py", "targets.json", "osv-snapshot", "표준 라이브러리", "pytest"):
        assert s in text, s
    assert "Java" in text and "교육용" in text


def test_capability_page_proves_incidents_by_excerpt_and_drops_unsourced_claim():
    import build_docs as b
    assert "923" not in b.CAP and "서류 통과" not in b.CAP
    assert "발췌" in b.CAP and b.CAP.count("<code>_system/") >= 3
    for bad in ("@", "gmail"):
        assert bad not in b.CAP.split("<h2>4.")[1]


def test_elapsed_table_states_cache_premise_inside_the_same_table():
    import build_docs as b
    p3 = b.SOL[2]
    t = p3[p3.index("<table>"):p3.index("</table>")]
    assert "소요" in t and "캐시" in t


def test_java_is_described_as_minimal_and_operational_repos_are_not_edu():
    text = alltext()
    assert "최소 어댑터" in text and "운영형 오픈소스" in text and "Gradle" in text
    assert "Java(Maven·Gradle)는 미지원" not in text


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
    assert "70%" in p4 and "20건" in p4 and "재스캔" in p4


def test_v12_has_screen_figure_from_real_ranking_file():
    import build_docs as b
    p4 = b.SOL[3]
    assert "그림 2" in p4 and "routes/index.js:270" in p4 and "mongoose-db.js:3" in p4


def test_v12_capability_sheet_has_live_urls_with_facts():
    import build_docs as b
    assert "ryugi62.github.io/justenough" in b.CAP and "ryugi62.github.io/trifecta-gate" in b.CAP
    assert "2026-11-02" in b.CAP and "HTTP 200" in b.CAP


def test_v12_version_label():
    import build_docs as b
    assert b.VER == "v1.3"
