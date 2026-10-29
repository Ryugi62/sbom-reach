from sbomreach.domain.versions import compare, pick_fix, target_version


def test_compare_numeric_not_lexical():
    assert compare("4.17.10", "4.17.9") > 0
    assert compare("1.0", "1.0.0") == 0
    assert compare("0.12.2", "0.12.3") < 0


def test_compare_prerelease_is_lower():
    assert compare("2.0.0rc1", "2.0.0") < 0
    assert compare("1.0.0-beta", "1.0.0") < 0


def test_pick_fix_smallest_above_current():
    assert pick_fix("4.17.4", ["4.17.5", "4.17.21", "3.0.0"]) == "4.17.5"


def test_pick_fix_prefers_same_major_but_falls_back():
    assert pick_fix("1.5.0", ["2.0.0", "1.5.3"]) == "1.5.3"
    assert pick_fix("1.5.0", ["2.0.0", "3.1.0"]) == "2.0.0"


def test_pick_fix_none_when_no_candidate_above_current():
    assert pick_fix("5.0.0", ["4.9.0"]) is None
    assert pick_fix("5.0.0", []) is None


def test_target_version_is_max_over_advisories():
    # 어드바이저리 A는 4.17.5, B는 4.17.21에서 고쳐짐 -> 둘 다 해결하려면 4.17.21
    assert target_version("4.17.4", [["4.17.5"], ["4.17.21"]]) == "4.17.21"


def test_target_version_none_if_any_advisory_unfixed():
    assert target_version("1.0.0", [["1.0.1"], []]) is None
