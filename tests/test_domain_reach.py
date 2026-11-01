from sbomreach.domain.models import Advisory, Alert, Component, Evidence, Verdict
from sbomreach.domain.reach import SourceIndex, judge
from sbomreach.domain.packages import modules_for


def mk_alert(name="PyYAML", eco="PyPI", symbols=("yaml.load",), version="5.1"):
    c = Component(name=name, version=version, ecosystem=eco)
    a = Advisory(id="GHSA-x", aliases=("CVE-1",), summary="s", severity="HIGH",
                 fixed_versions=("5.4",), symbols=tuple(symbols))
    return Alert(c, a)


def ev(path, line, text="x"):
    return Evidence(path=path, line=line, text=text)


def test_modules_for_alias_table():
    assert "yaml" in modules_for("PyPI", "PyYAML")
    assert "PIL" in modules_for("PyPI", "Pillow")
    assert "jwt" in modules_for("PyPI", "PyJWT")
    assert modules_for("npm", "lodash") == ("lodash",)
    assert modules_for("PyPI", "Flask-SQLAlchemy") == ("flask_sqlalchemy",)


def test_reached_when_symbol_called_with_evidence():
    idx = SourceIndex(imports={"yaml": [ev("a.py", 1, "import yaml")]},
                      refs={("yaml", "load"): [ev("a.py", 9, "yaml.load(x)")]})
    j = judge(mk_alert(), idx)
    assert j.verdict is Verdict.REACHED
    assert j.evidence[0].path == "a.py" and j.evidence[0].line == 9


def test_used_when_imported_but_symbol_not_called():
    idx = SourceIndex(imports={"yaml": [ev("a.py", 1)]},
                      refs={("yaml", "safe_load"): [ev("a.py", 3)]})
    j = judge(mk_alert(), idx)
    assert j.verdict is Verdict.USED
    assert j.evidence[0].line == 1


def test_unseen_when_not_imported():
    j = judge(mk_alert(), SourceIndex(imports={}, refs={}))
    assert j.verdict is Verdict.UNSEEN
    assert j.evidence == ()


def test_no_symbols_never_reached():
    # 취약 심볼을 모르면 import가 있어도 도달로 올릴 수 없다
    idx = SourceIndex(imports={"yaml": [ev("a.py", 1)]},
                      refs={("yaml", "load"): [ev("a.py", 9)]})
    j = judge(mk_alert(symbols=()), idx)
    assert j.verdict is Verdict.USED
    assert "심볼" in j.reason


def test_reached_requires_evidence():
    # 판정 객체를 억지로 만들어도 REACHED + 빈 근거는 거부
    import pytest
    from sbomreach.domain.models import Judgement
    with pytest.raises(ValueError):
        Judgement(alert=mk_alert(), verdict=Verdict.REACHED, evidence=(), reason="r")


def test_symbol_match_uses_last_segment_and_module_family():
    idx = SourceIndex(imports={"lodash": [ev("a.js", 1)]},
                      refs={("lodash", "template"): [ev("a.js", 4, "_.template(s)")]})
    al = mk_alert(name="lodash", eco="npm", symbols=("_.template",), version="4.17.4")
    assert judge(al, idx).verdict is Verdict.REACHED


def test_symbol_in_other_module_does_not_match():
    idx = SourceIndex(imports={"yaml": [ev("a.py", 1)]},
                      refs={("json", "load"): [ev("a.py", 5)]})
    assert judge(mk_alert(), idx).verdict is Verdict.USED


def test_weak_method_name_match_reaches_with_weak_flag():
    idx = SourceIndex(imports={"express": [ev("a.js", 1)]}, weak_refs={"redirect": [ev("b.js", 7, "res.redirect(x)")]})
    j = judge(mk_alert(name="express", eco="npm", symbols=("response.redirect",), version="4.12.4"), idx)
    assert j.verdict is Verdict.REACHED and j.weak is True and j.evidence[0].line == 7
    assert "타입 추론 없음" in j.reason


def test_weak_match_needs_qualified_symbol_and_import():
    idx = SourceIndex(imports={"express": [ev("a.js", 1)]}, weak_refs={"redirect": [ev("b.js", 7)]})
    # 한정되지 않은 심볼은 약한 근거를 쓰지 않는다
    assert judge(mk_alert(name="express", eco="npm", symbols=("redirect",), version="1"), idx).verdict is Verdict.USED
    # import가 없으면 약한 근거도 쓰지 않는다
    idx2 = SourceIndex(imports={}, weak_refs={"redirect": [ev("b.js", 7)]})
    assert judge(mk_alert(name="express", eco="npm", symbols=("response.redirect",), version="1"), idx2).verdict is Verdict.UNSEEN


def test_generic_method_names_are_not_weak_evidence():
    idx = SourceIndex(imports={"django": [ev("a.py", 1)]}, weak_refs={"filter": [ev("b.py", 3)]})
    al = mk_alert(name="Django", symbols=("QuerySet.filter",), version="4.2")
    assert judge(al, idx).verdict is Verdict.USED


def test_strong_hit_is_not_weak():
    idx = SourceIndex(imports={"yaml": [ev("a.py", 1)]}, refs={("yaml", "load"): [ev("a.py", 9)]}, weak_refs={"load": [ev("a.py", 9)]})
    j = judge(mk_alert(), idx)
    assert j.verdict is Verdict.REACHED and j.weak is False


def test_string_mention_gives_used_not_unseen():
    idx = SourceIndex(mentions={"allauth": [ev("settings.py", 48, '"allauth",')]})
    al = mk_alert(name="django-allauth", symbols=(), version="0.52.0")
    j = judge(al, idx)
    assert j.verdict is Verdict.USED and "문자열" in j.reason


# ---- v1.3: 일반 이름 심볼 오탐 검증 (SPEC S10) ----
from sbomreach.domain.reach import GENERIC, is_product_path

COMMON = frozenset({"decode", "session", "charfield"})


def test_generic_only_hit_is_not_reached():
    # 취약 심볼이 흔한 일반 이름(decode)뿐이고 모듈.이름으로 특정되지 않았다 -> 호출 줄이 있어도 USED
    idx = SourceIndex(imports={"jwt": [ev("a.py", 1, "import jwt")]},
                      refs={("jwt", "decode"): [ev("a.py", 9, "jwt.decode(t)")]})
    j = judge(mk_alert("PyJWT", symbols=("decode", "key_bytes", "PyJWK", "load_pem"), version="1.5"), idx, common_names=COMMON)
    assert j.verdict is Verdict.USED
    assert "일반 이름" in j.reason


def test_module_qualified_generic_name_stays_reached():
    # 어드바이저리가 jwt.decode 로 특정했으면 decode 도 근거가 된다(모듈.이름)
    idx = SourceIndex(imports={"jwt": [ev("a.py", 1)]},
                      refs={("jwt", "decode"): [ev("a.py", 9, "jwt.decode(t)")]})
    j = judge(mk_alert("PyJWT", symbols=("jwt.decode", "PyJWK"), version="1.5"), idx, common_names=COMMON)
    assert j.verdict is Verdict.REACHED


def test_specific_name_alongside_generic_is_reached():
    idx = SourceIndex(imports={"jwt": [ev("a.py", 1)]},
                      refs={("jwt", "get_unverified_header"): [ev("a.py", 7, "jwt.get_unverified_header(t)")]})
    j = judge(mk_alert("PyJWT", symbols=("decode", "get_unverified_header"), version="1.5"), idx, common_names=COMMON)
    assert j.verdict is Verdict.REACHED


def test_entry_point_library_named_symbol_stays_reached():
    # 단일 진입점 라이브러리(ms, marked): 심볼 이름이 모듈 이름과 같다
    idx = SourceIndex(imports={"ms": [ev("a.js", 1)]}, refs={("ms", "ms"): [ev("a.js", 5, "ms(p)")]})
    j = judge(mk_alert("ms", eco="npm", symbols=("ms",), version="0.6.2"), idx, common_names=COMMON)
    assert j.verdict is Verdict.REACHED


def test_hits_only_in_test_or_migration_paths_are_not_reached():
    idx = SourceIndex(imports={"yaml": [ev("app/a.py", 1)]},
                      refs={("yaml", "load"): [ev("tests/test_a.py", 9, "yaml.load(x)"), ev("app/migrations/0001.py", 3, "yaml.load(y)")]})
    j = judge(mk_alert(), idx)
    assert j.verdict is Verdict.USED
    assert "시험" in j.reason


def test_product_hit_survives_when_mixed_with_test_hits():
    idx = SourceIndex(imports={"yaml": [ev("app/a.py", 1)]},
                      refs={("yaml", "load"): [ev("tests/test_a.py", 9), ev("app/a.py", 12, "yaml.load(x)")]})
    j = judge(mk_alert(), idx)
    assert j.verdict is Verdict.REACHED and [e.path for e in j.evidence] == ["app/a.py"]


def test_is_product_path():
    for p in ["tests/a.py", "app/test_x.py", "src/x_test.py", "a/__tests__/b.js", "test/e2e/a.js", "x/migrations/0001_initial.py",
              "web/a.spec.js", "web/a.test.ts", "cypress/e2e/a.js", "conftest.py"]:
        assert not is_product_path(p), p
    for p in ["app/app.py", "routes/index.js", "server.js", "introduction/views.py", "src/main/java/a/B.java"]:
        assert is_product_path(p), p


def test_generic_constant_still_has_common_words():
    assert {"get", "set", "parse", "load"} <= GENERIC


# ---- v1.3 사후 수정(S10-④): 언어 내장·키워드는 취약 심볼 근거가 아니다 ----
def test_language_builtins_are_not_vulnerable_symbols():
    idx = SourceIndex(imports={"typeorm": [ev("a.js", 1, "require('typeorm')")]},
                      weak_refs={"stringify": [ev("a.js", 9, "JSON.stringify(x)")]},
                      refs={("typeorm", "require"): [ev("a.js", 2, "require('typeorm')")]})
    j = judge(mk_alert("typeorm", eco="npm", symbols=("JSON.stringify", "require", "import", "ViewEntity.up"), version="0.2"), idx)
    assert j.verdict is Verdict.USED


def test_real_symbol_next_to_builtins_still_reached():
    idx = SourceIndex(imports={"typeorm": [ev("a.js", 1)]},
                      refs={("typeorm", "escapeComment"): [ev("a.js", 4, "typeorm.escapeComment(c)")]})
    j = judge(mk_alert("typeorm", eco="npm", symbols=("JSON.stringify", "require", "escapeComment"), version="0.2"), idx)
    assert j.verdict is Verdict.REACHED
