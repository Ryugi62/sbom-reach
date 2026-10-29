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
