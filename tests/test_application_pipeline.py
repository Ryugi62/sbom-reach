import pytest

from sbomreach.application.explain import explain
from sbomreach.application.pipeline import ScanUseCase, dedupe_advisories, plan_remediation, compare_scans
from sbomreach.application.ports import VulnLookupError
from sbomreach.domain.models import Advisory, Component, Evidence, Verdict
from sbomreach.domain.reach import SourceIndex


def adv(i, aliases=(), sev="HIGH", fixed=("2.0.0",), syms=("go",)):
    return Advisory(id=i, aliases=tuple(aliases), summary="s", severity=sev, fixed_versions=tuple(fixed), symbols=tuple(syms))


class FakeSbom:
    tool = "fake"
    def __init__(self, comps, direct=None):
        self.comps, self.direct = comps, direct or {c.name.lower() for c in comps}
    def generate(self, repo):
        return self.comps, False
    def direct_names(self, repo):
        return self.direct


class FakeVulns:
    def __init__(self, table, fail=()):
        self.table, self.fail, self.calls = table, set(fail), 0
    def advisories(self, c):
        self.calls += 1
        if c.name in self.fail:
            raise VulnLookupError("timeout")
        return self.table.get(c.name, [])


class FakeSource:
    def __init__(self, idx):
        self.idx = idx
    def index(self, repo):
        return self.idx


class Tr:
    def __init__(self):
        self.events = []
    def record(self, e):
        self.events.append(e)


IDX = SourceIndex(imports={"pkga": [Evidence("a.py", 1, "import pkga")]},
                  refs={("pkga", "go"): [Evidence("a.py", 5, "pkga.go()")]})


def mk(comps, table, fail=(), tr=None, idx=IDX):
    return ScanUseCase(FakeSbom(comps), FakeVulns(table, fail), FakeSource(idx), tr or Tr())


def test_scan_end_to_end_verdicts_and_ranking():
    comps = [Component("pkga", "1.0.0", "PyPI"), Component("pkgb", "1.0.0", "PyPI")]
    r = mk(comps, {"pkga": [adv("A1")], "pkgb": [adv("B1", sev="CRITICAL")]}).run("/repo")
    by = {j.alert.advisory.id: j.verdict for j in r.judgements}
    assert by == {"A1": Verdict.REACHED, "B1": Verdict.UNSEEN}
    assert r.ranked[0].judgement.alert.advisory.id == "A1"   # 도달 > 미확인 심각도
    assert r.incomplete == [] and r.stage_status["scan"] == "ok"


def test_scan_incomplete_when_lookup_fails_and_never_reports_clean():
    comps = [Component("pkga", "1.0.0", "PyPI"), Component("pkgb", "1.0.0", "PyPI")]
    r = mk(comps, {"pkga": [adv("A1")]}, fail={"pkgb"}).run("/repo")
    assert [c.name for c in r.incomplete] == ["pkgb"]
    assert r.stage_status["scan"] == "incomplete"
    assert r.clean_claim_allowed is False


def test_scan_retries_lookup_twice_then_gives_up():
    v = FakeVulns({}, fail={"pkgb"})
    uc = ScanUseCase(FakeSbom([Component("pkgb", "1", "PyPI")]), v, FakeSource(SourceIndex()), Tr())
    uc.run("/r")
    assert v.calls == 3   # 최초 1 + 재시도 2


def test_trace_records_every_stage():
    tr = Tr()
    mk([Component("pkga", "1.0.0", "PyPI")], {"pkga": [adv("A1")]}, tr=tr).run("/repo")
    tools = [e["tool"] for e in tr.events]
    for t in ("sbom", "source_index", "vuln_lookup", "reach_judge", "rank"):
        assert t in tools, t


def test_dedupe_merges_aliases_prefers_ghsa_and_unions_fixed():
    a = adv("PYSEC-1", aliases=("CVE-1", "GHSA-x"), fixed=("2.1",))
    b = adv("GHSA-x", aliases=("CVE-1",), fixed=("2.0.0",))
    out = dedupe_advisories([a, b])
    assert len(out) == 1 and out[0].id == "GHSA-x"
    assert set(out[0].fixed_versions) == {"2.0.0", "2.1"}


def test_plan_remediation_groups_by_package_and_picks_max_target():
    comps = [Component("pkga", "1.0.0", "PyPI")]
    r = mk(comps, {"pkga": [adv("A1", fixed=("1.0.5",)), adv("A2", fixed=("1.2.0",), sev="LOW")]}).run("/r")
    plan = plan_remediation(r, scope="all", direct_names={"pkga"})
    assert len(plan) == 1 and plan[0].target == "1.2.0" and set(plan[0].advisory_ids) == {"A1", "A2"}
    assert plan[0].best_verdict is Verdict.REACHED


def test_plan_scope_reached_skips_unseen_packages():
    comps = [Component("pkga", "1.0.0", "PyPI"), Component("pkgb", "1.0.0", "PyPI")]
    r = mk(comps, {"pkga": [adv("A1")], "pkgb": [adv("B1")]}).run("/r")
    assert [p.package for p in plan_remediation(r, "reached", {"pkga", "pkgb"})] == ["pkga"]
    assert {p.package for p in plan_remediation(r, "all", {"pkga", "pkgb"})} == {"pkga", "pkgb"}


def test_plan_no_fix_gives_empty_target():
    r = mk([Component("pkga", "1.0.0", "PyPI")], {"pkga": [adv("A1", fixed=())]}).run("/r")
    p = plan_remediation(r, "all", {"pkga"})
    assert p[0].target == ""
    assert "고쳐진 버전" in explain(p[0], None, Verdict.REACHED, Tr()).text


def test_compare_scans_resolved_remaining_new():
    comps = [Component("pkga", "1.0.0", "PyPI"), Component("pkgb", "1.0.0", "PyPI")]
    before = mk(comps, {"pkga": [adv("A1")], "pkgb": [adv("B1")]}).run("/r")
    after_comps = [Component("pkga", "2.0.0", "PyPI"), Component("pkgb", "1.0.0", "PyPI")]
    after = mk(after_comps, {"pkgb": [adv("B1")], "pkga": [adv("A9", fixed=())]}).run("/r")
    d = compare_scans(before, after)
    assert d.before_total == 2 and d.after_total == 2
    assert d.resolved == 1 and d.remaining == 1 and d.new == 1
    assert d.reached_before == 1 and d.reached_after == 1   # 신규 A9가 pkga에 대해 도달


class FakeLlm:
    def __init__(self, text):
        self.text = text
    def complete(self, prompt):
        self.prompt = prompt
        return self.text


def _rem():
    from sbomreach.domain.models import Remediation
    return Remediation("lodash", "npm", "4.17.4", "4.17.21", ("A1",), Verdict.REACHED, True)


def test_explain_uses_llm_text_when_guardrails_pass():
    tr = Tr()
    out = explain(_rem(), FakeLlm("lodash를 4.17.4에서 4.17.21로 올리면 해결됩니다."), Verdict.REACHED, tr)
    assert out.text_source == "llm"


def test_explain_falls_back_when_llm_invents_version():
    tr = Tr()
    out = explain(_rem(), FakeLlm("lodash를 9.9.9로 올리세요"), Verdict.REACHED, tr)
    assert out.text_source == "template" and "9.9.9" not in out.text
    assert any(e["tool"] == "guardrail_block" and e["rule"] == "G2" for e in tr.events)


def test_explain_falls_back_when_llm_raises():
    class Boom:
        def complete(self, p):
            raise RuntimeError("429")
    tr = Tr()
    out = explain(_rem(), Boom(), Verdict.REACHED, tr)
    assert out.text_source == "template"
    assert any(e["tool"] == "fallback" for e in tr.events)


def test_explain_masks_secrets_in_prompt():
    llm = FakeLlm("lodash를 4.17.4에서 4.17.21로 올리세요")
    from dataclasses import replace
    r = replace(_rem(), package="lodash")
    explain(r, llm, Verdict.REACHED, Tr(), context="mail me@x.com key AIzaSyA1234567890abcdefghijklmnopqrstuv")
    assert "me@x.com" not in llm.prompt and "AIza" not in llm.prompt


def test_template_text_mentions_override_for_transitive_npm():
    from dataclasses import replace
    r = replace(_rem(), direct=False)
    out = explain(r, None, Verdict.USED, Tr())
    assert "overrides" in out.text and out.text_source == "template"
