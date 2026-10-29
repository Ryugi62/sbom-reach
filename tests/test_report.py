from sbomreach.application.pipeline import ScanUseCase
from sbomreach.application.report import alerts_to_dict, render_accuracy_md, render_ranking_md, scan_to_dict
from sbomreach.domain.evals import agreement
from sbomreach.domain.models import Advisory, Component, Evidence
from sbomreach.domain.reach import SourceIndex
from tests.test_application_pipeline import FakeSbom, FakeSource, FakeVulns, Tr, adv, IDX


def res():
    comps = [Component("pkga", "1.0.0", "PyPI"), Component("pkgb", "1.0.0", "PyPI")]
    return ScanUseCase(FakeSbom(comps), FakeVulns({"pkga": [adv("A1")], "pkgb": [adv("B1")]}), FakeSource(IDX), Tr()).run("/r")


def test_alerts_dict_has_no_verdict_so_gold_can_be_written_blind():
    d = alerts_to_dict(res())
    assert d and all("verdict" not in a and "evidence" not in a for a in d)
    assert {"package", "version", "advisory", "severity", "symbols"} <= set(d[0])


def test_scan_dict_has_verdict_evidence_and_counts():
    d = scan_to_dict(res(), name="demo")
    assert d["counts"] == {"alerts": 2, "REACHED": 1, "USED": 0, "UNSEEN": 1}
    top = d["alerts"][0]
    assert top["verdict"] == "REACHED" and top["evidence"][0]["line"] == 5 and top["rank"] == 1
    assert d["stage_status"]["scan"] == "ok"


def test_ranking_md_shows_korean_verdict_and_evidence_line():
    md = render_ranking_md(res(), top=5)
    assert "도달" in md and "a.py:5" in md


def test_accuracy_md_contains_rate_and_confusion():
    a = agreement({("r", "x"): "REACHED", ("r", "y"): "USED"}, {("r", "x"): "REACHED", ("r", "y"): "UNSEEN"})
    md = render_accuracy_md(a)
    assert "50.0%" in md and "USED" in md and "UNSEEN" in md
