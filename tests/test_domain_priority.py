from sbomreach.domain.models import Advisory, Alert, Component, Evidence, Judgement, Verdict
from sbomreach.domain.priority import rank, score


def J(sev, verdict, name="p"):
    c = Component(name=name, version="1.0.0", ecosystem="npm")
    a = Advisory(id=f"{name}-{sev}", aliases=(), summary="", severity=sev, fixed_versions=("1.0.1",), symbols=())
    ev = (Evidence("f.js", 1, "x"),) if verdict is not Verdict.UNSEEN else ()
    return Judgement(Alert(c, a), verdict, ev, "r")


def test_reached_moderate_outranks_unseen_critical():
    assert score("MODERATE", Verdict.REACHED) > score("CRITICAL", Verdict.UNSEEN)


def test_rank_orders_descending_and_is_stable():
    js = [J("LOW", Verdict.UNSEEN, "a"), J("HIGH", Verdict.REACHED, "b"), J("HIGH", Verdict.USED, "c")]
    r = rank(js)
    assert [x.judgement.alert.component.name for x in r] == ["b", "c", "a"]
    assert r[0].rank == 1 and r[-1].rank == 3


def test_unknown_severity_has_middle_weight():
    assert score("UNKNOWN", Verdict.REACHED) > score("LOW", Verdict.REACHED)
    assert score("UNKNOWN", Verdict.REACHED) < score("HIGH", Verdict.REACHED)
