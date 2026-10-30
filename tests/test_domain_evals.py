from sbomreach.domain.evals import agreement


def test_agreement_counts_and_confusion():
    gold = {("r1", "a"): "REACHED", ("r1", "b"): "USED", ("r2", "c"): "UNSEEN", ("r2", "d"): "USED"}
    pred = {("r1", "a"): "REACHED", ("r1", "b"): "UNSEEN", ("r2", "c"): "UNSEEN", ("r2", "d"): "USED"}
    r = agreement(gold, pred)
    assert r.total == 4 and r.matched == 3
    assert abs(r.rate - 0.75) < 1e-9
    assert r.confusion[("USED", "UNSEEN")] == 1
    assert r.per_repo["r1"] == (1, 2)


def test_agreement_missing_prediction_counts_as_miss():
    r = agreement({("r", "a"): "REACHED"}, {})
    assert r.matched == 0 and r.total == 1


def test_reached_precision_recall():
    gold = {("r", "a"): "REACHED", ("r", "b"): "USED", ("r", "c"): "REACHED"}
    pred = {("r", "a"): "REACHED", ("r", "b"): "REACHED", ("r", "c"): "USED"}
    r = agreement(gold, pred)
    assert abs(r.reached_precision - 0.5) < 1e-9
    assert abs(r.reached_recall - 0.5) < 1e-9


def test_wilson_interval_known_values():
    from sbomreach.domain.evals import wilson
    lo, hi = wilson(15, 22)
    assert round(lo, 3) == 0.473 and round(hi, 3) == 0.836
    assert wilson(0, 0) == (0.0, 1.0)
    lo, hi = wilson(37, 37)
    assert hi == 1.0 and lo > 0.9
