from sbomreach.application.v13_summary import llm_stats, reduction


def test_llm_stats_counts_adoption_and_status_codes():
    rows = [{"tool": "llm_explain"}, {"tool": "llm_explain"}, {"tool": "fallback", "stage": "llm", "status": 429},
            {"tool": "llm_call", "status": 200}, {"tool": "llm_call", "status": 429}, {"tool": "llm_call", "status": "cache"},
            {"tool": "llm_review", "answer": "CONFIRM"}, {"tool": "llm_review", "answer": "DOUBT"}]
    s = llm_stats(rows)
    assert s["adopted"] == 2 and s["fallback"] == 1 and s["requested"] == 3
    assert s["adopt_rate"] == round(2 / 3 * 100, 1)
    assert s["status"] == {"200": 1, "429": 1, "cache": 1}
    assert s["review_confirm"] == 1 and s["review_doubt"] == 1


def test_llm_stats_empty_is_zero_not_error():
    assert llm_stats([])["adopt_rate"] == 0.0


RUN = {"alerts": [
    {"package": "A", "version": "1", "advisory": "X", "verdict": "REACHED", "review": {"flagged": True}},
    {"package": "B", "version": "1", "advisory": "Y", "verdict": "REACHED"},
    {"package": "C", "version": "1", "advisory": "Z", "verdict": "USED"},
    {"package": "D", "version": "1", "advisory": "W", "verdict": "REACHED"}]}
GOLD = [{"repo": "r", "package": "a", "version": "1", "advisory": "X", "verdict": "USED"},
        {"repo": "r", "package": "b", "version": "1", "advisory": "Y", "verdict": "REACHED"}]


def test_reduction_counts_open_alerts_and_precision_at_n():
    r = reduction({"r": RUN}, GOLD)
    assert r["alerts"] == 4 and r["reached"] == 3 and r["flagged"] == 1 and r["unflagged"] == 2
    assert r["labeled_reached"] == 2 and r["tp"] == 1            # D 는 정답이 없어 표본 밖
    assert r["precision_labeled"] == 50.0
    assert r["unflagged_labeled"] == 1 and r["unflagged_tp"] == 1 and r["precision_unflagged"] == 100.0
