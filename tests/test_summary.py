from sbomreach.application.summary import summarize

RUN = {"r": {"components": 3, "elapsed_sec": 1.0, "stage_status": {"scan": "ok"}, "incomplete": [],
             "counts": {"alerts": 2, "REACHED": 1, "USED": 1, "UNSEEN": 0, "REACHED_weak": 0},
             "alerts": [{"package": "A", "version": "1", "advisory": "X", "verdict": "REACHED"},
                        {"package": "B", "version": "1", "advisory": "Y", "verdict": "USED"}]}}
GOLD = [{"repo": "r", "package": "a", "version": "1", "advisory": "X", "verdict": "REACHED"},
        {"repo": "r", "package": "b", "version": "1", "advisory": "Y", "verdict": "UNSEEN"}]
RS = {"r.reached": {"target": "r", "scope": "reached", "rounds": [1], "packages_changed": 1, "llm_texts": 0,
                    "diff": {"before_total": 2, "after_total": 1, "resolved": 1, "new": 0, "reached_before": 1, "reached_after": 0,
                             "used_before": 1, "used_after": 1}, "reached_after_items": []}}


def test_summarize_numbers_and_assumption_label():
    s = summarize({"r": {"language": "Python", "url": "u", "commit": "c"}}, RUN, RS, GOLD, GOLD, RUN)
    assert s["totals"]["alerts"] == 2 and s["accuracy"]["v1_dev"]["rate"] == 50.0
    assert s["rescan"]["r.reached"]["reached_after"] == 0
    assert s["effect"]["label"].startswith("가정") and s["effect"]["minutes_saved"] == 15
