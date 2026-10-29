import collections
import json
import os

EV = os.path.join(os.path.dirname(__file__), "..", "evidence")


def rows():
    return [json.loads(x) for x in open(os.path.join(EV, "gold.jsonl"), encoding="utf-8") if x.strip()]


def test_gold_size_and_spread():
    r = rows()
    assert len(r) >= 30
    per = collections.Counter(x["repo"] for x in r)
    assert len(per) >= 3 and min(per.values()) >= 8


def test_gold_reached_rows_have_evidence_and_unseen_have_none():
    for x in rows():
        if x["verdict"] == "REACHED":
            assert x["evidence"], x
        if x["verdict"] == "UNSEEN":
            assert not x["evidence"], x


def test_gold_labeler_is_not_claimed_to_be_human():
    for x in rows():
        assert "AI" in x["labeler"] and "사람 검산" not in x["labeler"].replace("사람 검산이 아니다", "")


def test_gold_has_all_three_classes_and_two_languages():
    r = rows()
    assert {x["verdict"] for x in r} == {"REACHED", "USED", "UNSEEN"}
    assert {"vulnerable-flask-app", "nodejs-goof"} <= {x["repo"] for x in r}
