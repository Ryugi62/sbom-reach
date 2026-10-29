import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "docs"))


def test_docs_have_no_internal_marks_and_label_assumptions():
    import build_docs as b
    text = "".join(b.SOL) + b.SUM + b.CAP
    for bad in ("[[", "projects/", "메인 판단", "TODO", "[확인"):
        assert bad not in text
    assert "가정" in text
    assert "사람이 아니라 AI" in text   # 정답 작성 주체를 사람이라 주장하지 않음
