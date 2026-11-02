"""inspect_context 도구의 파일 읽기 — 저장소 밖으로 나가지 못하고 읽기만 한다(S18)."""
import os

from sbomreach.infrastructure.context_reader import read_window


def test_reads_window_around_line(tmp_path):
    (tmp_path / "a.py").write_text("\n".join(f"l{i}" for i in range(1, 11)), encoding="utf-8")
    out = read_window(str(tmp_path), "a.py", 5, 2)
    assert [x["line"] for x in out] == [3, 4, 5, 6, 7] and out[2]["text"] == "l5"


def test_refuses_path_outside_repo(tmp_path):
    (tmp_path.parent / "secret.txt").write_text("x", encoding="utf-8")
    for bad in ("../secret.txt", "/etc/hosts", os.path.join("a", "..", "..", "secret.txt")):
        assert read_window(str(tmp_path), bad, 1, 1) == []


def test_missing_file_is_empty_and_text_is_capped(tmp_path):
    assert read_window(str(tmp_path), "nope.py", 1, 1) == []
    (tmp_path / "w.py").write_text("x" * 500, encoding="utf-8")
    assert len(read_window(str(tmp_path), "w.py", 1, 1)[0]["text"]) <= 200
