"""S19: 스캐너 비교 — 다른 도구 경보 수 vs 우리 사람이 볼 경보 M + 근거 줄. 설치 못 한 도구는 숫자를 지어내지 않는다."""
import glob
import json
import os

import pytest

from sbomreach.adapters.scanner_reports import parse_grype, parse_osv, parse_trivy
from sbomreach.application.scanner_compare import Row, ToolResult, ours_from_run, render_table

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OSV = {"results": [{"packages": [
    {"package": {"name": "flask", "version": "1.0", "ecosystem": "PyPI"},
     "vulnerabilities": [{"id": "GHSA-1"}, {"id": "PYSEC-1"}, {"id": "GHSA-2"}],
     "groups": [{"ids": ["GHSA-1", "PYSEC-1", "CVE-1"]}, {"ids": ["GHSA-2"]}]},
    {"package": {"name": "pyyaml", "version": "5.1", "ecosystem": "PyPI"}, "vulnerabilities": [{"id": "G3"}], "groups": [{"ids": ["G3"]}]}]}]}
GRYPE = {"matches": [
    {"vulnerability": {"id": "CVE-1"}, "artifact": {"name": "flask", "version": "1.0"}},
    {"vulnerability": {"id": "CVE-1"}, "artifact": {"name": "flask", "version": "1.0"}},
    {"vulnerability": {"id": "CVE-2"}, "artifact": {"name": "flask", "version": "1.0"}}]}
TRIVY = {"Results": [{"Target": "r.txt", "Vulnerabilities": [
    {"VulnerabilityID": "CVE-1", "PkgName": "flask", "InstalledVersion": "1.0"},
    {"VulnerabilityID": "CVE-1", "PkgName": "flask", "InstalledVersion": "1.0"}]}, {"Target": "x"}]}


def test_osv_counts_alias_groups_not_ids():
    assert len(parse_osv(json.dumps(OSV))) == 3


def test_grype_dedupes_same_package_version_id():
    assert len(parse_grype(json.dumps(GRYPE))) == 2


def test_trivy_dedupes_and_tolerates_results_without_vulns():
    assert len(parse_trivy(json.dumps(TRIVY))) == 1
    assert parse_trivy("{}") == set() and parse_osv("{}") == set() and parse_grype("{}") == set()


def test_non_json_raises_value_error():
    for f in (parse_osv, parse_grype, parse_trivy):
        with pytest.raises(ValueError):
            f("Error: boom")


def test_ours_from_run_counts_reached_and_evidence_lines():
    run = {"counts": {"alerts": 5}, "alerts": [
        {"verdict": "REACHED", "evidence": [{"path": "a", "line": 1}, {"path": "b", "line": 2}]},
        {"verdict": "REACHED", "evidence": [{"path": "a", "line": 9}]},
        {"verdict": "USED", "evidence": [{"path": "a", "line": 3}]},
        {"verdict": "UNSEEN", "evidence": []}]}
    assert ours_from_run(run) == (4, 2, 3)   # (전체 경보, 사람이 볼 경보 M, 근거 줄 K)


def test_table_shows_their_numbers_and_ours():
    md = render_table([Row("repoA", {"osv-scanner": ToolResult(30), "grype": ToolResult(41), "trivy": ToolResult(28)}, 20, 3, 5)])
    assert "repoA" in md and "30" in md and "41" in md and "28" in md
    assert "그들은 경보" in md and "사람이 볼 경보" in md and "3건" in md and "5줄" in md


def test_missing_tool_prints_error_verbatim_and_no_number():
    err = "zsh: exec format error: trivy"
    md = render_table([Row("repoB", {"osv-scanner": ToolResult(7), "trivy": ToolResult(None, err)}, 9, 1, 1)])
    assert err in md
    line = [l for l in md.splitlines() if l.startswith("| repoB")][0]
    cells = [c.strip() for c in line.strip("|").split("|")]
    assert cells[1].startswith("7") and err in cells[2]


def test_rendered_m_matches_committed_runs():
    runs = sorted(glob.glob(os.path.join(ROOT, "evidence", "runs", "*.json")))
    assert runs
    for p in runs:
        d = json.load(open(p, encoding="utf-8"))
        total, m, k = ours_from_run(d)
        assert m == d["counts"]["REACHED"] and total == d["counts"]["alerts"]
        assert k >= m   # 도달 1건마다 근거 줄 ≥1


def test_count_with_note_shows_both():
    md = render_table([Row("r", {"trivy": ToolResult(12, "--offline-scan: 원격 pom 해석 생략")}, 5, 1, 1)])
    line = [l for l in md.splitlines() if l.startswith("| r ")][0]
    assert "12" in line and "--offline-scan" in line
