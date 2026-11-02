"""다른 스캐너(osv-scanner·grype·trivy)의 JSON 보고서를 (패키지, 버전, 취약점 id) 집합으로 읽는다. 읽기만 한다."""
from __future__ import annotations

import json
from typing import Set, Tuple

Finding = Tuple[str, str, str]


def _load(text: str) -> dict:
    try:
        d = json.loads(text)
    except ValueError as e:
        raise ValueError(f"JSON이 아님: {text[:120]!r}") from e
    if not isinstance(d, dict):
        raise ValueError("JSON 객체가 아님")
    return d


def parse_osv(text: str) -> Set[Finding]:
    """osv-scanner는 별칭(GHSA·PYSEC·CVE)을 한 그룹으로 묶는다 — 그룹 1개 = 경보 1건."""
    out: Set[Finding] = set()
    for r in _load(text).get("results", []):
        for p in r.get("packages", []):
            pk = p.get("package", {})
            for g in p.get("groups", []):
                ids = sorted(g.get("ids", []))
                if ids:
                    out.add((pk.get("name", ""), pk.get("version", ""), ids[0]))
    return out


def parse_grype(text: str) -> Set[Finding]:
    return {(m["artifact"]["name"], m["artifact"].get("version", ""), m["vulnerability"]["id"])
            for m in _load(text).get("matches", [])}


def parse_trivy(text: str) -> Set[Finding]:
    out: Set[Finding] = set()
    for r in _load(text).get("Results", []) or []:
        for v in r.get("Vulnerabilities", []) or []:
            out.add((v.get("PkgName", ""), v.get("InstalledVersion", ""), v["VulnerabilityID"]))
    return out
