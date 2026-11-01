"""사용 사례: 스캔(SBOM -> 취약점 -> 도달 판정 -> 우선순위) · 조치 계획 · 재스캔 비교."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ..domain import guardrails
from ..domain.models import Advisory, Alert, Component, Judgement, Ranked, Remediation, Verdict
from ..domain.packages import normalize
from ..domain.priority import rank
from ..domain.reach import judge
from ..domain.versions import target_version
from .ports import SbomPort, SourcePort, TracePort, VulnLookupError, VulnPort

RETRIES = 2


@dataclass
class ScanResult:
    repo: str
    sbom_tool: str
    fallback_used: bool
    components: List[Component]
    judgements: List[Judgement]
    ranked: List[Ranked]
    incomplete: List[Component]
    stage_status: Dict[str, str]
    direct_names: Set[str]
    elapsed: float = 0.0

    @property
    def clean_claim_allowed(self) -> bool:
        return guardrails.safe_to_say_clean(len(self.judgements), bool(self.incomplete))

    def count(self, v: Verdict) -> int:
        return sum(1 for j in self.judgements if j.verdict is v)


def _pref(a: Advisory) -> int:
    return 0 if a.id.startswith("GHSA-") else 1 if a.id.startswith("PYSEC-") else 2


def dedupe_advisories(advs: List[Advisory]) -> List[Advisory]:
    groups: List[List[Advisory]] = []
    for a in advs:
        ids = {a.id, *a.aliases}
        hit = [g for g in groups if any(ids & {x.id, *x.aliases} for x in g)]
        if hit:
            hit[0].append(a)
            for extra in hit[1:]:
                hit[0].extend(extra)
                groups.remove(extra)
        else:
            groups.append([a])
    out = []
    for g in groups:
        best = sorted(g, key=_pref)[0]
        fixed: List[str] = []
        for x in g:
            for f in x.fixed_versions:
                if f not in fixed:
                    fixed.append(f)
        sym = best.symbols or next((x.symbols for x in g if x.symbols), ())
        from dataclasses import replace
        out.append(replace(best, fixed_versions=tuple(fixed), symbols=sym,
                           symbol_source=best.symbol_source if best.symbols else next((x.symbol_source for x in g if x.symbols), "none")))
    return out


class ScanUseCase:
    def __init__(self, sbom: SbomPort, vulns: VulnPort, source: SourcePort, trace: TracePort,
                 common_names: frozenset = frozenset()):
        self.sbom, self.vulns, self.source, self.trace = sbom, vulns, source, trace
        self.common_names = common_names

    def _t(self, tool: str, t0: float, **kw):
        self.trace.record({"tool": tool, "ms": round((time.time() - t0) * 1000), **kw})

    def run(self, repo: str) -> ScanResult:
        t_all = time.time()
        status: Dict[str, str] = {}
        t0 = time.time()
        comps, fallback = self.sbom.generate(repo)
        direct = self.sbom.direct_names(repo)
        status["sbom"] = "ok" if comps else "empty"
        self._t("sbom", t0, tool_name=self.sbom.tool, components=len(comps), fallback=fallback)
        if fallback:
            self.trace.record({"tool": "fallback", "stage": "sbom", "why": "syft 사용 불가 -> 잠금 파일 파서"})
        t0 = time.time()
        index = self.source.index(repo)
        status["source"] = "ok"
        self._t("source_index", t0, imported_modules=len(index.imports), referenced_symbols=len(index.refs))
        if hasattr(self.vulns, "prefetch"):
            self.vulns.prefetch(comps)
        t0 = time.time()
        alerts: List[Alert] = []
        incomplete: List[Component] = []
        for c in comps:
            last: Optional[Exception] = None
            advs = None
            for _ in range(1 + RETRIES):
                try:
                    advs = self.vulns.advisories(c)
                    break
                except VulnLookupError as e:
                    last = e
            if advs is None:
                incomplete.append(c)
                self.trace.record({"tool": "vuln_lookup", "component": f"{c.name}@{c.version}", "error": str(last)})
                continue
            for a in dedupe_advisories(advs):
                alerts.append(Alert(c, a))
        status["scan"] = "incomplete" if incomplete else "ok"
        self._t("vuln_lookup", t0, alerts=len(alerts), incomplete=len(incomplete))
        t0 = time.time()
        judgements = [judge(a, index, self.common_names) for a in alerts]
        status["reach"] = "ok"
        self._t("reach_judge", t0, reached=sum(j.verdict is Verdict.REACHED for j in judgements),
                used=sum(j.verdict is Verdict.USED for j in judgements),
                unseen=sum(j.verdict is Verdict.UNSEEN for j in judgements))
        t0 = time.time()
        ranked = rank(judgements)
        status["rank"] = "ok"
        self._t("rank", t0, top=[f"{r.judgement.alert.component.name}:{r.judgement.alert.advisory.id}:{r.score}" for r in ranked[:3]])
        return ScanResult(repo, getattr(self.sbom, "tool", "?"), fallback, comps, judgements, ranked, incomplete,
                          status, direct, round(time.time() - t_all, 2))


_ORDER = {Verdict.UNSEEN: 0, Verdict.USED: 1, Verdict.REACHED: 2}


def plan_remediation(res: ScanResult, scope: str, direct_names: Set[str]) -> List[Remediation]:
    """scope: reached(도달만) | reached+used | all."""
    want = {"reached": {Verdict.REACHED}, "reached+used": {Verdict.REACHED, Verdict.USED},
            "all": set(Verdict)}[scope]
    groups: Dict[Tuple[str, str, str], List[Judgement]] = {}
    for j in res.judgements:
        c = j.alert.component
        groups.setdefault((c.name, c.version, c.ecosystem), []).append(j)
    out = []
    for (name, ver, eco), js in groups.items():
        if not any(j.verdict in want for j in js):
            continue
        # 목표 버전은 범위 밖 경보까지 포함해 그 패키지 버전의 알려진 경보를 모두 덜어내는 가장 낮은 버전
        fixable = [list(j.alert.advisory.fixed_versions) for j in js if j.alert.advisory.fixed_versions]
        tgt = target_version(ver, fixable) if fixable else None
        best = max((j.verdict for j in js), key=lambda v: _ORDER[v])
        key = normalize(name) if eco == "PyPI" else name.lower()
        out.append(Remediation(name, eco, ver, tgt or "", tuple(j.alert.advisory.id for j in js), best,
                               key in direct_names))
    out.sort(key=lambda r: (-_ORDER[r.best_verdict], r.package))
    return out


@dataclass
class ScanDiff:
    before_total: int
    after_total: int
    resolved: int
    remaining: int
    new: int
    reached_before: int
    reached_after: int
    used_before: int = 0
    used_after: int = 0


def compare_scans(before: ScanResult, after: ScanResult) -> ScanDiff:
    kb = {(j.alert.component.name.lower(), j.alert.advisory.id) for j in before.judgements}
    ka = {(j.alert.component.name.lower(), j.alert.advisory.id) for j in after.judgements}
    return ScanDiff(len(kb), len(ka), len(kb - ka), len(kb & ka), len(ka - kb),
                    before.count(Verdict.REACHED), after.count(Verdict.REACHED),
                    before.count(Verdict.USED), after.count(Verdict.USED))
