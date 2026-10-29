"""결과 직렬화·마크다운 표. 문자열만 다룬다."""
from __future__ import annotations

from typing import Dict, List, Optional

from ..domain.evals import Agreement
from ..domain.models import Judgement, Remediation, Verdict
from .pipeline import ScanResult


def alerts_to_dict(res: ScanResult) -> List[Dict]:
    """판정 없는 경보 목록 — 정답(Gold)을 도구 판정을 보기 전에 쓰기 위한 입력."""
    rows = []
    for j in res.judgements:
        a, c = j.alert.advisory, j.alert.component
        rows.append({"package": c.name, "version": c.version, "ecosystem": c.ecosystem,
                     "direct": c.name.lower() in res.direct_names or c.name.lower().replace("_", "-") in res.direct_names,
                     "advisory": a.id, "aliases": list(a.aliases), "severity": a.severity, "summary": a.summary,
                     "fixed": list(a.fixed_versions), "symbols": list(a.symbols), "symbol_source": a.symbol_source})
    rows.sort(key=lambda r: (r["package"].lower(), r["version"], r["advisory"]))
    return rows


def scan_to_dict(res: ScanResult, name: str) -> Dict:
    rank_of = {id(r.judgement): r for r in res.ranked}
    alerts = []
    for r in res.ranked:
        j = r.judgement
        c, a = j.alert.component, j.alert.advisory
        alerts.append({"rank": r.rank, "score": r.score, "package": c.name, "version": c.version, "ecosystem": c.ecosystem,
                       "advisory": a.id, "severity": a.severity, "fixed": list(a.fixed_versions), "symbols": list(a.symbols),
                       "symbol_source": a.symbol_source, "verdict": j.verdict.value, "reason": j.reason,
                       "evidence": [{"path": e.path, "line": e.line, "text": e.text} for e in j.evidence]})
    return {"name": name, "repo": res.repo, "sbom_tool": res.sbom_tool, "fallback_used": res.fallback_used,
            "components": len(res.components), "elapsed_sec": res.elapsed, "stage_status": res.stage_status,
            "incomplete": [f"{c.name}@{c.version}" for c in res.incomplete],
            "counts": {"alerts": len(res.judgements), "REACHED": res.count(Verdict.REACHED),
                       "USED": res.count(Verdict.USED), "UNSEEN": res.count(Verdict.UNSEEN)},
            "alerts": alerts}


def render_ranking_md(res: ScanResult, top: int = 15) -> str:
    out = ["| 순위 | 패키지 | 버전 | 경보 | 심각도 | 판정 | 근거 줄 |", "|---|---|---|---|---|---|---|"]
    for r in res.ranked[:top]:
        j = r.judgement
        ev = "; ".join(f"{e.path}:{e.line}" for e in j.evidence[:2]) or "-"
        out.append(f"| {r.rank} | {j.alert.component.name} | {j.alert.component.version} | {j.alert.advisory.id} | "
                   f"{j.alert.advisory.severity} | {j.verdict.ko} | {ev} |")
    return "\n".join(out)


def render_accuracy_md(a: Agreement) -> str:
    kinds = ["REACHED", "USED", "UNSEEN"]
    out = [f"정답 {a.total}건 중 일치 {a.matched}건 = **{a.rate * 100:.1f}%**",
           f"도달 판정 정밀도 {a.reached_precision * 100:.1f}% · 재현율 {a.reached_recall * 100:.1f}%", "",
           "| 정답＼도구 | " + " | ".join(kinds) + " |", "|---|" + "---|" * len(kinds)]
    for g in kinds:
        out.append(f"| {g} | " + " | ".join(str(a.confusion.get((g, p), 0)) for p in kinds) + " |")
    out += ["", "| 저장소 | 일치/정답 |", "|---|---|"]
    for repo, (m, t) in sorted(a.per_repo.items()):
        out.append(f"| {repo} | {m}/{t} |")
    return "\n".join(out)
