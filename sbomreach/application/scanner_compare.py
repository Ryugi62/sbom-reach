"""스캐너 비교표(SPEC S19): 그들의 경보 수 vs 우리의 사람이 볼 경보 M + 근거 줄 K."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class ToolResult:
    count: Optional[int]       # None = 실행 못 함
    error: str = ""            # 못 한 이유의 원문


@dataclass(frozen=True)
class Row:
    repo: str
    tools: Dict[str, ToolResult]
    total: int                 # 우리 전체 경보
    reached: int               # M
    evidence_lines: int        # K


def ours_from_run(run: dict) -> Tuple[int, int, int]:
    alerts = run["alerts"]
    reached = [a for a in alerts if a["verdict"] == "REACHED"]
    return len(alerts), len(reached), sum(len(a.get("evidence", [])) for a in reached)


def _cell(r: Optional[ToolResult]) -> str:
    if r is None:
        return "미실행"
    if r.count is None:
        return f"실행 못 함 — {r.error}"
    return f"{r.count} ({r.error})" if r.error else str(r.count)


def render_table(rows: List[Row], tool_order: Tuple[str, ...] = ("osv-scanner", "grype", "trivy")) -> str:
    names = [n for n in tool_order if any(n in r.tools for r in rows)] or list(tool_order)
    head = "| 저장소 | " + " | ".join(f"그들은 경보 · {n}" for n in names) + " | 우리 전체 경보 | 우리는 사람이 볼 경보 M | 근거 줄 K |"
    sep = "|" + "---|" * (len(names) + 4)
    out = [head, sep]
    for r in rows:
        out.append(f"| {r.repo} | " + " | ".join(_cell(r.tools.get(n)) for n in names)
                   + f" | {r.total} | {r.reached}건 | {r.evidence_lines}줄 |")
    return "\n".join(out)
