"""v1.3 문서에 들어가는 숫자: AI 문장 채택률·호출 상태 코드, 사람이 열어 볼 경보 수와 precision@N."""
from __future__ import annotations

from collections import Counter
from typing import Dict, List


def llm_stats(rows: List[dict]) -> dict:
    adopted = sum(1 for r in rows if r.get("tool") == "llm_explain")
    fallback = sum(1 for r in rows if r.get("tool") == "fallback" and r.get("stage") == "llm")
    req = adopted + fallback
    status = Counter(str(r["status"]) for r in rows if r.get("tool") == "llm_call")
    return {"adopted": adopted, "fallback": fallback, "requested": req,
            "adopt_rate": round(adopted / req * 100, 1) if req else 0.0, "status": dict(status),
            "review_confirm": sum(1 for r in rows if r.get("tool") == "llm_review" and r.get("answer") == "CONFIRM"),
            "review_doubt": sum(1 for r in rows if r.get("tool") == "llm_review" and r.get("answer") == "DOUBT")}


def reduction(runs: Dict[str, dict], gold_rows: List[dict]) -> dict:
    """runs: 저장소 이름 -> scan JSON. 사람이 열어 볼 경보 = 도달(REACHED), 그중 「사람 확인 필요」 표시를 뺀 것이 unflagged.
    precision은 정답이 있는 도달 경보만으로 낸다(표본 밖은 따로 센다)."""
    gold = {(g["repo"], f'{g["package"].lower()}@{g["version"]}|{g["advisory"]}'): g["verdict"] for g in gold_rows}
    out = dict(alerts=0, reached=0, flagged=0, unflagged=0, labeled_reached=0, tp=0, unflagged_labeled=0, unflagged_tp=0)
    for name, run in runs.items():
        for a in run["alerts"]:
            out["alerts"] += 1
            if a["verdict"] != "REACHED":
                continue
            fl = bool((a.get("review") or {}).get("flagged"))
            out["reached"] += 1
            out["flagged" if fl else "unflagged"] += 1
            k = (name, f'{a["package"].lower()}@{a["version"]}|{a["advisory"]}')
            if k in gold:
                hit = gold[k] == "REACHED"
                out["labeled_reached"] += 1
                out["tp"] += hit
                if not fl:
                    out["unflagged_labeled"] += 1
                    out["unflagged_tp"] += hit
    out["precision_labeled"] = round(out["tp"] / out["labeled_reached"] * 100, 1) if out["labeled_reached"] else 0.0
    out["precision_unflagged"] = round(out["unflagged_tp"] / out["unflagged_labeled"] * 100, 1) if out["unflagged_labeled"] else 0.0
    return out
