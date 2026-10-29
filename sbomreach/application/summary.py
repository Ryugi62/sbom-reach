"""증거 요약 — 문서에 들어가는 숫자는 사람이 치지 않고 여기서 계산한다."""
from __future__ import annotations

from typing import Dict, List

from ..domain.effect import estimate
from ..domain.evals import agreement


def _pred(runs: Dict[str, dict]) -> Dict[tuple, str]:
    out = {}
    for name, r in runs.items():
        for a in r["alerts"]:
            out[(name, f'{a["package"].lower()}@{a["version"]}|{a["advisory"]}')] = a["verdict"]
    return out


def _gold(rows: List[dict]) -> Dict[tuple, str]:
    return {(g["repo"], f'{g["package"].lower()}@{g["version"]}|{g["advisory"]}'): g["verdict"] for g in rows}


def accuracy_block(gold_rows: List[dict], runs: Dict[str, dict]) -> dict:
    a = agreement(_gold(gold_rows), _pred(runs))
    return {"total": a.total, "matched": a.matched, "rate": round(a.rate * 100, 1),
            "reached_precision": round(a.reached_precision * 100, 1), "reached_recall": round(a.reached_recall * 100, 1),
            "confusion": {f"{g}->{p}": n for (g, p), n in sorted(a.confusion.items())},
            "per_repo": {k: list(v) for k, v in sorted(a.per_repo.items())}}


def summarize(targets: Dict[str, dict], runs: Dict[str, dict], rescans: Dict[str, dict], dev: List[dict], hold: List[dict],
              runs_v0: Dict[str, dict], minutes_per_alert: float = 15, hourly_cost: float = 50000) -> dict:
    repos = []
    for name, t in targets.items():
        r = runs[name]
        c = r["counts"]
        repos.append({"name": name, "language": t["language"], "url": t["url"], "commit": t["commit"], "components": r["components"],
                      "alerts": c["alerts"], "reached": c["REACHED"], "used": c["USED"], "unseen": c["UNSEEN"],
                      "reached_weak": c.get("REACHED_weak", 0), "elapsed_sec": r["elapsed_sec"],
                      "stage_status": r["stage_status"], "incomplete": len(r["incomplete"])})
    tot = {k: sum(x[k] for x in repos) for k in ("components", "alerts", "reached", "used", "unseen", "reached_weak")}
    eff = estimate(tot["alerts"], tot["reached"], minutes_per_alert, hourly_cost)
    rs = {}
    for key, d in rescans.items():
        df = d["diff"]
        rs[key] = {"target": d["target"], "scope": d["scope"], "rounds": len(d["rounds"]), "packages_changed": d["packages_changed"],
                   "alerts_before": df["before_total"], "alerts_after": df["after_total"], "resolved": df["resolved"],
                   "new": df["new"], "reached_before": df["reached_before"], "reached_after": df["reached_after"],
                   "used_before": df["used_before"], "used_after": df["used_after"], "llm_texts": d["llm_texts"],
                   "reached_after_items": d.get("reached_after_items", [])}
    return {"repos": repos, "totals": tot, "languages": sorted({x["language"] for x in repos}),
            "accuracy": {"v0_dev": accuracy_block(dev, runs_v0), "v1_dev": accuracy_block(dev, runs),
                         "v1_holdout": accuracy_block(hold, runs)},
            "rescan": rs,
            "effect": {"label": eff.label, "minutes_saved": eff.minutes_saved, "hours_saved": round(eff.minutes_saved / 60, 1),
                       "cost_saved": round(eff.cost_saved)}}
