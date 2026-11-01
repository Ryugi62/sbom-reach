"""CLI: alerts(판정 없는 경보 목록) · scan · remediate · eval."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from ..application.explain import explain
from ..application.pipeline import ScanUseCase, compare_scans, plan_remediation
from ..application.report import alerts_to_dict, render_accuracy_md, render_flag_table_md, render_ranking_md, scan_to_dict
from ..application.review import review_reached
from ..domain.evals import agreement, precision_by_flag
from ..domain.models import Verdict
from .gemini import GeminiLlm, load_key
from .maven_sbom import MavenSbom
from .osv_client import OsvVulnPort
from .repo_source import RepoSource
from .syft_runner import SyftSbom
from .trace import JsonlTrace
from .workcopy import apply_and_commit, make_workcopy

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EV = os.path.join(ROOT, "evidence")
SYFT = os.path.join(ROOT, "tools", "bin", "syft")


def target_repo_dir(t):
    """targets.json의 path는 저장소 루트 기준 상대경로(scripts/clone_targets.py가 받아 둔다)."""
    path = os.path.expanduser(t["path"])
    base = path if os.path.isabs(path) else os.path.join(ROOT, path)
    return os.path.join(base, t["scan_dir"]) if t["scan_dir"] else base


def targets(java: bool = True):
    """targets.json(Python·JS 4곳) + targets-java.json(운영형 오픈소스 Java, 홈의 ~/untrusted 에 받는다)."""
    out = {t["name"]: t for t in json.load(open(os.path.join(EV, "targets.json"), encoding="utf-8"))}
    jp = os.path.join(EV, "targets-java.json")
    if java and os.path.exists(jp):
        out.update({t["name"]: t for t in json.load(open(jp, encoding="utf-8"))})
    return out


def overrides():
    return json.load(open(os.path.join(ROOT, "data", "symbol_overrides.json"), encoding="utf-8"))


def common_names():
    """data/generic_names.json (scripts/build_generic_names.py). 없으면 빈 사전 = v1.2 동작."""
    try:
        return frozenset(json.load(open(os.path.join(ROOT, "data", "generic_names.json"), encoding="utf-8"))["names"])
    except (OSError, ValueError, KeyError):
        return frozenset()


def build(t, repo, trace):
    syft = SYFT if os.path.exists(SYFT) else "syft"
    sbom = MavenSbom(t["excludes"]) if t.get("language") == "Java" else SyftSbom(syft_path=syft, excludes=t["excludes"])
    return ScanUseCase(sbom,
                       OsvVulnPort(cache_dir=os.path.join(ROOT, "data", "osv-cache"), overrides=overrides()),
                       RepoSource(t["excludes"]), trace, common_names())


def scan_target(t, repo, tag, trace_path):
    if os.path.exists(trace_path):
        os.remove(trace_path)
    return build(t, repo, JsonlTrace(trace_path, run_id=tag)).run(repo)


def cmd_alerts(a):
    t = targets()[a.target]
    repo = target_repo_dir(t)
    os.makedirs(os.path.join(EV, "traces"), exist_ok=True)
    res = scan_target(t, repo, f"{a.target}-alerts", os.path.join(EV, "traces", f"{a.target}.alerts.jsonl"))
    out = os.path.join(EV, "alerts", f"{a.target}.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump({"target": a.target, "commit": t["commit"], "incomplete": [c.name for c in res.incomplete],
               "alerts": alerts_to_dict(res)}, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(a.target, "alerts", len(res.judgements), "components", len(res.components), "->", out)


def make_llm(trace):
    key = load_key()
    return GeminiLlm(key, trace=trace, cache_path=os.path.join(ROOT, "data", "llm-cache.json")) if key else None


def cmd_scan(a):
    t = targets()[a.target]
    repo = target_repo_dir(t)
    os.makedirs(os.path.join(EV, "traces"), exist_ok=True)
    tp = os.path.join(EV, "traces", f"{a.target}.jsonl")
    res = scan_target(t, repo, a.target, tp)
    reviews = None
    if a.review:   # SPEC S12: 판정은 이미 끝났다. LLM은 표시만 붙이고 판정 필드를 만들 수 없다
        trace = JsonlTrace(tp, run_id=a.target)
        llm = make_llm(trace)
        reviews = review_reached(res.judgements, llm, trace, common_names()) if llm else {}
    d = scan_to_dict(res, a.target, reviews)
    os.makedirs(os.path.join(EV, "runs"), exist_ok=True)
    json.dump(d, open(os.path.join(EV, "runs", f"{a.target}.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    open(os.path.join(EV, "runs", f"{a.target}.ranking.md"), "w", encoding="utf-8").write(render_ranking_md(res, 20))
    print(a.target, d["counts"], "elapsed", d["elapsed_sec"], d["stage_status"])


def cmd_remediate(a):
    t = targets()[a.target]
    repo = target_repo_dir(t)
    tp = os.path.join(EV, "traces", f"{a.target}.remediate-{a.scope}.jsonl")
    if os.path.exists(tp):
        os.remove(tp)
    trace = JsonlTrace(tp, run_id=f"{a.target}-{a.scope}")
    before = build(t, repo, trace).run(repo)
    llm = None if a.no_llm else make_llm(trace)
    wc = make_workcopy(repo, os.path.join(ROOT, "work", f"{a.target}-{a.scope}"), name="repo")
    cur, rounds, all_changed = before, [], []
    for n in range(1, a.max_rounds + 1):
        scope = a.scope if n == 1 else "reached"   # 개선 순환: 2바퀴부터는 남은·새 도달 경보만
        plan = [r for r in plan_remediation(cur, scope, cur.direct_names) if r.target]
        if not plan:
            break
        vmap = {}
        for j in cur.judgements:
            k = (j.alert.component.name, j.alert.component.version)
            if k not in vmap or j.verdict is Verdict.REACHED:
                vmap[k] = j.verdict
        plan = [explain(r, llm, vmap.get((r.package, r.current), Verdict.USED), trace) for r in plan]
        changed = []
        for eco in sorted({r.ecosystem for r in plan}):
            bumps = {r.package: r.target for r in plan if r.ecosystem == eco}
            trace.record({"tool": "apply_branch", "round": n, "ecosystem": eco, "bumps": len(bumps)})
            changed += apply_and_commit(wc, "fix/sbomreach", bumps, eco, excludes=t["excludes"])
        if not changed:
            trace.record({"tool": "apply_branch", "round": n, "result": "no_progress"})
            break
        all_changed += changed
        after = build(t, wc, trace).run(wc)
        rounds.append({"round": n, "scope": scope, "packages_changed": len(plan), "changed_files": changed,
                       "reached_after": after.count(Verdict.REACHED), "alerts_after": len(after.judgements),
                       "plan": [{"package": r.package, "current": r.current, "target": r.target, "verdict": r.best_verdict.value,
                                 "advisories": list(r.advisory_ids), "direct": r.direct, "text": r.text, "text_source": r.text_source} for r in plan]})
        cur = after
        if after.count(Verdict.REACHED) == 0:
            break
    d = compare_scans(before, cur)
    out = {"target": a.target, "scope": a.scope, "rounds": rounds,
           "packages_changed": sum(r["packages_changed"] for r in rounds), "changed_files": sorted(set(all_changed)),
           "diff": d.__dict__, "after_stage_status": cur.stage_status, "after_incomplete": [c.name for c in cur.incomplete],
           "reached_after_items": [f"{j.alert.component.name}@{j.alert.component.version}:{j.alert.advisory.id}" for j in cur.judgements if j.verdict is Verdict.REACHED],
           "llm_texts": sum(1 for rr in rounds for p in rr["plan"] if p["text_source"] == "llm"),
           "unfixed_alerts_after": sum(1 for j in cur.judgements if not j.alert.advisory.fixed_versions)}
    os.makedirs(os.path.join(EV, "rescan"), exist_ok=True)
    json.dump(out, open(os.path.join(EV, "rescan", f"{a.target}.{a.scope}.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(a.target, a.scope, "라운드", len(rounds), "패키지 조치", out["packages_changed"], d.__dict__)


def cmd_eval(a):
    gold = {}
    for line in open(os.path.join(EV, a.gold), encoding="utf-8"):
        if line.strip():
            g = json.loads(line)
            gold[(g["repo"], f'{g["package"].lower()}@{g["version"]}|{g["advisory"]}')] = g["verdict"]
    pred = {}
    for name in targets():
        p = os.path.join(EV, "runs", f"{name}.json")
        if os.path.exists(p):
            for x in json.load(open(p, encoding="utf-8"))["alerts"]:
                pred[(name, f'{x["package"].lower()}@{x["version"]}|{x["advisory"]}')] = x["verdict"]
    md = render_accuracy_md(agreement(gold, pred))
    open(os.path.join(EV, a.out), "w", encoding="utf-8").write(md + "\n")
    print(md)


def cmd_flagtable(a):
    rows = []
    for gname in a.gold:
        gold = {}
        for line in open(os.path.join(EV, gname), encoding="utf-8"):
            if line.strip():
                g = json.loads(line)
                gold[(g["repo"], f'{g["package"].lower()}@{g["version"]}|{g["advisory"]}')] = g["verdict"]
        pred, flagged = {}, set()
        for name in targets():
            for x in json.load(open(os.path.join(EV, "runs", f"{name}.json"), encoding="utf-8"))["alerts"]:
                k = (name, f'{x["package"].lower()}@{x["version"]}|{x["advisory"]}')
                pred[k] = x["verdict"]
                if (x.get("review") or {}).get("flagged"):
                    flagged.add(k)
        rows.append((gname.replace(".jsonl", ""), precision_by_flag(gold, pred, flagged)))
    md = render_flag_table_md(rows)
    open(os.path.join(EV, a.out), "w", encoding="utf-8").write(md + "\n")
    print(md)


def cmd_summary(a):
    import glob
    from ..application.summary import summarize
    load = lambda p: json.load(open(p, encoding="utf-8"))
    rows = lambda p: [json.loads(x) for x in open(p, encoding="utf-8") if x.strip()]
    tg = targets(java=False)
    runs = {n: load(os.path.join(EV, "runs", f"{n}.json")) for n in tg}
    v0 = {n: load(os.path.join(EV, "runs-v0", f"{n}.json")) for n in tg}
    rs = {os.path.basename(p)[:-5]: load(p) for p in sorted(glob.glob(os.path.join(EV, "rescan", "*.json")))}
    out = summarize(tg, runs, rs, rows(os.path.join(EV, "gold.jsonl")), rows(os.path.join(EV, "gold-holdout.jsonl")), v0)
    json.dump(out, open(os.path.join(EV, "summary.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps(out["totals"], ensure_ascii=False), out["accuracy"]["v1_holdout"]["rate"])


def main(argv=None):
    p = argparse.ArgumentParser(prog="sbomreach")
    sub = p.add_subparsers(dest="cmd", required=True)
    for n, f in (("alerts", cmd_alerts), ("scan", cmd_scan), ("remediate", cmd_remediate)):
        s = sub.add_parser(n)
        s.add_argument("--target", required=True)
        if n == "scan":
            s.add_argument("--review", action="store_true", help="REACHED 후보에 LLM 판정 보조 표시(판정 불변)")
        if n == "remediate":
            s.add_argument("--scope", default="reached", choices=["reached", "reached+used", "all"])
            s.add_argument("--no-llm", action="store_true")
            s.add_argument("--max-rounds", type=int, default=3)
        s.set_defaults(fn=f)
    sub.add_parser("summary").set_defaults(fn=cmd_summary)
    f = sub.add_parser("flagtable")
    f.add_argument("--gold", nargs="+", required=True)
    f.add_argument("--out", default="review-flag.md")
    f.set_defaults(fn=cmd_flagtable)
    e = sub.add_parser("eval")
    e.add_argument("--gold", default="gold.jsonl")
    e.add_argument("--out", default="accuracy.md")
    e.set_defaults(fn=cmd_eval)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
