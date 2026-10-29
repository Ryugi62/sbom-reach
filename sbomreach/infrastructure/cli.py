"""CLI: alerts(판정 없는 경보 목록) · scan · remediate · eval."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from ..application.explain import explain
from ..application.pipeline import ScanUseCase, compare_scans, plan_remediation
from ..application.report import alerts_to_dict, render_accuracy_md, render_ranking_md, scan_to_dict
from ..domain.evals import agreement
from ..domain.models import Verdict
from .gemini import GeminiLlm, load_key
from .osv_client import OsvVulnPort
from .repo_source import RepoSource
from .syft_runner import SyftSbom
from .trace import JsonlTrace
from .workcopy import apply_and_commit, make_workcopy

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EV = os.path.join(ROOT, "evidence")
SYFT = os.path.join(ROOT, "tools", "bin", "syft")


def targets():
    return {t["name"]: t for t in json.load(open(os.path.join(EV, "targets.json"), encoding="utf-8"))}


def overrides():
    return json.load(open(os.path.join(ROOT, "data", "symbol_overrides.json"), encoding="utf-8"))


def build(t, repo, trace):
    syft = SYFT if os.path.exists(SYFT) else "syft"
    return ScanUseCase(SyftSbom(syft_path=syft, excludes=t["excludes"]),
                       OsvVulnPort(cache_dir=os.path.join(ROOT, "data", "osv-cache"), overrides=overrides()),
                       RepoSource(t["excludes"]), trace)


def scan_target(t, repo, tag, trace_path):
    if os.path.exists(trace_path):
        os.remove(trace_path)
    return build(t, repo, JsonlTrace(trace_path, run_id=tag)).run(repo)


def cmd_alerts(a):
    t = targets()[a.target]
    repo = os.path.join(t["path"], t["scan_dir"]) if t["scan_dir"] else t["path"]
    os.makedirs(os.path.join(EV, "traces"), exist_ok=True)
    res = scan_target(t, repo, f"{a.target}-alerts", os.path.join(EV, "traces", f"{a.target}.alerts.jsonl"))
    out = os.path.join(EV, "alerts", f"{a.target}.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump({"target": a.target, "commit": t["commit"], "incomplete": [c.name for c in res.incomplete],
               "alerts": alerts_to_dict(res)}, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(a.target, "alerts", len(res.judgements), "components", len(res.components), "->", out)


def cmd_scan(a):
    t = targets()[a.target]
    repo = os.path.join(t["path"], t["scan_dir"]) if t["scan_dir"] else t["path"]
    os.makedirs(os.path.join(EV, "traces"), exist_ok=True)
    res = scan_target(t, repo, a.target, os.path.join(EV, "traces", f"{a.target}.jsonl"))
    d = scan_to_dict(res, a.target)
    os.makedirs(os.path.join(EV, "runs"), exist_ok=True)
    json.dump(d, open(os.path.join(EV, "runs", f"{a.target}.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    open(os.path.join(EV, "runs", f"{a.target}.ranking.md"), "w", encoding="utf-8").write(render_ranking_md(res, 20))
    print(a.target, d["counts"], "elapsed", d["elapsed_sec"], d["stage_status"])


def cmd_remediate(a):
    t = targets()[a.target]
    repo = os.path.join(t["path"], t["scan_dir"]) if t["scan_dir"] else t["path"]
    tp = os.path.join(EV, "traces", f"{a.target}.remediate-{a.scope}.jsonl")
    if os.path.exists(tp):
        os.remove(tp)
    trace = JsonlTrace(tp, run_id=f"{a.target}-{a.scope}")
    before = build(t, repo, trace).run(repo)
    plan = plan_remediation(before, a.scope, before.direct_names)
    key = None if a.no_llm else load_key()
    llm = GeminiLlm(key) if key else None
    vmap = {}
    for j in before.judgements:
        k = (j.alert.component.name, j.alert.component.version)
        if k not in vmap or j.verdict is Verdict.REACHED:
            vmap[k] = j.verdict
    plan = [explain(r, llm, vmap.get((r.package, r.current), Verdict.USED), trace) for r in plan]
    wc = make_workcopy(repo, os.path.join(ROOT, "work", f"{a.target}-{a.scope}"), name="repo")
    changed = []
    for eco in sorted({r.ecosystem for r in plan if r.target}):
        bumps = {r.package: r.target for r in plan if r.ecosystem == eco and r.target}
        trace.record({"tool": "apply_branch", "ecosystem": eco, "bumps": len(bumps)})
        changed += apply_and_commit(wc, "fix/sbomreach", bumps, eco, excludes=t["excludes"])
    after = build(t, wc, trace).run(wc)
    d = compare_scans(before, after)
    out = {"target": a.target, "scope": a.scope, "packages_changed": sum(1 for r in plan if r.target),
           "no_fix_packages": [r.package for r in plan if not r.target], "changed_files": changed,
           "diff": d.__dict__, "after_stage_status": after.stage_status, "after_incomplete": [c.name for c in after.incomplete],
           "llm_texts": sum(1 for r in plan if r.text_source == "llm"),
           "plan": [{"package": r.package, "current": r.current, "target": r.target, "verdict": r.best_verdict.value,
                     "advisories": list(r.advisory_ids), "direct": r.direct, "text": r.text, "text_source": r.text_source} for r in plan]}
    os.makedirs(os.path.join(EV, "rescan"), exist_ok=True)
    json.dump(out, open(os.path.join(EV, "rescan", f"{a.target}.{a.scope}.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(a.target, a.scope, "패키지 조치", out["packages_changed"], d.__dict__)


def cmd_eval(a):
    gold = {}
    for line in open(os.path.join(EV, "gold.jsonl"), encoding="utf-8"):
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
    open(os.path.join(EV, "accuracy.md"), "w", encoding="utf-8").write(md + "\n")
    print(md)


def main(argv=None):
    p = argparse.ArgumentParser(prog="sbomreach")
    sub = p.add_subparsers(dest="cmd", required=True)
    for n, f in (("alerts", cmd_alerts), ("scan", cmd_scan), ("remediate", cmd_remediate)):
        s = sub.add_parser(n)
        s.add_argument("--target", required=True)
        if n == "remediate":
            s.add_argument("--scope", default="reached", choices=["reached", "reached+used", "all"])
            s.add_argument("--no-llm", action="store_true")
        s.set_defaults(fn=f)
    sub.add_parser("eval").set_defaults(fn=cmd_eval)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
