#!/usr/bin/env python3
"""같은 고정 커밋 저장소를 osv-scanner·grype·trivy로 스캔해 경보 수를 세고 evidence/scanner-compare.md 를 쓴다(SPEC S19).
도구는 tools/scanners/ 의 단일 바이너리(무료)다. 저장소는 .git 을 뺀 복사본에서 읽기만 하고, 우리 excludes 와 같은 폴더를 뺀다.
사용: python3 scripts/compare_scanners.py [--only name ...]"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from sbomreach.adapters.scanner_reports import parse_grype, parse_osv, parse_trivy  # noqa: E402
from sbomreach.application.scanner_compare import Row, ToolResult, ours_from_run, render_table  # noqa: E402
from sbomreach.infrastructure.cli import targets, target_repo_dir  # noqa: E402

BIN = os.path.join(ROOT, "tools", "scanners")
TIMEOUT = 900


def cmds(binary, scan_dir, out):
    return {
        "osv-scanner": ([binary, "scan", "source", "-r", "--format", "json", "--output-file", out, scan_dir], parse_osv, True),
        "grype": ([binary, f"dir:{scan_dir}", "-o", "json", "--file", out], parse_grype, False),
        "trivy": ([binary, "fs", "--scanners", "vuln", "--format", "json", "--output", out, "--quiet", scan_dir], parse_trivy, False),
    }


def version(name, binary):
    flag = {"osv-scanner": "--version", "grype": "version", "trivy": "--version"}[name]
    try:
        r = subprocess.run([binary, flag], capture_output=True, text=True, timeout=30)
        lines = (r.stdout or r.stderr).strip().splitlines()
        return next((l.strip() for l in lines if l.strip().startswith("Version")), lines[0].strip())
    except (OSError, subprocess.SubprocessError, IndexError) as e:
        return f"버전 확인 실패: {e}"


def prepare(t, tmp):
    src = os.path.abspath(target_repo_dir(t))
    dst = os.path.join(tmp, t["name"])

    def ign(d, names):
        out = [n for n in names if n == ".git"]
        if os.path.abspath(d) == src:
            out += [n for n in names if n in t["excludes"]]
        return out
    shutil.copytree(src, dst, ignore=ign, symlinks=True)
    return dst


def run_tool(name, binary, scan_dir, tmp):
    out = os.path.join(tmp, f"{name}.json")
    if os.path.exists(out):
        os.remove(out)   # 이전 저장소의 보고서를 이번 결과로 읽는 사고를 막는다
    argv, parse, nonzero_ok = cmds(binary, scan_dir, out)[name]
    if not os.path.exists(binary):
        return ToolResult(None, f"실행 파일 없음: {binary}"), None
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT)
    except (OSError, subprocess.SubprocessError) as e:
        return ToolResult(None, f"{type(e).__name__}: {e}"), None
    try:
        found = parse(open(out, encoding="utf-8").read())
    except (OSError, ValueError) as e:   # 보고서 미생성·JSON 아님 = 실행 못 함(오류 원문을 그대로 적는다)
        tail = (r.stderr or r.stdout).strip().splitlines()[-3:]
        return ToolResult(None, f"exit {r.returncode}; " + " / ".join(tail)[:300]), None
    return ToolResult(len(found)), sorted(found)


def run_tool_with_fallback(name, binary, scan_dir, tmp):
    """trivy가 Maven Central 429로 멈추면 --offline-scan(원격 pom 해석 생략)으로 한 번 더 돌리고, 그 사실을 칸에 적는다."""
    res, found = run_tool(name, binary, scan_dir, tmp)
    if name == "trivy" and res.count is None and "429" in res.error:
        first = res.error
        out = os.path.join(tmp, "trivy.json")
        if os.path.exists(out):
            os.remove(out)
        argv = cmds(binary, scan_dir, out)["trivy"][0] + ["--offline-scan"]
        try:
            subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT)
            n = len(parse_trivy(open(out, encoding="utf-8").read()))
            return ToolResult(n, "Maven Central 429로 원격 pom 해석 생략(--offline-scan), 전이 의존 일부 누락 가능"), None
        except (OSError, ValueError, subprocess.SubprocessError) as e:
            return ToolResult(None, f"{first} / 재시도(--offline-scan)도 실패: {e}"[:400]), None
    return res, found


def main(argv):
    only = argv[argv.index("--only") + 1:] if "--only" in argv else None
    tg = targets()
    jp = os.path.join(ROOT, "evidence", "scanner-compare.json")
    old = json.load(open(jp, encoding="utf-8")) if only and os.path.exists(jp) else {"per_repo": {}}
    detail = dict(old["per_repo"])
    with tempfile.TemporaryDirectory() as tmp:
        for name, t in tg.items():
            if only and name not in only:
                continue
            runp = os.path.join(ROOT, "evidence", "runs", f"{name}.json")
            if not os.path.exists(runp) or not os.path.isdir(target_repo_dir(t)):
                print("건너뜀(실행 기록 또는 저장소 없음):", name)
                continue
            sd = prepare(t, tmp)
            detail[name] = {}
            for tool in ("osv-scanner", "grype", "trivy"):
                r, _ = run_tool_with_fallback(tool, os.path.join(BIN, tool), sd, tmp)
                detail[name][tool] = {"count": r.count, "error": r.error}
                print(name, tool, r, flush=True)
            shutil.rmtree(sd, ignore_errors=True)
    rows = []
    for name in tg:
        runp = os.path.join(ROOT, "evidence", "runs", f"{name}.json")
        if name in detail and os.path.exists(runp):
            total, m, k = ours_from_run(json.load(open(runp, encoding="utf-8")))
            rows.append(Row(name, {n: ToolResult(v["count"], v["error"]) for n, v in detail[name].items()}, total, m, k))
    vers = {n: version(n, os.path.join(BIN, n)) for n in ("osv-scanner", "grype", "trivy")}
    md = ["# 스캐너 비교 — 같은 고정 커밋, 경보 개수 (SPEC S19)", "",
          "측정 " + __import__("time").strftime("%Y-%m-%d") + " · 무료 단일 바이너리 · 결제 0 · 저장소는 읽기만(.git·우리 excludes 제외한 복사본)", "",
          "도구 버전: " + " · ".join(f"{k} `{v}`" for k, v in vers.items()), "",
          render_table(rows), "",
          "읽는 법", "- 그들의 경보 = 패키지×버전×취약점 id 고유 건수(osv-scanner는 별칭 묶음 1건, grype·trivy는 보고서의 id 그대로라 같은 취약점이 CVE·GHSA로 따로 셀 수 있음).",
          "- 우리 전체 경보 = 우리 파이프라인이 만든 Alert 수(별칭 중복 제거). M = 근거 줄이 있는 `REACHED`, K = 그 근거 줄 합.",
          "- 개수 비교일 뿐이다. 이 도구들은 소스 호출 여부를 판정하지 않으므로(설계 목적이 다름) 정밀도 비교가 아니며 틀렸다는 뜻도 아니다. 도구마다 읽는 파일(잠금 파일·매니페스트·소스 트리)이 달라 개수가 다르다.",
          "- 「실행 못 함」 칸은 숫자를 채우지 않고 오류 원문을 적었다.", ""]
    open(os.path.join(ROOT, "evidence", "scanner-compare.md"), "w", encoding="utf-8").write("\n".join(md))
    json.dump({"versions": vers, "per_repo": detail}, open(os.path.join(ROOT, "evidence", "scanner-compare.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("\n".join(md))


if __name__ == "__main__":
    main(sys.argv[1:])
