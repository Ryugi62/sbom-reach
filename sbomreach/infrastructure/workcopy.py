"""조치 적용 가지 — 원본 저장소를 건드리지 않고 사본에서 git 가지를 만들어 매니페스트만 고친다."""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import Callable, Dict, List

from ..adapters.manifest import bump_package_json, bump_requirements
from ..domain import guardrails
from .repo_files import SKIP_DIRS

ENV = dict(os.environ, GIT_AUTHOR_NAME="Jarvis", GIT_AUTHOR_EMAIL="sbomreach@example.invalid",
           GIT_COMMITTER_NAME="Jarvis", GIT_COMMITTER_EMAIL="sbomreach@example.invalid")


def default_run(argv: List[str], cwd: str) -> str:
    chk = guardrails.check_command(argv)
    if not chk.ok:
        raise PermissionError(f"{chk.rule}: {chk.why}")
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=True, env=ENV, timeout=600).stdout


def make_workcopy(src: str, work_root: str, name: str, run=default_run) -> str:
    dst = os.path.join(work_root, name)
    if os.path.exists(dst):
        shutil.rmtree(dst)
    os.makedirs(work_root, exist_ok=True)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(*SKIP_DIRS))
    run(["git", "init", "-q"], dst)
    run(["git", "add", "-A"], dst)
    run(["git", "commit", "-q", "-m", "baseline"], dst)
    return dst


def apply_and_commit(wc: str, branch: str, bumps: Dict[str, str], ecosystem: str, run=default_run,
                     excludes=()) -> List[str]:
    """bumps: 패키지 -> 목표 버전. 바뀐 파일 목록을 돌려준다."""
    if not _on(wc, branch, run):
        run(["git", "checkout", "-q", "-b", branch], wc)
    changed = []
    for d, dirs, files in os.walk(wc):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not any(os.path.relpath(os.path.join(d, x), wc).startswith(e.strip("/")) for e in excludes if e)]
        for f in files:
            p = os.path.join(d, f)
            if ecosystem == "PyPI" and f.startswith("requirements") and f.endswith(".txt"):
                old = open(p, encoding="utf-8").read()
                new = bump_requirements(old, bumps)
            elif ecosystem == "npm" and f == "package.json" and d == wc:
                old = open(p, encoding="utf-8").read()
                new = bump_package_json(old, bumps)
            else:
                continue
            if new != old:
                open(p, "w", encoding="utf-8").write(new)
                changed.append(os.path.relpath(p, wc))
    if ecosystem == "npm" and changed:
        run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--legacy-peer-deps", "--no-audit", "--no-fund"], wc)
        changed.append("package-lock.json")
    run(["git", "add", "-A"], wc)
    run(["git", "commit", "-q", "-m", f"sbomreach: {ecosystem} 취약 의존성 {len(bumps)}개 버전 조치"], wc)
    return changed


def _on(wc: str, branch: str, run) -> bool:
    try:
        return run(["git", "rev-parse", "--abbrev-ref", "HEAD"], wc).strip() == branch
    except subprocess.CalledProcessError:
        return False
