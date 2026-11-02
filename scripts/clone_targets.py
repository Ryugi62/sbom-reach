#!/usr/bin/env python3
"""targets.json(Python·JS 4곳, 저장소 안 untrusted/)·targets-java.json(Java 3곳)·targets-ops.json(운영형 Python·JS 2곳)의
공개 저장소 9곳을 고정 커밋으로 받는다(Java·운영형은 홈의 ~/untrusted/). 받기만 하고 코드는 실행·설치하지 않는다.
사용: python3 scripts/clone_targets.py [--dry-run]"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def all_targets(evidence_dir):
    out = []
    for f in ("targets.json", "targets-java.json", "targets-ops.json"):
        out += json.load(open(os.path.join(evidence_dir, f), encoding="utf-8"))
    return out


def plan(targets, root, home=None):
    out = []
    home = home or os.path.expanduser("~")
    for t in targets:
        if t["path"].startswith("~/"):
            top = os.path.join(os.path.normpath(home), "untrusted")
            dst = os.path.normpath(os.path.join(home, t["path"][2:]))
        elif os.path.isabs(t["path"]):
            raise ValueError(f"절대경로 금지: {t['path']}")
        else:
            top = os.path.join(os.path.normpath(root), "untrusted")
            dst = os.path.normpath(os.path.join(root, t["path"]))
        if not dst.startswith(top + os.sep):
            raise ValueError(f"untrusted/ 밖 경로: {t['path']}")
        out.append((["git", "clone", "--no-checkout", t["url"], dst], None))
        out.append((["git", "checkout", "--detach", t["commit"]], dst))
    return out


def main(argv):
    targets = all_targets(os.path.join(ROOT, "evidence"))
    for cmd, cwd in plan(targets, ROOT):
        print(("$ (cd %s) " % cwd if cwd else "$ ") + " ".join(cmd))
        if "--dry-run" in argv:
            continue
        if cmd[1] == "clone" and os.path.exists(cmd[-1]):
            continue
        subprocess.run(cmd, cwd=cwd, check=True)


if __name__ == "__main__":
    main(sys.argv[1:])
