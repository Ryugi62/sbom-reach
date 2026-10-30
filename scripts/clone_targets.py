#!/usr/bin/env python3
"""evidence/targets.json의 공개 저장소 4곳을 고정 커밋으로 untrusted/ 아래에 받는다. 받기만 하고 코드는 실행·설치하지 않는다.
사용: python3 scripts/clone_targets.py [--dry-run]"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def plan(targets, root):
    out = []
    base = os.path.realpath(os.path.join(root, "untrusted"))
    for t in targets:
        if os.path.isabs(t["path"]):
            raise ValueError(f"절대경로 금지: {t['path']}")
        dst = os.path.normpath(os.path.join(root, t["path"]))
        if not dst.startswith(os.path.join(os.path.normpath(root), "untrusted") + os.sep):
            raise ValueError(f"untrusted/ 밖 경로: {t['path']}")
        out.append((["git", "clone", "--no-checkout", t["url"], dst], None))
        out.append((["git", "checkout", "--detach", t["commit"]], dst))
    return out


def main(argv):
    targets = json.load(open(os.path.join(ROOT, "evidence", "targets.json"), encoding="utf-8"))
    for cmd, cwd in plan(targets, ROOT):
        print(("$ (cd %s) " % cwd if cwd else "$ ") + " ".join(cmd))
        if "--dry-run" in argv:
            continue
        if cmd[1] == "clone" and os.path.exists(cmd[-1]):
            continue
        subprocess.run(cmd, cwd=cwd, check=True)


if __name__ == "__main__":
    main(sys.argv[1:])
