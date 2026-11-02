"""inspect_context 도구: 근거 줄 주변을 읽는다. 저장소 밖 경로는 거부하고, 읽기만 한다."""
from __future__ import annotations

import os
from typing import List


def read_window(repo: str, rel: str, line: int, radius: int) -> List[dict]:
    root = os.path.realpath(repo)
    path = os.path.realpath(os.path.join(root, rel))
    if os.path.isabs(rel) or not (path == root or path.startswith(root + os.sep)):
        return []
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
    except OSError:
        return []
    lo, hi = max(1, line - radius), min(len(lines), line + radius)
    return [{"line": n, "text": lines[n - 1][:200]} for n in range(lo, hi + 1)]
