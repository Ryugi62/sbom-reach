"""저장소 파일 읽기 전용 로더. 대상 코드는 읽기만 한다(실행·설치 없음)."""
from __future__ import annotations

import os
from typing import Dict, Iterable

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "site-packages", "__pycache__", "dist", "build", ".tox"}
SRC_EXT = (".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")
MANIFESTS = ("package.json", "package-lock.json")
MAX_BYTES = 1_000_000


def _walk(root: str, excludes: Iterable[str]):
    ex = [e.strip("/") for e in excludes]
    for d, dirs, files in os.walk(root):
        rel = os.path.relpath(d, root)
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS and
                         not any((os.path.normpath(os.path.join(rel, x)) == e or os.path.normpath(os.path.join(rel, x)).startswith(e + os.sep)) for e in ex))
        for f in sorted(files):
            yield os.path.normpath(os.path.join(rel, f)), os.path.join(d, f)


def _read(p: str) -> str:
    if os.path.getsize(p) > MAX_BYTES:
        return ""
    return open(p, encoding="utf-8", errors="replace").read()


def read_sources(root: str, excludes: Iterable[str] = ()) -> Dict[str, str]:
    out = {}
    for rel, p in _walk(root, excludes):
        if rel.endswith(SRC_EXT) and not rel.endswith(".min.js") and "/public/" not in "/" + rel and "/static/" not in "/" + rel:
            out[rel] = _read(p)
    return out


def read_manifests(root: str, excludes: Iterable[str] = ()) -> Dict[str, str]:
    out = {}
    for rel, p in _walk(root, excludes):
        base = os.path.basename(rel)
        if base in MANIFESTS or (base.startswith("requirements") and base.endswith(".txt")):
            out[rel] = _read(p)
    return out
