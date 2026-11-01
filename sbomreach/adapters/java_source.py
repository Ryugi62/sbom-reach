"""Java 소스 분석 — import 줄과 클래스·메서드 이름 사용. 컴파일·타입 추론 없음(이름 일치 + import 존재 확인)."""
from __future__ import annotations

import re
from typing import Dict, List, Sequence, Set, Tuple

from ..domain.models import Evidence
from ..domain.reach import SourceIndex
from .js_source import strip

_IMPORT = re.compile(r"^\s*import\s+(static\s+)?([\w.]+?)(\.\*)?\s*;")
_IDENT = re.compile(r"\b[A-Za-z_]\w*\b")
_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


def _prefixes(name: str) -> List[str]:
    parts = name.split(".")
    return [".".join(parts[:i]) for i in range(2, len(parts) + 1)]


def analyze_java(files: Dict[str, str]) -> SourceIndex:
    idx = SourceIndex()
    classes: Dict[str, Dict[str, str]] = {}        # 파일 -> {단순 이름: 전체 이름}
    wild: Dict[str, Set[str]] = {}                 # 파일 -> 와일드카드 import 패키지
    prefs: Dict[str, Set[str]] = {}                # 파일 -> import 접두 전부
    idents: Dict[str, Dict[str, List[int]]] = {}   # 파일 -> 이름 -> 줄들
    calls: Dict[str, Dict[str, List[int]]] = {}
    orig: Dict[str, List[str]] = {}
    for path in sorted(files):
        text = files[path]
        if "import " not in text:
            continue
        _code, nostr = strip(text)
        lines, olines = nostr.split("\n"), text.split("\n")
        orig[path] = olines
        cm, wd, pf, idl, cl = {}, set(), set(), {}, {}
        for n, line in enumerate(lines, 1):
            m = _IMPORT.match(line)
            if m:
                static, name, star = bool(m.group(1)), m.group(2), bool(m.group(3))
                for pre in _prefixes(name):
                    pf.add(pre)
                    idx.imports.setdefault(pre, []).append(Evidence(path, n, olines[n - 1].strip()))
                if star:
                    wd.add(name)
                elif not static:
                    cm[name.rsplit(".", 1)[-1]] = name
                else:
                    cm[name.rsplit(".", 1)[-1]] = name   # 정적 import 한 멤버도 단순 이름으로 쓴다
                continue
            if line.lstrip().startswith("package "):
                continue
            for w in _IDENT.findall(line):
                idl.setdefault(w, []).append(n)
            for w in _CALL.findall(line):
                cl.setdefault(w, []).append(n)
        classes[path], wild[path], prefs[path], idents[path], calls[path] = cm, wd, pf, idl, cl

    def finder(name: str, mods: Sequence[str], kind: str) -> List[Evidence]:
        out: List[Evidence] = []
        for path in classes:
            ls: List[int] = []
            if kind == "class":
                full = classes[path].get(name)
                ok = bool(full) and any(full.startswith(m + ".") or full == m for m in mods)
                ok = ok or (name[:1].isupper() and any(w == m or w.startswith(m + ".") or m.startswith(w + ".") for w in wild[path] for m in mods))
                if ok:
                    ls = idents[path].get(name, [])
            else:
                if any(m in prefs[path] for m in mods):
                    ls = calls[path].get(name, [])
            for n in sorted(set(ls)):
                out.append(Evidence(path, n, orig[path][n - 1].strip()))
        return out

    idx.finder = finder
    return idx
