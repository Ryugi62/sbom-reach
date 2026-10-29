"""JavaScript 소스 분석 — 정규식 기반(구문 분석 아님). 주석·문자열 제거 후 토큰 매칭."""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

from ..domain.models import Evidence
from ..domain.reach import SourceIndex


def strip(src: str) -> Tuple[str, str]:
    """(주석 제거본, 주석+문자열 내용 제거본). 길이·줄바꿈 유지. 문자열은 줄 끝에서 닫힌 것으로 본다."""
    code, nostr = [], []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and src[i:i + 2] == "//":
            j = src.find("\n", i)
            j = n if j < 0 else j
            code.append(" " * (j - i)); nostr.append(" " * (j - i)); i = j
        elif c == "/" and src[i:i + 2] == "/*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            seg = re.sub(r"[^\n]", " ", src[i:j])
            code.append(seg); nostr.append(seg); i = j
        elif c in "'\"`":
            q = c
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == q or (q != "`" and src[j] == "\n"):
                    break
                j += 1
            j = min(j, n - 1)
            seg = src[i:j + 1]
            code.append(seg)
            nostr.append(c + re.sub(r"[^\n]", " ", seg[1:-1]) + (seg[-1] if len(seg) > 1 else ""))
            i = j + 1
        else:
            code.append(c); nostr.append(c); i += 1
    return "".join(code), "".join(nostr)


def _root(mod: str):
    if mod.startswith((".", "/")) or not mod:
        return None, None
    parts = mod.split("/")
    if mod.startswith("@"):
        if len(parts) < 2:
            return None, None
        return "/".join(parts[:2]), ("/".join(parts[2:]) or None)
    return parts[0], ("/".join(parts[1:]) or None)


_REQ = re.compile(r"\brequire\s*\(\s*([\"'`])")
_IMP_FROM = re.compile(r"\bimport\b([^;'\"`]*?)\bfrom\s*([\"'`])")
_IMP_SIDE = re.compile(r"\bimport\s*([\"'`])")


def _line_of(src: str, pos: int) -> int:
    return src.count("\n", 0, pos) + 1


def _names(blob: str):
    out = []
    for part in blob.split(","):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"^([\w$]+)\s*(?:as|:)\s*([\w$]+)$", part)
        out.append((m.group(1), m.group(2)) if m else (part, part))
    return out


def analyze_js(files: Dict[str, str]) -> SourceIndex:
    idx = SourceIndex()
    for path in sorted(files):
        src = files[path]
        code, nostr = strip(src)
        lines = src.split("\n")

        def ev(pos: int) -> Evidence:
            n = _line_of(src, pos)
            return Evidence(path, n, lines[n - 1].strip())

        def add_import(root, pos):
            idx.imports.setdefault(root, []).append(ev(pos))

        def add_ref(root, name, pos):
            idx.refs.setdefault((root, name), []).append(ev(pos))

        def modstr(qpos: int) -> str:  # qpos = 여는 따옴표 다음 위치
            q = nostr[qpos - 1]
            end = nostr.find(q, qpos)
            return code[qpos:end] if end >= 0 else ""

        bindings: List[Tuple[str, str, str, int, int]] = []  # (ident, root, member|None, stmt_start, stmt_end)
        for m in _REQ.finditer(nostr):
            mod = modstr(m.end())
            root, sub = _root(mod)
            if not root:
                continue
            add_import(root, m.start())
            before = nostr[max(0, m.start() - 120):m.start()]
            stmt_start = m.start()
            d = re.search(r"(?:const|let|var)\s+([\w$]+)\s*=\s*$", before) or re.search(r"(?<![\w$.])([\w$]+)\s*=\s*$", before)
            if d:
                bindings.append((d.group(1), root, sub or "", stmt_start - (len(before) - d.start()), m.end()))
                if sub:
                    add_ref(root, sub.split("/")[-1], m.start())
                continue
            ds = re.search(r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*$", before)
            if ds:
                for orig, local in _names(ds.group(1)):
                    bindings.append((local, root, "member:" + orig, stmt_start - (len(before) - ds.start()), m.end()))
                continue
            after = nostr[m.end():m.end() + 200]
            close = nostr.find(")", m.end())
            tail = nostr[close + 1:close + 80] if close >= 0 else ""
            mm = re.match(r"\s*\.\s*([\w$]+)", tail)
            if mm:
                add_ref(root, mm.group(1), m.start())
            elif re.match(r"\s*\(", tail):
                add_ref(root, sub.split("/")[-1] if sub else root.split("/")[-1], m.start())
        for m in _IMP_FROM.finditer(nostr):
            mod = modstr(m.end())
            root, sub = _root(mod)
            if not root:
                continue
            add_import(root, m.start())
            spec = m.group(1)
            stmt = (m.start(), m.end())
            brace = re.search(r"\{([^}]*)\}", spec)
            if brace:
                for orig, local in _names(brace.group(1)):
                    bindings.append((local, root, "member:" + orig, *stmt))
                spec = spec.replace(brace.group(0), "")
            ns = re.search(r"\*\s*as\s+([\w$]+)", spec)
            if ns:
                bindings.append((ns.group(1), root, sub or "", *stmt))
            else:
                dflt = re.match(r"\s*([\w$]+)\s*,?\s*$", spec)
                if dflt:
                    bindings.append((dflt.group(1), root, sub or "", *stmt))
        for m in _IMP_SIDE.finditer(nostr):
            root, _ = _root(modstr(m.end()))
            if root:
                add_import(root, m.start())
        for ident, root, member, s0, s1 in bindings:
            rx = re.compile(r"(?<![\w$.])" + re.escape(ident) + r"(?![\w$])(\s*\.\s*([\w$]+))?")
            base = root.split("/")[-1]
            for u in rx.finditer(nostr):
                if s0 <= u.start() < s1:
                    continue
                if member.startswith("member:"):
                    add_ref(root, member[7:], u.start())
                elif member:
                    add_ref(root, member.split("/")[-1], u.start())
                    if u.group(2):
                        add_ref(root, u.group(2), u.start())
                elif u.group(2):
                    add_ref(root, u.group(2), u.start())
                else:
                    add_ref(root, base, u.start())
    return idx
