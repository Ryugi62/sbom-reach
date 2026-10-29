"""Python 소스 분석 — ast 기반 이름 해석(별칭 import 포함). 타입 추론은 하지 않는다."""
from __future__ import annotations

import ast
import re
from typing import Dict, List, Tuple

from ..domain.models import Evidence
from ..domain.reach import SourceIndex


_DOTTED = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")


class _V(ast.NodeVisitor):
    def __init__(self, path: str, lines: List[str], idx: SourceIndex):
        self.path, self.lines, self.idx = path, lines, idx
        self.bind: Dict[str, Tuple] = {}
        self.inst: Dict[str, str] = {}   # 변수 -> 그 변수가 담은 객체의 모듈 뿌리

    def ev(self, node) -> Evidence:
        n = node.lineno
        return Evidence(self.path, n, self.lines[n - 1].strip() if 0 < n <= len(self.lines) else "")

    def add_ref(self, root: str, name: str, node):
        self.idx.refs.setdefault((root, name), []).append(self.ev(node))

    def visit_Import(self, node):
        for a in node.names:
            root = a.name.split(".")[0]
            self.bind[a.asname or root] = ("mod", root)
            self.idx.imports.setdefault(root, []).append(self.ev(node))

    def visit_ImportFrom(self, node):
        if node.level or not node.module:
            return
        root = node.module.split(".")[0]
        self.idx.imports.setdefault(root, []).append(self.ev(node))
        for a in node.names:
            self.bind[a.asname or a.name] = ("from", root, a.name)

    def visit_Name(self, node):
        b = self.bind.get(node.id)
        if b and b[0] == "from" and isinstance(node.ctx, ast.Load):
            self.add_ref(b[1], b[2], node)

    def _root_of_call(self, call):
        f = call.func
        while isinstance(f, ast.Attribute):
            f = f.value
        if isinstance(f, ast.Name) and f.id in self.bind:
            return self.bind[f.id][1]
        return None

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Call) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            root = self._root_of_call(node.value)
            if root:
                self.inst[node.targets[0].id] = root
        self.generic_visit(node)

    def visit_Constant(self, node):
        v = node.value
        if isinstance(v, str) and len(v) < 80 and _DOTTED.match(v):
            self.idx.mentions.setdefault(v.split(".")[0], []).append(self.ev(node))

    def visit_Attribute(self, node):
        base = node
        while isinstance(base, ast.Attribute):
            base = base.value
        if isinstance(base, ast.Name) and base.id in self.bind:
            b = self.bind[base.id]
            self.add_ref(b[1], node.attr, node)
        elif isinstance(base, ast.Name) and base.id in self.inst:
            self.add_ref(self.inst[base.id], node.attr, node)
        elif isinstance(node.ctx, ast.Load):
            self.idx.weak_refs.setdefault(node.attr, []).append(self.ev(node))
        self.generic_visit(node)


def analyze_python(files: Dict[str, str]) -> SourceIndex:
    idx = SourceIndex()
    for path in sorted(files):
        text = files[path]
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            continue
        _V(path, text.split("\n"), idx).visit(tree)
    return idx
