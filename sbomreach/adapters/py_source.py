"""Python 소스 분석 — ast 기반 이름 해석(별칭 import 포함). 타입 추론은 하지 않는다."""
from __future__ import annotations

import ast
from typing import Dict, List, Tuple

from ..domain.models import Evidence
from ..domain.reach import SourceIndex


class _V(ast.NodeVisitor):
    def __init__(self, path: str, lines: List[str], idx: SourceIndex):
        self.path, self.lines, self.idx = path, lines, idx
        self.bind: Dict[str, Tuple] = {}

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

    def visit_Attribute(self, node):
        base = node
        while isinstance(base, ast.Attribute):
            base = base.value
        if isinstance(base, ast.Name) and base.id in self.bind:
            b = self.bind[base.id]
            self.add_ref(b[1], node.attr, node)
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
