from __future__ import annotations

from typing import Iterable

from ..adapters.java_source import analyze_java
from ..adapters.js_source import analyze_js
from ..adapters.py_source import analyze_python
from ..domain.reach import SourceIndex
from .repo_files import read_sources


class RepoSource:
    def __init__(self, excludes: Iterable[str] = ()):
        self.excludes = list(excludes)

    def index(self, repo: str) -> SourceIndex:
        files = read_sources(repo, self.excludes)
        py = analyze_python({k: v for k, v in files.items() if k.endswith(".py")})
        js = analyze_js({k: v for k, v in files.items() if not k.endswith((".py", ".java"))})
        jv = analyze_java({k: v for k, v in files.items() if k.endswith(".java")})
        for k, v in jv.imports.items():
            py.imports.setdefault(k, []).extend(v)
        py.finder = jv.finder
        for k, v in js.imports.items():
            py.imports.setdefault(k, []).extend(v)
        for k, v in js.refs.items():
            py.refs.setdefault(k, []).extend(v)
        for k, v in js.weak_refs.items():
            py.weak_refs.setdefault(k, []).extend(v)
        for k, v in js.mentions.items():
            py.mentions.setdefault(k, []).extend(v)
        return py
