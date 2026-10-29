"""syft가 없을 때의 대체 SBOM(잠금 파일 파서) + 직접 선언 이름."""
from __future__ import annotations

import json
import re
from typing import Dict, List, Set

from ..domain.models import Component
from ..domain.packages import normalize

_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)")


def _py(text: str) -> List[Component]:
    out = []
    for line in text.splitlines():
        m = _REQ.match(line)
        if m:
            out.append(Component(m.group(1), m.group(2), "PyPI"))
    return out


def _walk_v1(deps: dict, acc: List[Component]):
    for name, d in (deps or {}).items():
        if d.get("version"):
            acc.append(Component(name, d["version"], "npm"))
        _walk_v1(d.get("dependencies") or {}, acc)


def _npm(text: str) -> List[Component]:
    doc = json.loads(text)
    acc: List[Component] = []
    if "packages" in doc:
        for path, meta in doc["packages"].items():
            if not path or meta.get("link") or not meta.get("version") or "node_modules/" not in path:
                continue
            acc.append(Component(path.split("node_modules/")[-1], meta["version"], "npm"))
    else:
        _walk_v1(doc.get("dependencies") or {}, acc)
    return acc


def components_from_files(files: Dict[str, str]) -> List[Component]:
    out: List[Component] = []
    seen = set()
    for path, text in sorted(files.items()):
        base = path.split("/")[-1]
        try:
            comps = _py(text) if base.startswith("requirements") and base.endswith(".txt") else \
                _npm(text) if base == "package-lock.json" else []
        except (ValueError, KeyError):
            comps = []
        for c in comps:
            k = (c.name.lower(), c.version, c.ecosystem)
            if k not in seen:
                seen.add(k)
                out.append(Component(c.name, c.version, c.ecosystem, manifest=path))
    return out


def direct_names_from_files(files: Dict[str, str]) -> Set[str]:
    names: Set[str] = set()
    for path, text in files.items():
        base = path.split("/")[-1]
        if base == "package.json":
            try:
                doc = json.loads(text)
            except ValueError:
                continue
            for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                names |= {n.lower() for n in (doc.get(sec) or {})}
        elif base.startswith("requirements") and base.endswith(".txt"):
            for line in text.splitlines():
                m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)", line)
                if m and not line.lstrip().startswith(("-", "#")):
                    names.add(normalize(m.group(1)))
    return names
