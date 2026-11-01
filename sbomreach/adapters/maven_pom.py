"""Maven pom.xml -> 부품 목록. 속성(${...})·dependencyManagement·저장소 안 부모 pom 사슬까지만 읽는다.
외부 BOM(spring-boot-starter-parent 등)이 정하는 버전은 읽지 않고 개수(unresolved)로 보고한다. 전이 의존은 보지 않는다."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, Tuple

from ..domain.models import Component

_VAR = re.compile(r"\$\{([^}]+)\}")


def _tag(e) -> str:
    return e.tag.rsplit("}", 1)[-1] if isinstance(e.tag, str) else ""


def _child(e, name):
    for c in e:
        if _tag(c) == name:
            return c
    return None


def _text(e, name) -> Optional[str]:
    c = _child(e, name)
    return c.text.strip() if c is not None and c.text and c.text.strip() else None


def _deps(parent) -> List[dict]:
    out = []
    if parent is None:
        return out
    for d in parent:
        if _tag(d) != "dependency":
            continue
        out.append({"g": _text(d, "groupId"), "a": _text(d, "artifactId"), "v": _text(d, "version"),
                    "scope": (_text(d, "scope") or "compile").lower(), "type": (_text(d, "type") or "jar").lower()})
    return out


class _Pom:
    def __init__(self, path: str, root):
        self.path = path
        par = _child(root, "parent")
        self.parent = (_text(par, "groupId"), _text(par, "artifactId"), _text(par, "version")) if par is not None else None
        self.group = _text(root, "groupId") or (self.parent[0] if self.parent else None)
        self.artifact = _text(root, "artifactId")
        self.version = _text(root, "version") or (self.parent[2] if self.parent else None)
        props = _child(root, "properties")
        self.props = {_tag(p): (p.text or "").strip() for p in props} if props is not None else {}
        dm = _child(root, "dependencyManagement")
        self.managed: Dict[Tuple[str, str], Optional[str]] = {}
        self.bom_imports: List[Tuple[Optional[str], Optional[str]]] = []
        for d in _deps(_child(dm, "dependencies") if dm is not None else None):
            if d["scope"] == "import":
                self.bom_imports.append((d["g"], d["a"]))
                continue
            if d["g"] and d["a"]:
                self.managed[(d["g"], d["a"])] = d["v"]
        self.deps = _deps(_child(root, "dependencies"))


def _interp(s: Optional[str], props: Dict[str, str]) -> Optional[str]:
    if s is None:
        return None
    for _ in range(6):
        if "${" not in s:
            return s
        s2 = _VAR.sub(lambda m: props.get(m.group(1), m.group(0)), s)
        if s2 == s:
            break
        s = s2
    return None if "${" in s else s


def components_from_poms(files: Dict[str, str]) -> Tuple[List[Component], Dict[str, int]]:
    stat = {"poms": 0, "parse_errors": 0, "total_declared": 0, "test_scope": 0, "internal": 0, "unresolved": 0, "resolved": 0}
    poms: List[_Pom] = []
    for path, text in sorted(files.items()):
        if not path.endswith("pom.xml"):
            continue
        try:
            poms.append(_Pom(path, ET.fromstring(text)))
        except (ET.ParseError, ValueError):
            stat["parse_errors"] += 1
    stat["poms"] = len(poms)
    by_ga = {(p.group, p.artifact): p for p in poms if p.artifact}
    internal: Set[Tuple[Optional[str], Optional[str]]] = set(by_ga)

    def chain(p: _Pom) -> List[_Pom]:
        out, seen = [p], {id(p)}
        while out[-1].parent:
            nxt = by_ga.get((out[-1].parent[0], out[-1].parent[1]))
            if nxt is None or id(nxt) in seen:
                break
            out.append(nxt)
            seen.add(id(nxt))
        return out

    def eff_props(p: _Pom) -> Dict[str, str]:
        props: Dict[str, str] = {}
        for q in reversed(chain(p)):          # 먼 조상부터 덮어써서 자식이 이긴다
            props.update(q.props)
        props.update({"project.version": p.version or "", "pom.version": p.version or "", "project.groupId": p.group or "",
                      "project.artifactId": p.artifact or "", "project.parent.version": (p.parent[2] if p.parent else "") or ""})
        if "revision" not in props and p.version:
            props["revision"] = p.version
        return props

    memo: Dict[int, Dict[Tuple[str, str], Optional[str]]] = {}

    def eff_managed(p: _Pom, depth: int = 0) -> Dict[Tuple[str, str], Optional[str]]:
        """관리 버전표. BOM 가져오기(import)는 저장소 안에 있으면 그 BOM의 속성 문맥으로 풀어 낮은 우선순위로 합친다."""
        if id(p) in memo:
            return memo[id(p)]
        memo[id(p)] = {}
        props = eff_props(p)
        out: Dict[Tuple[str, str], Optional[str]] = {}
        for q in reversed(chain(p)):
            if depth < 6:
                for ga in q.bom_imports:
                    bom = by_ga.get(ga)
                    if bom is not None:
                        out.update(eff_managed(bom, depth + 1))
            for ga, v in q.managed.items():
                out[ga] = _interp(v, props) if v else None
        memo[id(p)] = out
        return out

    comps: List[Component] = []
    seen_c: Set[Tuple[str, str]] = set()
    for p in poms:
        props = eff_props(p)
        managed = eff_managed(p)
        for d in p.deps:
            stat["total_declared"] += 1
            g, a = _interp(d["g"], props), _interp(d["a"], props)
            if not g or not a:
                stat["unresolved"] += 1
                continue
            if (g, a) in internal or g == p.group:   # 같은 저장소 모듈(자기 groupId)
                stat["internal"] += 1
                continue
            if d["scope"] == "test":
                stat["test_scope"] += 1
                continue
            v = _interp(d["v"] or managed.get((g, a)), props)
            if not v:
                stat["unresolved"] += 1
                continue
            if (f"{g}:{a}", v) in seen_c:
                continue
            seen_c.add((f"{g}:{a}", v))
            comps.append(Component(f"{g}:{a}", v, "Maven", True, p.path))
    stat["resolved"] = len(comps)
    return comps, stat


def direct_names_from_poms(files: Dict[str, str]) -> Set[str]:
    comps, _ = components_from_poms(files)
    return {c.name.lower() for c in comps}
