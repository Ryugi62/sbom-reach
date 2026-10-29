from __future__ import annotations

from typing import List, Tuple

from ..domain.models import Component

_ECO = {"pypi": "PyPI", "npm": "npm"}


def parse_components(doc: dict) -> List[Component]:
    out: List[Component] = []
    seen = set()
    for c in doc.get("components") or []:
        purl = c.get("purl") or ""
        if c.get("type") != "library" or not purl.startswith("pkg:"):
            continue
        eco = _ECO.get(purl[4:].split("/")[0])
        if not eco or not c.get("version"):
            continue
        key = (c["name"], c["version"], eco)
        if key in seen:
            continue
        seen.add(key)
        manifest = ""
        for p in c.get("properties") or []:
            if p.get("name") == "syft:location:0:path":
                manifest = p.get("value", "")
        out.append(Component(name=c["name"], version=c["version"], ecosystem=eco, manifest=manifest))
    return out
