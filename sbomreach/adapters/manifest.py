"""매니페스트 편집 — 조치 적용 가지에서만 쓴다."""
from __future__ import annotations

import json
import re
from typing import Dict

from ..domain.packages import normalize

_LINE = re.compile(r"^(\s*)([A-Za-z0-9][A-Za-z0-9_.\-]*)(\[[^\]]*\])?(\s*==\s*)([^\s;#]+)(.*)$")


def bump_requirements(text: str, targets: Dict[str, str]) -> str:
    want = {normalize(k): v for k, v in targets.items()}
    out = []
    for line in text.split("\n"):
        m = _LINE.match(line)
        if m and normalize(m.group(2)) in want:
            line = f"{m.group(1)}{m.group(2)}{m.group(3) or ''}{m.group(4)}{want[normalize(m.group(2))]}{m.group(6)}"
        out.append(line)
    return "\n".join(out)


def bump_package_json(text: str, targets: Dict[str, str]) -> str:
    doc = json.loads(text)
    placed = set()
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        for name in list((doc.get(sec) or {})):
            if name in targets:
                doc[sec][name] = targets[name]
                placed.add(name)
    rest = {k: v for k, v in targets.items() if k not in placed}
    if rest:
        doc.setdefault("overrides", {}).update(rest)
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
