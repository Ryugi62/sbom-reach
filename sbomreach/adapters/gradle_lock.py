"""gradle.lockfile -> Maven 부품 목록. build.gradle 은 읽지 않는다(스크립트라 실행 없이는 버전이 정해지지 않는다)."""
from __future__ import annotations

import re
from typing import Dict, List

from ..domain.models import Component

_LINE = re.compile(r"^([^:#=\s]+):([^:#=\s]+):([^:#=\s]+)=(\S+)$")


def components_from_gradle_lock(files: Dict[str, str]) -> List[Component]:
    out, seen = [], set()
    for path, text in sorted(files.items()):
        if path.split("/")[-1] != "gradle.lockfile":
            continue
        for line in text.splitlines():
            m = _LINE.match(line.strip())
            if not m:
                continue
            g, a, v, confs = m.groups()
            if all(c.lower().startswith("test") for c in confs.split(",")):   # 시험 전용 구성만 있으면 제외(pom의 test scope와 같은 규칙)
                continue
            if (g, a, v) not in seen:
                seen.add((g, a, v))
                out.append(Component(f"{g}:{a}", v, "Maven", True, path))
    return out
