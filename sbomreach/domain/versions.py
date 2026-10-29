"""버전 비교 — 표준 라이브러리 정규식만."""
from __future__ import annotations

import re
from typing import Iterable, List, Optional, Tuple

_TOK = re.compile(r"(\d+)|([A-Za-z]+)")


def _key(v: str) -> Tuple[Tuple[int, ...], int, Tuple]:
    v = v.strip().lstrip("vV")
    m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", v)
    if not m:
        return ((0,), 0, ((1, v),))
    nums = [int(x) for x in m.group(1).split(".")]
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    rest = m.group(2).strip("-_.+")
    if not rest:
        return (tuple(nums), 1, ())
    toks = tuple((0, int(a)) if a else (1, b.lower()) for a, b in _TOK.findall(rest))
    return (tuple(nums), 0, toks)  # 접미사가 있으면 같은 숫자의 정식 버전보다 낮다(rc·beta·dev 등)


def compare(a: str, b: str) -> int:
    ka, kb = _key(a), _key(b)
    return (ka > kb) - (ka < kb)


def _major(v: str) -> int:
    return _key(v)[0][0]


def pick_fix(current: str, fixed: Iterable[str]) -> Optional[str]:
    cands = [f for f in fixed if compare(f, current) > 0]
    if not cands:
        return None
    same = [f for f in cands if _major(f) == _major(current)]
    pool = same or cands
    return sorted(pool, key=_key)[0]


def target_version(current: str, per_advisory_fixed: List[List[str]]) -> Optional[str]:
    picks = []
    for fixed in per_advisory_fixed:
        p = pick_fix(current, fixed)
        if p is None:
            return None
        picks.append(p)
    if not picks:
        return None
    return sorted(picks, key=_key)[-1]
