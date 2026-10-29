"""가드레일 — LLM 출력·명령 실행·비밀·불완전 스캔을 코드로 막는다."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Set

from .models import Verdict


@dataclass(frozen=True)
class Check:
    ok: bool
    rule: str = ""
    why: str = ""


_VERSION = re.compile(r"(?<![0-9A-Za-z_.])\d+\.\d+(?:\.\d+)*(?![0-9A-Za-z_])(?!\.\d)")
_SAFE_CLAIMS = ["안전합니다", "안전하다", "취약하지 않", "위험 없", "위험이 없", "문제 없", "문제없", "영향 없", "영향이 없"]
_REACH_CLAIMS = ["도달 가능", "도달가능", "호출됩니다", "호출되고 있"]


def check_llm_text(text: str, allowed_versions: Set[str], verdict: Verdict) -> Check:
    """G2 허용 목록 밖 버전 숫자 금지 · G3 안전 단정·판정 뒤집기 금지."""
    for v in _VERSION.findall(text):
        if v not in allowed_versions:
            return Check(False, "G2", f"허용 목록에 없는 버전 숫자 {v}")
    for c in _SAFE_CLAIMS:
        if c in text:
            return Check(False, "G3", f"안전 단정 표현 「{c}」")
    if verdict is not Verdict.REACHED:
        for c in _REACH_CLAIMS:
            if c in text:
                return Check(False, "G3", f"판정이 {verdict.ko}인데 도달 단정 「{c}」")
    return Check(True)


_ALLOWED = {
    "syft": lambda a: len(a) >= 2 and a[1] == "scan",
    "git": lambda a: len(a) >= 2 and a[1] in {"init", "add", "commit", "checkout", "branch", "diff", "status", "rev-parse", "log"},
    "npm": lambda a: "install" in a and "--package-lock-only" in a and "--ignore-scripts" in a,
}


def check_command(argv: List[str]) -> Check:
    """G4 대상 저장소 코드를 실행·설치하지 않는다. 허용 목록 밖 명령은 차단."""
    if not argv:
        return Check(False, "G4", "빈 명령")
    exe = argv[0].split("/")[-1]
    ok = _ALLOWED.get(exe)
    if ok is None or not ok(argv):
        return Check(False, "G4", f"허용 목록 밖 명령 {exe}")
    return Check(True)


_SECRETS = [
    (re.compile(r"AIza[0-9A-Za-z_\-]{20,}"), "[KEY]"),
    (re.compile(r"gh[pousr]_[0-9A-Za-z]{20,}"), "[TOKEN]"),
    (re.compile(r"sk-[0-9A-Za-z_\-]{20,}"), "[KEY]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[KEY]"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "[EMAIL]"),
]


def mask_secrets(s: str) -> str:
    """G5 LLM으로 나가는 문장에서 비밀·이메일을 가린다."""
    for rx, rep in _SECRETS:
        s = rx.sub(rep, s)
    return s


def safe_to_say_clean(alert_count: int, scan_incomplete: bool) -> bool:
    """G6 조회가 덜 끝났으면 경보 0건을 「깨끗함」이라 말하지 않는다."""
    return alert_count == 0 and not scan_incomplete
