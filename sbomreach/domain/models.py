"""도메인 모델 — 프레임워크·I/O를 모른다."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Tuple


class Verdict(str, Enum):
    REACHED = "REACHED"   # 도달: 취약 심볼 호출 근거 줄 >= 1
    USED = "USED"         # 사용: 패키지 import 근거만
    UNSEEN = "UNSEEN"     # 미확인: 소스에 import 근거 없음(전이 의존·동적 로딩 배제 못 함)

    @property
    def ko(self) -> str:
        return {"REACHED": "도달", "USED": "사용", "UNSEEN": "미확인"}[self.value]


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    ecosystem: str          # "PyPI" | "npm"
    direct: bool = True     # 매니페스트에 직접 선언됐는가 (모르면 True 아님 -> 아래 어댑터가 채움)
    manifest: str = ""


@dataclass(frozen=True)
class Advisory:
    id: str
    aliases: Tuple[str, ...]
    summary: str
    severity: str                       # CRITICAL | HIGH | MODERATE | LOW | UNKNOWN
    fixed_versions: Tuple[str, ...]
    symbols: Tuple[str, ...] = ()
    symbol_source: str = "none"         # none | auto | curated


@dataclass(frozen=True)
class Alert:
    component: Component
    advisory: Advisory

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.component.name.lower(), self.component.version, self.advisory.id)


@dataclass(frozen=True)
class Evidence:
    path: str
    line: int
    text: str


@dataclass(frozen=True)
class Judgement:
    alert: Alert
    verdict: Verdict
    evidence: Tuple[Evidence, ...]
    reason: str
    weak: bool = False   # 메서드 이름만 일치한 약한 근거(타입 추론 없음)

    def __post_init__(self):
        if self.verdict is Verdict.REACHED and not self.evidence:
            raise ValueError("REACHED 판정은 근거 줄(Evidence) 없이 만들 수 없다")


@dataclass(frozen=True)
class Ranked:
    rank: int
    score: float
    judgement: Judgement


@dataclass(frozen=True)
class Remediation:
    package: str
    ecosystem: str
    current: str
    target: str            # "" 이면 고쳐진 버전 없음 -> 우회/제거 검토
    advisory_ids: Tuple[str, ...]
    best_verdict: Verdict
    direct: bool = True
    text: str = ""
    text_source: str = "template"   # template | llm
