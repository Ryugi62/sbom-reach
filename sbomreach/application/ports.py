"""응용 계층이 바깥에 요구하는 구멍(포트)."""
from __future__ import annotations

from typing import Dict, List, Protocol, Set, Tuple

from ..domain.models import Advisory, Component
from ..domain.reach import SourceIndex


class VulnLookupError(Exception):
    pass


class SbomPort(Protocol):
    tool: str

    def generate(self, repo: str) -> Tuple[List[Component], bool]:
        """(부품 목록, 대체 경로 사용 여부)"""

    def direct_names(self, repo: str) -> Set[str]: ...


class VulnPort(Protocol):
    def advisories(self, c: Component) -> List[Advisory]: ...


class SourcePort(Protocol):
    def index(self, repo: str) -> SourceIndex: ...


class LlmPort(Protocol):
    def complete(self, prompt: str) -> str: ...


class TracePort(Protocol):
    def record(self, event: Dict) -> None: ...
