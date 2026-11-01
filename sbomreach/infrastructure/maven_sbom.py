from __future__ import annotations

from typing import Dict, List, Set, Tuple

from ..adapters.maven_pom import components_from_poms, direct_names_from_poms
from ..domain.models import Component
from .repo_files import read_manifests


class MavenSbom:
    """pom.xml 해석 SBOM(SbomPort). syft·mvn을 실행하지 않는다 — 대상 코드는 읽기만 한다."""
    tool = "pom.xml 해석기"

    def __init__(self, excludes=()):
        self.excludes = list(excludes)
        self.stat: Dict[str, int] = {}

    def generate(self, repo: str) -> Tuple[List[Component], bool]:
        comps, self.stat = components_from_poms(read_manifests(repo, self.excludes))
        return comps, False

    def direct_names(self, repo: str) -> Set[str]:
        return direct_names_from_poms(read_manifests(repo, self.excludes))
