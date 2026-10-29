from __future__ import annotations

import json
import subprocess
from typing import Callable, Iterable, List, Set, Tuple

from ..adapters.cyclonedx import parse_components
from ..adapters.lockfile import components_from_files, direct_names_from_files
from ..domain import guardrails
from ..domain.models import Component
from .repo_files import read_manifests


def default_run(argv: List[str]) -> str:
    chk = guardrails.check_command(argv)
    if not chk.ok:
        raise PermissionError(f"{chk.rule}: {chk.why}")
    return subprocess.run(argv, capture_output=True, text=True, check=True, timeout=300).stdout


class SyftSbom:
    tool = "syft"

    def __init__(self, run: Callable[[List[str]], str] = default_run, syft_path: str = "syft", excludes: Iterable[str] = ()):
        self.run, self.syft, self.excludes = run, syft_path, list(excludes)

    def generate(self, repo: str) -> Tuple[List[Component], bool]:
        argv = [self.syft, "scan", f"dir:{repo}", "-o", "cyclonedx-json", "-q"]
        for e in self.excludes:
            argv += ["--exclude", f"./{e.strip('/')}/**"]
        try:
            comps = parse_components(json.loads(self.run(argv)))
            if comps:
                return comps, False
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
            pass
        return components_from_files(read_manifests(repo, self.excludes)), True

    def direct_names(self, repo: str) -> Set[str]:
        return direct_names_from_files(read_manifests(repo, self.excludes))
