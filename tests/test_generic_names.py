import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from build_generic_names import common_names  # noqa: E402

from sbomreach.application.pipeline import ScanUseCase
from sbomreach.domain.models import Advisory, Component, Evidence
from sbomreach.domain.reach import SourceIndex


def vuln(details):
    return {"id": "X", "summary": "s", "details": details, "affected": []}


def test_common_names_counts_distinct_packages(tmp_path):
    for pkg, d in [("a", "uses `decode()` badly"), ("b", "calls `decode` badly"), ("c", "the `decode` function"), ("d", "`rare_fn` only")]:
        json.dump([vuln(d)], open(tmp_path / f"PyPI__{pkg}__1.0.json", "w"))
    out = common_names(str(tmp_path), min_packages=3)
    assert "decode" in out and "rare_fn" not in out


def test_same_package_many_versions_counts_once(tmp_path):
    for v in ["1.0", "1.1", "1.2"]:
        json.dump([vuln("uses `decode()`")], open(tmp_path / f"PyPI__a__{v}.json", "w"))
    assert "decode" not in common_names(str(tmp_path), min_packages=3)


class _S:
    tool = "f"
    def generate(self, r): return [Component("jwt-x", "1", "PyPI")], False
    def direct_names(self, r): return set()


class _V:
    def advisories(self, c):
        return [Advisory("A", (), "s", "HIGH", ("2",), ("decode", "other_a", "other_b", "other_c"))]


class _Src:
    def index(self, r):
        return SourceIndex(imports={"jwt_x": [Evidence("a.py", 1, "i")]}, refs={("jwt_x", "decode"): [Evidence("a.py", 5, "jwt_x.decode(t)")]})


class _T:
    def record(self, e): pass


def test_pipeline_passes_common_names_to_judge():
    r1 = ScanUseCase(_S(), _V(), _Src(), _T()).run("r")
    assert r1.judgements[0].verdict.value == "REACHED"      # 사전이 없으면 v1.2 동작
    r2 = ScanUseCase(_S(), _V(), _Src(), _T(), common_names=frozenset({"decode"})).run("r")
    assert r2.judgements[0].verdict.value == "USED"
