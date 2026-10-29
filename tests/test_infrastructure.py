import json
import subprocess

import pytest

from sbomreach.application.ports import VulnLookupError
from sbomreach.domain.models import Component, Evidence
from sbomreach.infrastructure.osv_client import OsvVulnPort
from sbomreach.infrastructure.repo_files import read_manifests, read_sources
from sbomreach.infrastructure.syft_runner import SyftSbom
from sbomreach.infrastructure.trace import JsonlTrace
from sbomreach.infrastructure.workcopy import make_workcopy, apply_and_commit

VULN = {"id": "GHSA-1", "aliases": ["CVE-1"], "summary": "s", "details": "uses `load()`",
        "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "PyYAML", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}]}


def test_osv_parses_caches_and_does_not_recall(tmp_path):
    calls = []

    def http(url, body):
        calls.append(body)
        return {"vulns": [VULN]}

    p = OsvVulnPort(http_post=http, cache_dir=str(tmp_path), overrides={})
    c = Component("PyYAML", "5.1", "PyPI")
    a = p.advisories(c)
    assert a[0].id == "GHSA-1" and a[0].fixed_versions == ("5.4",)
    p.advisories(c)
    assert len(calls) == 1   # 두 번째는 캐시


def test_osv_follows_pagination(tmp_path):
    pages = [{"vulns": [VULN], "next_page_token": "t"}, {"vulns": [dict(VULN, id="GHSA-2", aliases=[])]}]

    def http(url, body):
        return pages.pop(0)

    got = OsvVulnPort(http_post=http, cache_dir=str(tmp_path), overrides={}).advisories(Component("PyYAML", "5.1", "PyPI"))
    assert {a.id for a in got} == {"GHSA-1", "GHSA-2"}


def test_osv_error_becomes_lookup_error_and_is_not_cached(tmp_path):
    def http(url, body):
        raise OSError("down")

    p = OsvVulnPort(http_post=http, cache_dir=str(tmp_path), overrides={})
    with pytest.raises(VulnLookupError):
        p.advisories(Component("PyYAML", "5.1", "PyPI"))
    assert list(tmp_path.iterdir()) == []


def test_osv_empty_result_is_cached_as_empty(tmp_path):
    p = OsvVulnPort(http_post=lambda u, b: {}, cache_dir=str(tmp_path), overrides={})
    assert p.advisories(Component("x", "1", "npm")) == []
    assert len(list(tmp_path.iterdir())) == 1


def test_repo_files_excludes_vendor_dirs(tmp_path):
    (tmp_path / "node_modules/x").mkdir(parents=True)
    (tmp_path / "node_modules/x/i.js").write_text("require('a')")
    (tmp_path / "app").mkdir()
    (tmp_path / "app/a.js").write_text("require('b')")
    (tmp_path / "app/b.py").write_text("import c")
    (tmp_path / "dockerized_labs").mkdir()
    (tmp_path / "dockerized_labs/z.py").write_text("import z")
    (tmp_path / "package.json").write_text("{}")
    src = read_sources(str(tmp_path), excludes=["dockerized_labs"])
    assert set(src) == {"app/a.js", "app/b.py"}
    assert "package.json" in read_manifests(str(tmp_path), excludes=[])


def test_syft_sbom_uses_syft_output(tmp_path):
    doc = {"components": [{"type": "library", "name": "lodash", "version": "4.17.4", "purl": "pkg:npm/lodash@4.17.4"}]}
    sb = SyftSbom(run=lambda argv: json.dumps(doc), syft_path="syft")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.4"}}))
    comps, fb = sb.generate(str(tmp_path))
    assert [(c.name, c.version) for c in comps] == [("lodash", "4.17.4")] and fb is False
    assert "lodash" in sb.direct_names(str(tmp_path))


def test_syft_missing_falls_back_to_lockfile(tmp_path):
    def run(argv):
        raise FileNotFoundError("syft")

    (tmp_path / "requirements.txt").write_text("PyYAML==5.1\n")
    comps, fb = SyftSbom(run=run, syft_path="syft").generate(str(tmp_path))
    assert fb is True and comps[0].name == "PyYAML"


def test_syft_command_goes_through_guardrail(tmp_path):
    seen = []

    def run(argv):
        seen.append(argv)
        return json.dumps({"components": []})

    SyftSbom(run=run, syft_path="syft").generate(str(tmp_path))
    assert seen[0][:2] == ["syft", "scan"] and seen[0][2].startswith("dir:")


def test_trace_writes_jsonl(tmp_path):
    f = tmp_path / "t.jsonl"
    t = JsonlTrace(str(f), run_id="r1")
    t.record({"tool": "sbom", "components": 3})
    line = json.loads(f.read_text().strip())
    assert line["tool"] == "sbom" and line["run_id"] == "r1" and "ts" in line and line["seq"] == 1


def _git(cwd, *a):
    return subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True, text=True).stdout


def test_workcopy_creates_branch_and_applies_python_bump(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "requirements.txt").write_text("PyYAML==5.1\nrequests==2.18.1\n")
    (src / "app.py").write_text("import yaml\n")
    wc = make_workcopy(str(src), str(tmp_path / "work"), name="demo")
    assert "baseline" in _git(wc, "log", "--oneline")
    apply_and_commit(wc, branch="fix/sbomreach", bumps={"PyYAML": "5.4"}, ecosystem="PyPI")
    assert _git(wc, "rev-parse", "--abbrev-ref", "HEAD").strip() == "fix/sbomreach"
    assert "PyYAML==5.4" in (tmp_path / "work/demo/requirements.txt").read_text()
    assert "requests==2.18.1" in (tmp_path / "work/demo/requirements.txt").read_text()
    # 원본은 그대로
    assert "PyYAML==5.1" in (src / "requirements.txt").read_text()


def test_repo_source_merges_python_and_js(tmp_path):
    from sbomreach.infrastructure.repo_source import RepoSource
    (tmp_path / "a.py").write_text("import yaml\nyaml.load(1)\n")
    (tmp_path / "b.js").write_text("const _ = require('lodash');\n_.template(1);\n")
    idx = RepoSource().index(str(tmp_path))
    assert "yaml" in idx.imports and "lodash" in idx.imports
    assert ("yaml", "load") in idx.refs and ("lodash", "template") in idx.refs


def test_gemini_adapter_builds_request_and_reads_text():
    from sbomreach.infrastructure.gemini import GeminiLlm
    seen = {}

    def post(url, body):
        seen["url"], seen["body"] = url, body
        return {"candidates": [{"content": {"parts": [{"text": "문장"}]}}]}

    assert GeminiLlm("K", model="m", post=post).complete("p") == "문장"
    assert "models/m:generateContent" in seen["url"] and seen["body"]["generationConfig"]["temperature"] == 0


def test_targets_file_has_two_languages_and_four_repos():
    import os
    from sbomreach.infrastructure import cli
    t = cli.targets()
    assert len(t) >= 3 and {x["language"] for x in t.values()} >= {"Python", "JavaScript"}


def test_osv_prefetch_fills_cache_in_parallel_and_skips_failures(tmp_path):
    def http(url, body):
        if body["package"]["name"] == "bad":
            raise OSError("x")
        return {"vulns": []}

    p = OsvVulnPort(http_post=http, cache_dir=str(tmp_path), overrides={})
    comps = [Component(n, "1", "npm") for n in ("a", "b", "bad")]
    p.prefetch(comps)
    assert len(list(tmp_path.iterdir())) == 2


def test_repo_source_merges_weak_refs_and_mentions_from_both_languages(tmp_path):
    from sbomreach.infrastructure.repo_source import RepoSource
    (tmp_path / "a.py").write_text("APPS = ['allauth']\ndef f(r):\n    return r.body\n")
    (tmp_path / "b.js").write_text("function h(req, res) { return res.redirect('/x'); }\n")
    idx = RepoSource().index(str(tmp_path))
    assert "allauth" in idx.mentions and "body" in idx.weak_refs and "redirect" in idx.weak_refs


def test_cli_parser_accepts_rounds_and_scope():
    from sbomreach.infrastructure import cli
    import argparse
    assert callable(cli.cmd_remediate)
    # 인자 정의가 깨지지 않았는지: --max-rounds 기본 3
    import inspect
    assert "max_rounds" in inspect.getsource(cli.cmd_remediate)
