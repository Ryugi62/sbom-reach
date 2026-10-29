import json
import pathlib

from sbomreach.adapters.osv import apply_overrides, extract_symbols, parse_vuln
from sbomreach.domain.models import Component

FX = pathlib.Path(__file__).parent / "fixtures"


def load(n):
    return json.loads((FX / n).read_text())


def test_extract_symbols_from_backticks():
    d = load("osv_lodash.json")
    syms = extract_symbols(d["summary"], d["details"])
    assert {"toNumber", "trim", "trimEnd"} <= set(syms)


def test_extract_symbols_drops_stopwords_and_files():
    syms = extract_symbols("", "use `package.json`, `true`, `null`, `Content-Type`, `a/b`, `__proto__` and `merge()`")
    assert "merge" in syms
    assert not ({"package.json", "true", "null", "Content-Type", "a/b", "__proto__"} & set(syms))


def test_extract_symbols_dotted_kept():
    assert "_.template" in extract_symbols("code injection via `_.template` imports", "")


def test_extract_symbols_from_named_method_phrase():
    syms = extract_symbols("", "arbitrary code execution when it processes untrusted YAML files through the full_load method or with the FullLoader loader")
    assert "full_load" in syms


def test_parse_vuln_picks_fixed_versions_for_component_only():
    c = Component("lodash", "4.17.4", "npm")
    a = parse_vuln(load("osv_lodash.json"), c)
    assert a.id == "GHSA-29mw-wpgm-hmr9"
    assert a.fixed_versions == ("4.17.21",)   # lodash-es의 9.9.9는 섞이면 안 된다
    assert a.severity == "MODERATE"
    assert a.symbol_source == "auto"


def test_parse_vuln_pypi_name_normalization_and_severity():
    c = Component("pyyaml", "5.1", "PyPI")
    a = parse_vuln(load("osv_pyyaml.json"), c)
    assert a.fixed_versions == ("5.4",) and a.severity == "CRITICAL"


def test_overrides_replace_symbols_by_id_or_alias():
    c = Component("PyYAML", "5.1", "PyPI")
    a = parse_vuln(load("osv_pyyaml.json"), c)
    b = apply_overrides(a, {"CVE-2020-14343": ["yaml.full_load", "yaml.load"]})
    assert b.symbol_source == "curated" and "yaml.load" in b.symbols
    assert apply_overrides(a, {}) == a


def test_severity_fallback_unknown():
    d = load("osv_pyyaml.json")
    d["database_specific"] = {}
    assert parse_vuln(d, Component("PyYAML", "5.1", "PyPI")).severity == "UNKNOWN"


def test_severity_from_cvss_vector_when_no_label():
    d = load("osv_pyyaml.json")
    d["database_specific"] = {}
    d["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    assert parse_vuln(d, Component("PyYAML", "5.1", "PyPI")).severity == "CRITICAL"
    d["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N"}]
    assert parse_vuln(d, Component("PyYAML", "5.1", "PyPI")).severity == "MODERATE"
