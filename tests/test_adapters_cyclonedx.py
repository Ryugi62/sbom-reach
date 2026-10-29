import json
import pathlib

from sbomreach.adapters.cyclonedx import parse_components

FX = pathlib.Path(__file__).parent / "fixtures"


def test_parse_components_filters_and_dedupes():
    comps = parse_components(json.loads((FX / "cdx_min.json").read_text()))
    names = [(c.name, c.version, c.ecosystem) for c in comps]
    assert names == [("PyYAML", "5.1", "PyPI"), ("lodash", "4.17.4", "npm")]


def test_manifest_path_from_syft_property():
    comps = parse_components(json.loads((FX / "cdx_min.json").read_text()))
    assert comps[0].manifest == "/requirements.txt"
