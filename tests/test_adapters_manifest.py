import json

from sbomreach.adapters.manifest import bump_package_json, bump_requirements


def test_bump_requirements_preserves_comments_and_others():
    txt = "# top\nPyYAML==5.1  # yaml\nrequests==2.18.1\nFlask==0.12.2\n"
    out = bump_requirements(txt, {"pyyaml": "5.4", "requests": "2.31.0"})
    assert out == "# top\nPyYAML==5.4  # yaml\nrequests==2.31.0\nFlask==0.12.2\n"


def test_bump_requirements_ignores_unlisted():
    assert bump_requirements("a==1.0\n", {"zzz": "9"}) == "a==1.0\n"


def test_bump_package_json_direct_and_override():
    pj = json.dumps({"dependencies": {"lodash": "4.17.4", "ms": "^0.7.1"}, "devDependencies": {"tap": "^11.1.3"}})
    out = json.loads(bump_package_json(pj, {"lodash": "4.17.21", "tap": "12.0.0", "minimist": "1.2.8"}))
    assert out["dependencies"]["lodash"] == "4.17.21"
    assert out["dependencies"]["ms"] == "^0.7.1"
    assert out["devDependencies"]["tap"] == "12.0.0"
    assert out["overrides"]["minimist"] == "1.2.8"   # 전이 의존은 overrides
    assert "lodash" not in out["overrides"]
