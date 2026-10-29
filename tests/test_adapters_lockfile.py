import json

from sbomreach.adapters.lockfile import components_from_files, direct_names_from_files

REQ = "# c\nPyYAML==5.1\nrequests==2.18.1  # pin\n-r other.txt\nflask>=1.0\n"
LOCK3 = json.dumps({"lockfileVersion": 3, "packages": {
    "": {"dependencies": {"lodash": "4.17.4"}},
    "node_modules/lodash": {"version": "4.17.4"},
    "node_modules/a/node_modules/ms": {"version": "0.7.1"}}})
LOCK1 = json.dumps({"lockfileVersion": 1, "dependencies": {"lodash": {"version": "4.17.4", "dependencies": {"ms": {"version": "0.7.1"}}}}})


def test_requirements_pinned_only():
    cs = components_from_files({"requirements.txt": REQ})
    assert [(c.name, c.version) for c in cs] == [("PyYAML", "5.1"), ("requests", "2.18.1")]
    assert all(c.ecosystem == "PyPI" for c in cs)


def test_package_lock_v3_and_v1():
    for lock in (LOCK3, LOCK1):
        cs = components_from_files({"package-lock.json": lock})
        assert {(c.name, c.version) for c in cs} == {("lodash", "4.17.4"), ("ms", "0.7.1")}


def test_direct_names():
    files = {"package.json": json.dumps({"dependencies": {"lodash": "4"}, "devDependencies": {"tap": "1"}}),
             "requirements.txt": REQ}
    d = direct_names_from_files(files)
    assert {"lodash", "tap", "pyyaml", "requests"} <= d
