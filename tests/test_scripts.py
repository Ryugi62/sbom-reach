import importlib.util
import os

HERE = os.path.dirname(__file__)


def load():
    spec = importlib.util.spec_from_file_location("clone_targets", os.path.join(HERE, "..", "scripts", "clone_targets.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_clone_plan_pins_commit_and_stays_under_untrusted():
    m = load()
    plan = m.plan([{"name": "x", "url": "https://github.com/a/B", "commit": "abc1234", "path": "untrusted/B"}], "/r")
    assert plan == [(["git", "clone", "--no-checkout", "https://github.com/a/B", "/r/untrusted/B"], None),
                    (["git", "checkout", "--detach", "abc1234"], "/r/untrusted/B")]


def test_clone_plan_refuses_path_escape():
    m = load()
    try:
        m.plan([{"name": "x", "url": "u", "commit": "c", "path": "../evil"}], "/r")
    except ValueError:
        return
    raise AssertionError("path escape not refused")
