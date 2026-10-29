from sbomreach.adapters.py_source import analyze_python

SRC = '''import yaml
import os.path
from django.utils.html import mark_safe as ms
from jwt import decode
import requests as rq
from flask import Flask

def f(x):
    a = yaml.load(x)
    b = yaml.safe_load(x)
    ms(a)
    decode(b, "k")
    rq.get("u")
    return os.path.join("a")
'''


def test_imports_recorded_with_lines():
    idx = analyze_python({"a.py": SRC})
    assert idx.imports["yaml"][0].line == 1
    assert "django" in idx.imports and "jwt" in idx.imports and "requests" in idx.imports


def test_attribute_calls_resolved():
    idx = analyze_python({"a.py": SRC})
    assert idx.refs[("yaml", "load")][0].line == 9
    assert idx.refs[("yaml", "safe_load")][0].line == 10


def test_from_import_alias_call_resolved():
    idx = analyze_python({"a.py": SRC})
    assert idx.refs[("django", "mark_safe")][0].line == 11
    assert idx.refs[("jwt", "decode")][0].line == 12


def test_module_alias_resolved():
    idx = analyze_python({"a.py": SRC})
    assert idx.refs[("requests", "get")][0].line == 13


def test_comment_and_string_are_not_calls():
    idx = analyze_python({"b.py": "import yaml\n# yaml.load(x)\ns = 'yaml.load(x)'\n"})
    assert ("yaml", "load") not in idx.refs


def test_syntax_error_file_skipped_not_crash():
    idx = analyze_python({"bad.py": "def (:\n", "ok.py": "import yaml\n"})
    assert "yaml" in idx.imports


def test_evidence_text_is_source_line():
    idx = analyze_python({"a.py": SRC})
    assert idx.refs[("yaml", "load")][0].text == "a = yaml.load(x)"
    assert idx.refs[("yaml", "load")][0].path == "a.py"
