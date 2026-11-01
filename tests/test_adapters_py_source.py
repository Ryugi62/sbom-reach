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


def test_relative_import_ignored():
    idx = analyze_python({"r.py": "from . import x\nfrom .y import z\nz()\n"})
    assert idx.imports == {} and idx.refs == {}


def test_nested_attribute_chain_records_last_attr_only():
    # v1.3(SPEC S10-①): 사슬 중간 이름(utils)은 근거가 아니다 — 마지막 이름만
    idx = analyze_python({"n.py": "import django\ndjango.utils.html.mark_safe('x')\n"})
    assert ("django", "mark_safe") in idx.refs and ("django", "utils") not in idx.refs


def test_instance_attribute_is_ref_of_module():
    idx = analyze_python({"d.py": "from docx import Document\ndoc = Document('a')\nfor p in doc.paragraphs:\n    pass\n"})
    assert ("docx", "paragraphs") in idx.refs


def test_string_mentions_of_dotted_names():
    idx = analyze_python({"s.py": 'INSTALLED_APPS = ["allauth", "allauth.account"]\nURL = "https://x.y/z"\n'})
    assert idx.mentions["allauth"][0].line == 1
    assert "https" not in idx.mentions


def test_weak_refs_python_attribute_on_unresolved_receiver():
    idx = analyze_python({"w.py": "def f(request):\n    return request.body\n"})
    assert idx.weak_refs["body"][0].line == 2


def test_only_last_name_of_attribute_chain_is_a_reference():
    # SPEC S10-①: django.db.models.deletion.CASCADE 의 db·models·deletion 은 이름 풀이 경로일 뿐 근거가 아니다
    idx = analyze_python({"a.py": "import django\nx = django.db.models.deletion.CASCADE\nimport os\nos.path.join('a')\n"})
    assert ("django", "CASCADE") in idx.refs
    assert ("django", "db") not in idx.refs and ("django", "models") not in idx.refs and ("django", "deletion") not in idx.refs
    assert ("os", "join") in idx.refs and ("os", "path") not in idx.refs
