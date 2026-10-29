from sbomreach.adapters.js_source import analyze_js

SRC = '''const _ = require('lodash');
const marked = require("marked");
const { template } = require('lodash');
const merge = require('lodash/merge');
import express from 'express';
// _.zipObjectDeep(a)
/* _.defaultsDeep(a) */
const s = "_.set(a)";
function f(x) {
  _.template(x);
  marked(x);
  template(x);
  merge({}, x);
  express().use(1);
  require('ms')(x);
}
'''


def test_requires_and_imports_recorded():
    idx = analyze_js({"a.js": SRC})
    for m in ("lodash", "marked", "express", "ms"):
        assert m in idx.imports, m
    assert idx.imports["lodash"][0].line == 1


def test_member_call_via_alias_binding():
    idx = analyze_js({"a.js": SRC})
    assert idx.refs[("lodash", "template")][0].line in (3, 10, 12)
    assert any(e.line == 10 for e in idx.refs[("lodash", "template")])


def test_bare_call_of_module_binding_is_ref_by_module_name():
    idx = analyze_js({"a.js": SRC})
    assert idx.refs[("marked", "marked")][0].line == 11


def test_destructured_name_used_later():
    idx = analyze_js({"a.js": SRC})
    assert any(e.line == 12 for e in idx.refs[("lodash", "template")])


def test_submodule_require_is_ref_by_submodule_name():
    idx = analyze_js({"a.js": SRC})
    assert any(e.line == 13 for e in idx.refs[("lodash", "merge")])


def test_comments_and_strings_ignored():
    idx = analyze_js({"a.js": SRC})
    assert ("lodash", "zipObjectDeep") not in idx.refs
    assert ("lodash", "defaultsDeep") not in idx.refs
    assert ("lodash", "set") not in idx.refs


def test_inline_require_call():
    idx = analyze_js({"a.js": SRC})
    assert idx.refs[("ms", "ms")][0].line == 15


def test_scoped_package_root():
    idx = analyze_js({"b.js": "const x = require('@scope/pkg/sub');\nx.go();\n"})
    assert "@scope/pkg" in idx.imports


def test_url_in_string_is_not_a_comment():
    idx = analyze_js({"c.js": "const u = 'http://x.y/z'; const m = require('marked'); m(u);\n"})
    assert ("marked", "marked") in idx.refs


def test_relative_require_ignored():
    idx = analyze_js({"d.js": "const a = require('./local'); a.x();\n"})
    assert idx.imports == {}


def test_member_chain_on_module_binding():
    idx = analyze_js({"e.js": "const m = require('moment');\nm.utc().format();\n"})
    assert ("moment", "utc") in idx.refs
