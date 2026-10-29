"""OSV(osv.dev) 응답 -> Advisory. 취약 심볼 후보 추출."""
from __future__ import annotations

import math
import re
from dataclasses import replace
from typing import Dict, Iterable, List, Optional, Tuple

from ..domain.models import Advisory, Component
from ..domain.packages import normalize

_BACKTICK = re.compile(r"`([^`\n]{1,60})`")
_IDENT = re.compile(r"^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$")
_STOP = {"true", "false", "null", "none", "undefined", "this", "self", "object", "string", "array", "number",
         "boolean", "function", "constructor", "prototype", "proto", "__proto__", "node", "npm", "pip", "python",
         "javascript", "json", "html", "http", "https", "url", "get", "set", "options", "default", "name", "value",
         "data", "window", "document", "global", "root", "src", "div", "script"}
_EXT = (".js", ".py", ".json", ".md", ".html", ".txt", ".xml", ".yml", ".yaml", ".ts", ".css", ".cfg", ".ini", ".lock")
_EXT_WORDS = {"js", "py", "json", "com", "org", "io", "net", "md", "html"}
_NAMED = re.compile(r"\b([A-Za-z]+_[A-Za-z_]+|[a-z]+[A-Z][A-Za-z]+)\s+(?:method|function|API)\b|"
                    r"\b(?:method|function)\s+([A-Za-z]+_[A-Za-z_]+|[a-z]+[A-Z][A-Za-z]+)\b")


_ENUM = re.compile(r"\b(?:via|in|using|through|by|of)\s+(?:the\s+)?((?:[A-Za-z_]\w*\s*,\s*)*(?:and\s+)?[A-Za-z_]\w*(?:\s*,?\s+and\s+[A-Za-z_]\w*)?)\s+(?:functions?|methods?)\b")
_ENUM_STOP = {"the", "a", "an", "certain", "some", "specific", "these", "those", "following", "various", "other", "affected",
              "vulnerable", "same", "this", "that", "all", "and", "or", "any", "each", "every", "such", "its", "their", "which", "particular",
              "public", "private", "internal", "helper", "utility", "standard", "built", "in", "of", "with", "user", "another", "one", "two"}


def extract_symbols(summary: str, details: str, package: str = "") -> Tuple[str, ...]:
    text = f"{summary}\n{details}"
    out: List[str] = []
    for tok in _BACKTICK.findall(text):
        t = tok.strip()
        if t.endswith("()"):
            t = t[:-2]
        if not _IDENT.match(t) or t.lower().endswith(_EXT) or t.lower() in _STOP:
            continue
        if t.isupper() and len(t) > 1 and "." not in t:
            continue
        if t.lower().split(".")[-1] in _STOP and "." not in t:
            continue
        if t not in out:
            out.append(t)
    for m in _ENUM.finditer(text):
        for w in re.split(r"\s*,\s*|\s+and\s+|\s*,?\s+", m.group(1)):
            w = w.strip()
            if w and w.lower() not in _ENUM_STOP and w.lower() not in _STOP and len(w) > 2 and w not in out:
                out.append(w)
    if package:
        pk = re.escape(package)
        for m in re.finditer(r"\b(" + pk + r")\.([A-Za-z_]\w*)\b", text):
            t = f"{m.group(1)}.{m.group(2)}"
            if m.group(2).lower() not in _EXT_WORDS and t not in out:
                out.append(t)
    for m in _NAMED.finditer(text):
        t = m.group(1) or m.group(2)
        if t and t.lower() not in _STOP and t not in out:
            out.append(t)
    return tuple(out)


_CVSS_W = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
           "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0.0},
           "I": {"H": 0.56, "L": 0.22, "N": 0.0}, "A": {"H": 0.56, "L": 0.22, "N": 0.0}}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> Optional[float]:
    try:
        parts = dict(p.split(":") for p in vector.split("/")[1:])
        scope_changed = parts["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[parts["PR"]]
        iss = 1 - (1 - _CVSS_W["C"][parts["C"]]) * (1 - _CVSS_W["I"][parts["I"]]) * (1 - _CVSS_W["A"][parts["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * _CVSS_W["AV"][parts["AV"]] * _CVSS_W["AC"][parts["AC"]] * pr * _CVSS_W["UI"][parts["UI"]]
        if impact <= 0:
            return 0.0
        base = min(1.08 * (impact + expl), 10) if scope_changed else min(impact + expl, 10)
        return _roundup(base)
    except (KeyError, ValueError):
        return None


def _severity(raw: dict) -> str:
    label = ((raw.get("database_specific") or {}).get("severity") or "").upper()
    if label in {"CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"}:
        return "MODERATE" if label == "MEDIUM" else label
    for s in raw.get("severity") or []:
        if str(s.get("score", "")).startswith("CVSS:3"):
            sc = cvss3_score(s["score"])
            if sc is not None:
                return "CRITICAL" if sc >= 9 else "HIGH" if sc >= 7 else "MODERATE" if sc >= 4 else "LOW"
    return "UNKNOWN"


def _fixed_for(raw: dict, c: Component) -> Tuple[str, ...]:
    want = normalize(c.name) if c.ecosystem == "PyPI" else c.name
    fixed: List[str] = []
    for aff in raw.get("affected") or []:
        pkg = aff.get("package") or {}
        have = normalize(pkg.get("name", "")) if c.ecosystem == "PyPI" else pkg.get("name", "")
        if have != want:
            continue
        for rg in aff.get("ranges") or []:
            for ev in rg.get("events") or []:
                if "fixed" in ev and ev["fixed"] not in fixed:
                    fixed.append(ev["fixed"])
    return tuple(fixed)


def parse_vuln(raw: dict, c: Component) -> Advisory:
    summary = raw.get("summary") or ""
    syms = extract_symbols(summary, raw.get("details") or "", package=c.name)
    return Advisory(id=raw.get("id", ""), aliases=tuple(raw.get("aliases") or ()), summary=summary,
                    severity=_severity(raw), fixed_versions=_fixed_for(raw, c), symbols=syms,
                    symbol_source="auto" if syms else "none")


def apply_overrides(a: Advisory, overrides: Dict[str, List[str]]) -> Advisory:
    for key in (a.id, *a.aliases):
        if key in overrides:
            return replace(a, symbols=tuple(overrides[key]), symbol_source="curated")
    return a
