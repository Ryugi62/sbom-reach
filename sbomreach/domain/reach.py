"""도달가능성 판정 — 결정적 규칙. LLM·I/O 없음."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import AbstractSet, Dict, List, Tuple

from .models import Alert, Evidence, Judgement, Verdict
from .packages import modules_for


@dataclass
class SourceIndex:
    """소스 분석기가 만든 사실표. imports: 모듈 -> import 줄들, refs: (모듈, 이름) -> 참조·호출 줄들."""
    imports: Dict[str, List[Evidence]] = field(default_factory=dict)
    refs: Dict[Tuple[str, str], List[Evidence]] = field(default_factory=dict)
    weak_refs: Dict[str, List[Evidence]] = field(default_factory=dict)   # 메서드·속성 이름 -> 받는 쪽 타입을 모르는 호출 줄
    mentions: Dict[str, List[Evidence]] = field(default_factory=dict)    # 문자열로만 나온 모듈 이름(설정 로딩 등)


def _sym_name(sym: str) -> str:
    s = sym.strip().rstrip("()")
    return s.replace("::", ".").split(".")[-1]


GENERIC = {"get", "set", "filter", "find", "exclude", "parse", "load", "body", "data", "add", "update", "delete", "save",
           "close", "open", "read", "write", "run", "start", "stop", "init", "format", "join", "split", "keys", "values",
           "items", "name", "type", "id", "path", "url", "size", "length", "index", "count", "map", "push", "pop", "then",
           "catch", "call", "apply", "bind", "send", "end", "on", "emit", "use", "render", "request", "response", "args",
           "next", "create", "remove", "query", "value", "key", "text", "content", "file", "files", "form", "headers", "cookies"}


def _qualified(sym: str, mods) -> bool:
    s = sym.strip().rstrip("()").replace("::", ".")
    if "." not in s:
        return False
    head = s.split(".")[0]
    return head not in ("_", "$") and head.lower() not in {m.lower() for m in mods}


def _weak_hits(qualified, mods, index) -> List[Evidence]:
    hits: List[Evidence] = []
    for s in qualified:
        n = _sym_name(s)
        if n and n.lower() not in GENERIC:
            hits += index.weak_refs.get(n, [])
    return hits


def _dedupe(evs: List[Evidence], limit: int = 5) -> Tuple[Evidence, ...]:
    seen, out = set(), []
    for e in evs:
        k = (e.path, e.line)
        if k not in seen:
            seen.add(k)
            out.append(e)
    return tuple(out[:limit])


_NONPROD_DIRS = {"test", "tests", "__tests__", "spec", "specs", "e2e", "migrations", "fixtures", "testdata", "cypress"}
_NONPROD_FILE = re.compile(r"(^test_.*\.py$|_test\.py$|^tests\.py$|^conftest\.py$|\.(test|spec)\.[A-Za-z]+$)")


def is_product_path(path: str) -> bool:
    """시험·마이그레이션 경로가 아니면 제품 코드로 본다(SPEC S10-②)."""
    parts = path.replace("\\", "/").split("/")
    if any(p in _NONPROD_DIRS for p in parts[:-1]):
        return False
    return not _NONPROD_FILE.search(parts[-1])


def _split_names(alert_symbols, mods, common: AbstractSet[str]):
    """취약 심볼 이름을 (특정 이름, 일반 이름)으로 가른다. 일반 이름이라도 `모듈.이름` 으로 특정됐거나 모듈 이름과 같으면(단일 진입점) 특정으로 본다."""
    modset = {m.lower() for m in mods}
    qualified_specific = set()
    for s in alert_symbols:
        t = s.strip().rstrip("()").replace("::", ".")
        parts = t.split(".")
        if len(parts) == 2 and parts[0].lower() in modset:
            qualified_specific.add(parts[1])
    specific, generic = set(), set()
    for s in alert_symbols:
        n = _sym_name(s)
        if not n:
            continue
        low = n.lower()
        is_common = low in GENERIC or low in common
        if low in modset or n in qualified_specific or not is_common:
            specific.add(n)
        else:
            generic.add(n)
    return specific, generic


def _product_only(evs: List[Evidence]) -> List[Evidence]:
    return [e for e in evs if is_product_path(e.path)]


def judge(alert: Alert, index: SourceIndex, common_names: AbstractSet[str] = frozenset()) -> Judgement:
    mods = modules_for(alert.component.ecosystem, alert.component.name)
    import_ev: List[Evidence] = []
    for m in mods:
        import_ev += index.imports.get(m, [])
    if not import_ev:
        men: List[Evidence] = []
        for m in mods:
            men += index.mentions.get(m, [])
        if men:
            return Judgement(alert, Verdict.USED, _dedupe(men),
                             "import 문은 없으나 설정 등에 모듈 이름이 문자열로 나옴 — 설정으로 로딩될 수 있음")
        return Judgement(alert, Verdict.UNSEEN, (),
                         "소스에 이 패키지의 import 근거 줄이 없음 — 전이 의존이거나 동적 로딩일 수 있어 안전하다는 뜻이 아님")
    names = {_sym_name(s) for s in alert.advisory.symbols if _sym_name(s)}
    names_q = [s for s in alert.advisory.symbols if _qualified(s, mods)]
    if not names:
        return Judgement(alert, Verdict.USED, _dedupe(import_ev),
                         "import 근거는 있으나 어드바이저리에서 취약 심볼을 특정하지 못해 호출 여부를 판정할 수 없음")
    specific, generic = _split_names(alert.advisory.symbols, mods, common_names)

    def refs_for(ns) -> List[Evidence]:
        out: List[Evidence] = []
        for m in mods:
            for n in sorted(ns):
                out += index.refs.get((m, n), [])
        return out

    hits_s, hits_g = refs_for(specific), refs_for(generic)
    nonprod_seen = False
    if hits_s:
        prod = _product_only(hits_s)
        if prod:
            return Judgement(alert, Verdict.REACHED, _dedupe(prod),
                             "취약 심볼 " + ", ".join(sorted(specific)) + " 의 참조·호출 근거 줄이 있음")
        nonprod_seen = True
    weak = _weak_hits(names_q, mods, index)
    if weak:
        prod = _product_only(weak)
        if prod:
            return Judgement(alert, Verdict.REACHED, _dedupe(prod),
                             "(약한 근거) 패키지 import가 있고 취약 메서드 이름과 같은 호출이 있음 — 타입 추론 없음, 같은 이름의 다른 객체일 수 있음", weak=True)
        nonprod_seen = True
    if nonprod_seen:
        return Judgement(alert, Verdict.USED, _dedupe(import_ev),
                         "취약 심볼 호출 근거 줄이 시험·마이그레이션 코드에만 있어 도달이라 하지 않음")
    if hits_g:
        return Judgement(alert, Verdict.USED, _dedupe(import_ev),
                         "취약 심볼 " + ", ".join(sorted(generic)) + " 은(는) 여러 패키지에 흔한 일반 이름이고 `모듈.이름`으로 특정되지 않아 호출 줄만으로 도달이라 하지 않음")
    return Judgement(alert, Verdict.USED, _dedupe(import_ev),
                     "패키지는 import되나 취약 심볼 " + ", ".join(sorted(names)) + " 의 참조·호출 근거 줄은 없음")
