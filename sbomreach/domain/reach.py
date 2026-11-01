"""도달가능성 판정 — 결정적 규칙. LLM·I/O 없음."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import AbstractSet, Callable, Dict, List, Optional, Tuple

from .models import Alert, Evidence, Judgement, Verdict
from .packages import modules_for


@dataclass
class SourceIndex:
    """소스 분석기가 만든 사실표. imports: 모듈 -> import 줄들, refs: (모듈, 이름) -> 참조·호출 줄들."""
    imports: Dict[str, List[Evidence]] = field(default_factory=dict)
    refs: Dict[Tuple[str, str], List[Evidence]] = field(default_factory=dict)
    weak_refs: Dict[str, List[Evidence]] = field(default_factory=dict)   # 메서드·속성 이름 -> 받는 쪽 타입을 모르는 호출 줄
    mentions: Dict[str, List[Evidence]] = field(default_factory=dict)    # 문자열로만 나온 모듈 이름(설정 로딩 등)
    # Java: finder(이름, 모듈 접두들, "class"|"call") -> 근거 줄. 어댑터가 붙인다(도메인은 I/O를 모른다)
    finder: Optional[Callable[[str, Tuple[str, ...], str], List[Evidence]]] = None


def _sym_name(sym: str) -> str:
    s = sym.strip().rstrip("()")
    return s.replace("::", ".").split(".")[-1]


GENERIC = {"get", "set", "filter", "find", "exclude", "parse", "load", "body", "data", "add", "update", "delete", "save",
           "close", "open", "read", "write", "run", "start", "stop", "init", "format", "join", "split", "keys", "values",
           "items", "name", "type", "id", "path", "url", "size", "length", "index", "count", "map", "push", "pop", "then",
           "catch", "call", "apply", "bind", "send", "end", "on", "emit", "use", "render", "request", "response", "args",
           "next", "create", "remove", "query", "value", "key", "text", "content", "file", "files", "form", "headers", "cookies",
           # Java에서 흔한 메서드 이름
           "put", "equals", "hashcode", "tostring", "deserialize", "serialize", "readvalue", "writevalue", "contains", "containskey",
           "size", "isempty", "append", "getclass", "getmessage", "valueof", "of", "builder", "build", "newinstance", "toarray",
           "iterator", "flush", "accept", "apply", "test", "compare", "compareto", "clone"}


# 언어 내장·키워드 — 어드바이저리 본문에 예시로 섞여 나오지만 취약 함수가 아니다(SPEC S10-④)
BUILTIN_HEADS = {"JSON", "Object", "Array", "Math", "Promise", "Date", "String", "Number", "Boolean", "Buffer", "Symbol", "Map", "Set",
                 "RegExp", "Error", "process", "console", "global", "window", "document", "Reflect", "Proxy",
                 "str", "dict", "list", "int", "float", "bytes", "tuple", "os", "sys", "re", "json"}
BUILTIN_NAMES = {"require", "import", "export", "module", "exports", "prototype", "constructor", "this", "self", "super",
                 "dict", "str", "bytes", "list", "int", "float", "tuple", "set", "len", "print", "type", "object", "isinstance"}


def _builtin_symbol(sym: str) -> bool:
    t = sym.strip().rstrip("()").replace("::", ".")
    head = t.split(".")[0]
    return (len(t.split(".")) > 1 and head in BUILTIN_HEADS) or t in BUILTIN_NAMES or t.split(".")[-1] in BUILTIN_NAMES


def _qualified(sym: str, mods) -> bool:
    s = sym.strip().rstrip("()").replace("::", ".")
    if "." not in s:
        return False
    head = s.split(".")[0]
    if head in BUILTIN_HEADS:
        return False
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
        if not n or _builtin_symbol(s):
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


def _judge_java(alert: Alert, index: SourceIndex, mods, import_ev, common) -> Judgement:
    """Java: 가져온(import) 클래스를 쓰면 강한 근거, 패키지를 import한 파일에서 같은 이름의 메서드 호출은 약한 근거(타입 추론 없음)."""
    specific, generic = _split_names(alert.advisory.symbols, mods, common)
    strong: List[Evidence] = []
    weak: List[Evidence] = []
    matched = set()
    for n in sorted(specific):
        if n[:1].isupper():
            hits = index.finder(n, tuple(mods), "class")
            if hits:
                strong += hits
                matched.add(n)
        else:
            hits = index.finder(n, tuple(mods), "call")
            if hits:
                weak += hits
                matched.add(n)
    nonprod = False
    sp, wp = _product_only(strong), _product_only(weak)
    if strong and not sp or weak and not wp:
        nonprod = True
    if sp:
        return Judgement(alert, Verdict.REACHED, _dedupe(sp),
                         "가져온 클래스 " + ", ".join(sorted(matched)) + " 를 쓰는 근거 줄이 있음", matched=tuple(sorted(matched)))
    if wp:
        return Judgement(alert, Verdict.REACHED, _dedupe(wp),
                         "(약한 근거) 패키지를 import한 파일에 취약 메서드 이름과 같은 호출이 있음 — 타입 추론 없음", weak=True,
                         matched=tuple(sorted(matched)))
    if nonprod:
        return Judgement(alert, Verdict.USED, _dedupe(import_ev), "취약 심볼 사용 줄이 시험 코드에만 있어 도달이라 하지 않음")
    return Judgement(alert, Verdict.USED, _dedupe(import_ev),
                     "패키지는 import되나 취약 심볼 " + ", ".join(sorted(specific | generic)) + " 의 사용 근거 줄은 없음")


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
    if alert.component.ecosystem == "Maven" and index.finder is not None:
        return _judge_java(alert, index, mods, import_ev, common_names)
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
            got = tuple(sorted(n for n in specific if any(index.refs.get((m, n)) for m in mods)))
            return Judgement(alert, Verdict.REACHED, _dedupe(prod),
                             "취약 심볼 " + ", ".join(sorted(specific)) + " 의 참조·호출 근거 줄이 있음", matched=got)
        nonprod_seen = True
    weak = _weak_hits(names_q, mods, index)
    if weak:
        prod = _product_only(weak)
        if prod:
            return Judgement(alert, Verdict.REACHED, _dedupe(prod),
                             "(약한 근거) 패키지 import가 있고 취약 메서드 이름과 같은 호출이 있음 — 타입 추론 없음, 같은 이름의 다른 객체일 수 있음", weak=True,
                             matched=tuple(sorted({_sym_name(x) for x in names_q if index.weak_refs.get(_sym_name(x))})))
        nonprod_seen = True
    if nonprod_seen:
        return Judgement(alert, Verdict.USED, _dedupe(import_ev),
                         "취약 심볼 호출 근거 줄이 시험·마이그레이션 코드에만 있어 도달이라 하지 않음")
    if hits_g:
        return Judgement(alert, Verdict.USED, _dedupe(import_ev),
                         "취약 심볼 " + ", ".join(sorted(generic)) + " 은(는) 여러 패키지에 흔한 일반 이름이고 `모듈.이름`으로 특정되지 않아 호출 줄만으로 도달이라 하지 않음")
    return Judgement(alert, Verdict.USED, _dedupe(import_ev),
                     "패키지는 import되나 취약 심볼 " + ", ".join(sorted(names)) + " 의 참조·호출 근거 줄은 없음")
