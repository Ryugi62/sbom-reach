"""도달가능성 판정 — 결정적 규칙. LLM·I/O 없음."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

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


def judge(alert: Alert, index: SourceIndex) -> Judgement:
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
    hits: List[Evidence] = []
    for m in mods:
        for n in names:
            hits += index.refs.get((m, n), [])
    if hits:
        return Judgement(alert, Verdict.REACHED, _dedupe(hits),
                         "취약 심볼 " + ", ".join(sorted(names)) + " 의 참조·호출 근거 줄이 있음")
    weak = _weak_hits(names_q, mods, index)
    if weak:
        return Judgement(alert, Verdict.REACHED, _dedupe(weak),
                         "(약한 근거) 패키지 import가 있고 취약 메서드 이름과 같은 호출이 있음 — 타입 추론 없음, 같은 이름의 다른 객체일 수 있음", weak=True)
    return Judgement(alert, Verdict.USED, _dedupe(import_ev),
                     "패키지는 import되나 취약 심볼 " + ", ".join(sorted(names)) + " 의 참조·호출 근거 줄은 없음")
