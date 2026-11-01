"""정답을 다른 모델(Gemini)에게 독립 재판정시키는 입력·출력 처리. 도구 판정·원래 정답은 보여 주지 않는다."""
from __future__ import annotations

import re
from typing import Dict, List, Sequence, Tuple

DEFS = ("REACHED(도달): 저장소 코드가 어드바이저리가 지목한 취약 함수·속성을 호출·참조한다. "
        "USED(사용): 저장소가 그 패키지를 쓰지만(import 또는 설정 로딩) 지목된 취약 기능은 호출하지 않는다. "
        "UNSEEN(미확인): 저장소 소스에 그 패키지를 쓰는 줄이 없다.")


def context_lines(files: Dict[str, str], modules: Sequence[str], names: Sequence[str], limit: int = 40) -> List[str]:
    """판정 규칙 없이 글자 검색만: 모듈 이름이 든 줄(import 등) 먼저, 그다음 심볼 이름이 든 줄."""
    mod_hits, name_hits = [], []
    for path in sorted(files):
        for n, line in enumerate(files[path].split("\n"), 1):
            t = line.strip()
            if not t:
                continue
            if any(re.search(r"(?<![\w.])" + re.escape(m) + r"(?![\w])", t) for m in modules):
                mod_hits.append(f"{path}:{n}: {t[:160]}")
            elif any(re.search(r"\b" + re.escape(x) + r"\b", t) for x in names if len(x) > 2):
                name_hits.append(f"{path}:{n}: {t[:160]}")
    return (mod_hits[: limit // 2] + name_hits[: limit - min(len(mod_hits), limit // 2)])[:limit]


def build_prompt(package: str, version: str, title: str, symbols: Sequence[str], lines: Sequence[str]) -> str:
    ctx = "\n".join(lines) if lines else "(이 저장소 소스에서 해당 이름을 찾지 못함)"
    return ("당신은 코드 보안 검토자입니다. 아래 경보가 이 저장소에서 어떤 상태인지 세 가지 중 하나로 판정하세요.\n"
            f"{DEFS}\n"
            "답은 첫 단어를 REACHED, USED, UNSEEN 중 하나로 쓰고 이어서 한국어 한 문장으로 이유를 쓰세요.\n"
            f"패키지: {package} {version}\n경보 제목: {title}\n어드바이저리가 말하는 심볼 후보: {', '.join(symbols[:10]) or '(없음)'}\n"
            f"저장소 소스에서 글자 검색으로 찾은 줄(파일:줄: 내용):\n{ctx}")


_LABEL = re.compile(r"\b(REACHED|USED|UNSEEN)\b")


def parse_label(text: str) -> Tuple[str, str]:
    m = _LABEL.search(text)
    if not m:
        return "UNPARSED", text.strip()[:160]
    rest = text[m.end():].lstrip(" *:—-–.)").strip()
    return m.group(1), rest[:200]
