#!/usr/bin/env python3
"""OSV 캐시에서 「여러 패키지의 어드바이저리에 흔히 나오는 심볼 이름」 사전을 만든다(SPEC S10-③).
사람이 단어를 골라 넣지 않는다 — 서로 다른 패키지 ≥N개에서 후보 심볼로 나온 이름이 일반 이름이다.
사용: python3 scripts/build_generic_names.py [--min-packages 3]  -> data/generic_names.json"""
import glob
import json
import os
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sbomreach.adapters.osv import extract_symbols  # noqa: E402


def common_names(cache_dir, min_packages=3):
    df = defaultdict(set)
    for p in glob.glob(os.path.join(cache_dir, "*.json")):
        eco, name, _ver = os.path.basename(p)[:-5].split("__", 2)
        try:
            vulns = json.load(open(p, encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for v in vulns:
            for s in extract_symbols(v.get("summary") or "", v.get("details") or "", package=name):
                last = s.strip().rstrip("()").replace("::", ".").split(".")[-1].lower()
                if last:
                    df[last].add((eco, name.lower()))
    return sorted(n for n, pk in df.items() if len(pk) >= min_packages)


def main(argv):
    n = int(argv[argv.index("--min-packages") + 1]) if "--min-packages" in argv else 3
    names = common_names(os.path.join(ROOT, "data", "osv-cache"), n)
    out = os.path.join(ROOT, "data", "generic_names.json")
    json.dump({"min_packages": n, "names": names}, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=0)
    print(len(names), "names ->", out)


if __name__ == "__main__":
    main(sys.argv[1:])
