"""패키지 이름 -> 소스에서 import되는 모듈 이름."""
from __future__ import annotations

import re
from typing import Tuple

# 배포 이름과 import 이름이 다른 PyPI 패키지(자주 나오는 것만 — 목록 밖은 정규화 규칙)
PY_ALIASES = {
    "pyyaml": ("yaml",),
    "pillow": ("PIL",),
    "pyjwt": ("jwt",),
    "python-docx": ("docx",),
    "python-dateutil": ("dateutil",),
    "mysql-python": ("MySQLdb",),
    "mysqlclient": ("MySQLdb",),
    "beautifulsoup4": ("bs4",),
    "scikit-learn": ("sklearn",),
    "opencv-python": ("cv2",),
    "python3-openid": ("openid",),
    "python-openid": ("openid",),
    "django-allauth": ("allauth",),
    "django-crispy-forms": ("crispy_forms",),
    "crispy-bootstrap4": ("crispy_bootstrap4",),
    "dj-database-url": ("dj_database_url",),
    "argon2-cffi": ("argon2",),
    "argon2-cffi-bindings": ("_argon2_cffi_bindings",),
    "requests-oauthlib": ("requests_oauthlib",),
    "grequests": ("grequests",),
    "markupsafe": ("markupsafe",),
    "pre-commit": ("pre_commit",),
    "charset-normalizer": ("charset_normalizer",),
    "backports-abc": ("backports_abc",),
    "typing-extensions": ("typing_extensions",),
}


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _maven_prefixes(coord: str) -> Tuple[str, ...]:
    """groupId:artifactId -> import 접두 후보. 이름 규칙 휴리스틱이라 안 맞으면 미확인이 된다(SPEC 비목표)."""
    g, _, a = coord.partition(":")
    last = g.rsplit(".", 1)[-1].lower()
    toks = a.lower().split("-")
    cands = []
    rest = toks[:]
    if rest and (rest[0] == last or rest[0] in last or last in rest[0]) and len(rest) > 1:
        rest = rest[1:]
    for t in (rest, toks):
        c = f"{g}." + ".".join(t)
        if c not in cands:
            cands.append(c)
    joined = f"{g}." + "".join(toks)
    if joined not in cands:
        cands.append(joined)
    if a.lower() == last or g.endswith("." + a.lower()):
        cands.append(g)
    return tuple(cands)


def modules_for(ecosystem: str, package: str) -> Tuple[str, ...]:
    if ecosystem.lower() == "maven":
        return _maven_prefixes(package)
    if ecosystem.lower() == "npm":
        return (package,)
    n = normalize(package)
    if n in PY_ALIASES:
        return PY_ALIASES[n]
    return (n.replace("-", "_"),)
