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


def modules_for(ecosystem: str, package: str) -> Tuple[str, ...]:
    if ecosystem.lower() == "npm":
        return (package,)
    n = normalize(package)
    if n in PY_ALIASES:
        return PY_ALIASES[n]
    return (n.replace("-", "_"),)
