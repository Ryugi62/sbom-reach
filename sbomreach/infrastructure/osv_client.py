"""OSV(osv.dev) 조회 + 디스크 캐시. 실패는 캐시하지 않는다."""
from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Callable, Dict, List, Optional

from ..adapters.osv import apply_overrides, parse_vuln
from ..application.ports import VulnLookupError
from ..domain.models import Advisory, Component

URL = "https://api.osv.dev/v1/query"


def default_post(url: str, body: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


class OsvVulnPort:
    def __init__(self, http_post: Callable[[str, dict], dict] = default_post, cache_dir: Optional[str] = None,
                 overrides: Optional[Dict[str, List[str]]] = None):
        self.http, self.cache_dir, self.overrides = http_post, cache_dir, overrides or {}
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)

    def _path(self, c: Component) -> Optional[str]:
        if not self.cache_dir:
            return None
        safe = re.sub(r"[^A-Za-z0-9_.@-]", "_", f"{c.ecosystem}__{c.name}__{c.version}")
        return os.path.join(self.cache_dir, safe + ".json")

    def _fetch(self, c: Component) -> List[dict]:
        body = {"package": {"name": c.name, "ecosystem": c.ecosystem}, "version": c.version}
        vulns: List[dict] = []
        try:
            while True:
                d = self.http(URL, body)
                vulns += d.get("vulns") or []
                tok = d.get("next_page_token")
                if not tok:
                    return vulns
                body = dict(body, page_token=tok)
        except (OSError, ValueError) as e:  # URLError·타임아웃·JSON 오류
            raise VulnLookupError(f"{c.name}@{c.version}: {type(e).__name__}") from e

    def advisories(self, c: Component) -> List[Advisory]:
        p = self._path(c)
        if p and os.path.exists(p):
            raw = json.load(open(p, encoding="utf-8"))
        else:
            raw = self._fetch(c)
            if p:
                json.dump(raw, open(p, "w", encoding="utf-8"), ensure_ascii=False)
        return [apply_overrides(parse_vuln(v, c), self.overrides) for v in raw]
