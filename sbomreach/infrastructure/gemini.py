from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from typing import Callable, Optional

ENV_FILE = os.environ.get("SBOMREACH_ENV_FILE", os.path.expanduser("~/.config/sbomreach/gemini.env"))
DEFAULT_MODEL = "gemini-3.5-flash-lite"   # 실측(2026-11-02): gemini-2.5-flash 는 무료 한도 429, 3.5-flash-lite 는 연속 호출 통과
RETRYABLE = {429, 500, 502, 503, 504}


class LlmHttpError(Exception):
    """HTTP 실패. status·body(키 가림)를 그대로 들고 있어 trace에 원인을 남긴다."""

    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}")
        self.status, self.body = status, body


def load_key(path: str = ENV_FILE) -> Optional[str]:
    if os.environ.get("GEMINI_API_KEY"):
        return os.environ["GEMINI_API_KEY"]
    try:
        for line in open(path, encoding="utf-8"):
            if line.startswith("GEMINI_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"\'')
    except OSError:
        return None
    return None


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise LlmHttpError(e.code, e.read().decode("utf-8", "replace")[:400]) from None


class GeminiLlm:
    """간격 제한(min_interval)·재시도(429/5xx)·디스크 캐시. 키는 어떤 기록에도 남기지 않는다."""

    def __init__(self, key: str, model: str = DEFAULT_MODEL, post: Callable[[str, dict], dict] = _post,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
                 trace=None, retries: int = 3, min_interval: float = 4.5, cache_path: Optional[str] = None,
                 max_tokens: int = 300):
        self.key, self.model, self.post, self.sleep, self.clock = key, model, post, sleep, clock
        self.trace, self.retries, self.min_interval, self.cache_path, self.max_tokens = trace, retries, min_interval, cache_path, max_tokens
        self._last: Optional[float] = None
        self._cache = {}
        if cache_path and os.path.exists(cache_path):
            try:
                self._cache = json.load(open(cache_path, encoding="utf-8"))
            except (OSError, ValueError):
                self._cache = {}

    def _mask(self, s: str) -> str:
        return s.replace(self.key, "[KEY]") if self.key else s

    def _rec(self, **ev):
        if self.trace is not None:
            self.trace.record({"tool": "llm_call", "model": self.model, **{k: (self._mask(v) if isinstance(v, str) else v) for k, v in ev.items()}})

    def _throttle(self):
        if self._last is not None:
            wait = self.min_interval - (self.clock() - self._last)
            if wait > 0:
                self.sleep(wait)
        self._last = self.clock()

    def complete(self, prompt: str) -> str:
        ck = hashlib.sha1((self.model + "\n" + prompt).encode("utf-8")).hexdigest()
        if ck in self._cache:
            self._rec(status="cache", attempt=0)
            return self._cache[ck]
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.key}"
        body = {"contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0, "maxOutputTokens": self.max_tokens}}
        for attempt in range(1, self.retries + 2):
            self._throttle()
            t0 = time.time()
            try:
                d = self.post(url, body)
                text = d["candidates"][0]["content"]["parts"][0]["text"]
            except LlmHttpError as e:
                e.body = self._mask(e.body)
                self._rec(status=e.status, attempt=attempt, detail=e.body[:160], ms=round((time.time() - t0) * 1000))
                if e.status in RETRYABLE and attempt <= self.retries:
                    self.sleep(min(60.0, 5.0 * (2 ** (attempt - 1))))
                    continue
                raise
            self._rec(status=200, attempt=attempt, ms=round((time.time() - t0) * 1000))
            self._cache[ck] = text
            if self.cache_path:
                json.dump(self._cache, open(self.cache_path, "w", encoding="utf-8"), ensure_ascii=False)
            return text
        raise LlmHttpError(0, "unreachable")
