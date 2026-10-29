from __future__ import annotations

import json
import os
import urllib.request
from typing import Callable, Optional

ENV_FILE = os.path.expanduser("~/.config/sbomreach/gemini.env")


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
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.loads(r.read().decode())


class GeminiLlm:
    def __init__(self, key: str, model: str = "gemini-2.5-flash", post: Callable[[str, dict], dict] = _post):
        self.key, self.model, self.post = key, model, post

    def complete(self, prompt: str) -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.key}"
        d = self.post(url, {"contents": [{"parts": [{"text": prompt}]}],
                            "generationConfig": {"temperature": 0, "maxOutputTokens": 300,
                                                 "thinkingConfig": {"thinkingBudget": 0}}})
        return d["candidates"][0]["content"]["parts"][0]["text"]
