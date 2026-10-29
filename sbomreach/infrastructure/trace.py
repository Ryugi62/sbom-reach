from __future__ import annotations

import json
import time


class JsonlTrace:
    """도구 호출 1건 = 1줄. 평가(Evals)가 이 기록을 다시 읽는다."""

    def __init__(self, path: str, run_id: str):
        self.path, self.run_id, self.seq = path, run_id, 0

    def record(self, event: dict) -> None:
        self.seq += 1
        line = {"run_id": self.run_id, "seq": self.seq, "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **event}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")
