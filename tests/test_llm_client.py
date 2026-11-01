import json

import pytest

from sbomreach.application.explain import explain
from sbomreach.domain.models import Remediation, Verdict
from sbomreach.infrastructure.gemini import GeminiLlm, LlmHttpError


class Tr:
    def __init__(self):
        self.events = []

    def record(self, e):
        self.events.append(e)


def ok_body(text="hello"):
    return {"candidates": [{"content": {"parts": [{"text": text}]}}]}


def make(post, tr=None, **kw):
    sleeps = []
    llm = GeminiLlm("KEY123", post=post, sleep=sleeps.append, clock=lambda: 0.0, trace=tr, **kw)
    return llm, sleeps


def test_retries_429_then_succeeds_and_records_status():
    seq = [LlmHttpError(429, "RESOURCE_EXHAUSTED quota"), LlmHttpError(429, "RESOURCE_EXHAUSTED quota"), ok_body("문장")]

    def post(url, body):
        r = seq.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    tr = Tr()
    llm, sleeps = make(post, tr)
    assert llm.complete("p") == "문장"
    statuses = [e["status"] for e in tr.events if e["tool"] == "llm_call"]
    assert statuses == [429, 429, 200]
    assert len(sleeps) >= 2 and all(s > 0 for s in sleeps)


def test_gives_up_after_retries_with_status_code_in_error():
    def post(url, body):
        raise LlmHttpError(429, "RESOURCE_EXHAUSTED quota")

    llm, _ = make(post, retries=2)
    with pytest.raises(LlmHttpError) as e:
        llm.complete("p")
    assert e.value.status == 429 and "RESOURCE_EXHAUSTED" in e.value.body


def test_non_retryable_status_fails_fast():
    calls = []

    def post(url, body):
        calls.append(1)
        raise LlmHttpError(400, "INVALID_ARGUMENT")

    llm, _ = make(post)
    with pytest.raises(LlmHttpError):
        llm.complete("p")
    assert len(calls) == 1


def test_error_body_never_contains_api_key():
    def post(url, body):
        raise LlmHttpError(403, "bad key KEY123 here")

    tr = Tr()
    llm, _ = make(post, tr)
    with pytest.raises(LlmHttpError) as e:
        llm.complete("p")
    assert "KEY123" not in e.value.body
    assert all("KEY123" not in json.dumps(ev) for ev in tr.events)


def test_cache_prevents_second_call(tmp_path):
    calls = []

    def post(url, body):
        calls.append(1)
        return ok_body("캐시")

    llm, _ = make(post, cache_path=str(tmp_path / "c.json"))
    assert llm.complete("same") == "캐시"
    llm2, _ = make(post, cache_path=str(tmp_path / "c.json"))
    assert llm2.complete("same") == "캐시"
    assert len(calls) == 1


def test_min_interval_is_enforced_between_calls():
    t = [0.0]
    sleeps = []
    llm = GeminiLlm("K", post=lambda u, b: ok_body(), sleep=lambda s: (sleeps.append(s), t.__setitem__(0, t[0] + s)),
                    clock=lambda: t[0], min_interval=4.0)
    llm.complete("a")
    llm.complete("b")
    assert sleeps and sleeps[0] == pytest.approx(4.0)


def test_request_has_no_thinking_budget_param():
    # 실측: gemini-3.5-flash-lite 는 thinkingBudget 를 받으면 400. 요청 본문에 넣지 않는다.
    seen = []

    def post(url, body):
        seen.append(body)
        return ok_body()

    llm, _ = make(post)
    llm.complete("p")
    assert "thinkingConfig" not in json.dumps(seen[0])


def test_explain_fallback_trace_carries_status():
    class Bad:
        def complete(self, prompt):
            raise LlmHttpError(429, "RESOURCE_EXHAUSTED")

    tr = Tr()
    r = Remediation("pkg", "npm", "1.0.0", "1.2.3", ("GHSA-1",), Verdict.USED)
    out = explain(r, Bad(), Verdict.USED, tr)
    assert out.text_source == "template"
    fb = [e for e in tr.events if e["tool"] == "fallback"][0]
    assert fb["status"] == 429 and "RESOURCE_EXHAUSTED" in fb["detail"]
