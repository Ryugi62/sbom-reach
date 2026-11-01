# 정답 독립 재판정 — 다른 모델(Gemini gemini-3.5-flash-lite)

대상 30건(gold-holdout2.jsonl 에서 고정 난수 7로 추출) · 일치 26건 = 86.7% · **Cohen kappa = 0.75**

| 정답(Claude)＼재판정(Gemini) | REACHED | USED | UNSEEN | 판독불가 |
|---|---|---|---|---|
| REACHED | 5 | 2 | 0 | 0 |
| USED | 1 | 17 | 0 | 0 |
| UNSEEN | 0 | 1 | 4 | 0 |

다르게 본 건:

- vulnerable-flask-app requests GHSA-9hjg-9r4m-mvj7: Claude UNSEEN · Gemini USED — requests 패키지를 import하여 사용하고 있으나, 취약한 .netrc 자격 증명 유출 기능은 직접 호출하거나 참조하지 않습니다.
- nodejs-goof st GHSA-72fg-jqhx-c68p: Claude REACHED · Gemini USED — 저장소가 `st` 패키지를 임포트하여 사용하고 있지만, 어드바이저리가 지목한 취약한 리다이렉트 기능을 직접 호출하거나 설정하는 코드는 확인되지 않습니다.
- nodejs-goof body-parser GHSA-27r3-jxmh-p828: Claude REACHED · Gemini USED — 저장소가 'body-parser' 패키지를 불러와 사용하고 있지만, 어드바이저리가 지목한 취약한 'gzip' 기능이나 관련 코드를 직접 호출하는 흔적은 소스 코드에서 확인되지 않습니다.
- nodejs-goof mongoose GHSA-h8hf-x3f4-xwgp: Claude USED · Gemini REACHED — 저장소 코드가 `mongoose.Schema`를 직접 참조하여 스키마를 정의하고 있으므로 취약한 기능에 도달합니다.

한계: 두 모델 모두 AI다. 사람 검산을 대신하지 못한다. Gemini에게는 글자 검색으로 찾은 줄만 줬다(도구 판정·원래 정답은 숨김).
