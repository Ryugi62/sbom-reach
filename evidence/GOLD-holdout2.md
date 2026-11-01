# 홀드아웃2 정답 — 동결 2026-11-02 (v1.3 판정기 수정 전)

- 작성자: Claude(AI). 사람 검산이 아니다. 소스 파일을 열어(grep·줄 읽기) 판정했고, **일반 이름 심볼 검증을 고치는 코드를 쓰기 전에** 이 파일을 커밋했다(커밋 메시지 「홀드아웃2 동결」).
- 후보 고르기: 4개 저장소의 경보 중 개발셋(gold.jsonl)·홀드아웃1(gold-holdout.jsonl)에 없는 것. v1.2 판정 도달인 14건은 전부 후보에 넣고, 사용 16건·미확인 6건은 고정 난수(seed 20261102)로 뽑았다. 즉 후보 선택은 v1.2 판정에 기대고 있다(편향 한계).
- 정직한 한계 1: 후보 목록을 만들 때 v1.2의 도달 판정 목록을 이미 봤다. 수정 규칙의 종류(모듈 경로형 심볼·시험/마이그레이션 근거 줄)는 그 목록과 개발셋 오류에서 나왔다. 그래서 이 값은 「정답 동결 뒤 수정 판정기의 첫 실행값」이지 완전한 눈가림 측정이 아니다. 완전히 새로운 입력은 Java 저장소 실행(evidence/java/)이다.
- 정직한 한계 2: 한 사람(AI)의 판단이다. 20~30건은 다른 모델(Gemini)로 독립 재판정해 일치도(Cohen kappa)를 evidence/kappa.md에 둔다.
- 제외(정답이 애매해 넣지 않음, 4건): pygoat django GHSA-pv4p-cwwg-4rph · GHSA-6w2r-r2m5-xq5w(함수 미특정 SQL 주입 — aggregate 사용은 있음), vulnerable-flask-app tornado GHSA-7cx3-6m66-7c5m · GHSA-8w49-h785-mj3c(HTTPServer 내부 파싱 — 함수 미특정).
- pygoat의 dockerized_labs는 스캔 범위 밖(targets.json excludes)이라 그 안의 import는 근거로 치지 않는다 — 그쪽 경보 4건은 후보에서 뺐다.
- 분류 정의는 evidence/GOLD.md와 같다.
