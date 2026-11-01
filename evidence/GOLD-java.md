# Java 정답 — 동결 2026-11-02 (Java 판정기 실행 전)

- 작성자: Claude(AI). 사람 검산이 아니다. 저장소를 `~/untrusted/`에 받아 grep·줄 읽기로 판정했고, Java 판정 결과(verdict)를 **한 번도 보지 않은 채** 이 파일을 커밋했다(경보 목록은 판정 없는 `evidence/alerts/*.json`에서 가져옴).
- 대상: 교육용이 아닌 운영형 오픈소스 Java 3곳 — Apache DolphinScheduler(워크플로 스케줄러) · OpenRefine(데이터 정제 서버) · JeecgBoot(기업용 로우코드 플랫폼). 커밋은 `targets-java.json`.
- 고르기: 함수가 특정된 경보(심볼이 있거나 제목이 기능을 가리키는 것)만. 함수를 특정하지 않은 경보(logback·protobuf·sshd·beanutils 등)와 호출 여부가 모호한 것(jackson `readValue` 일반 호출)은 제외했다.
- 한계: 한 사람(AI)의 판단. 도달 정답이 1건뿐이라 이 묶음으로는 「도달 정밀도」를 말할 수 없다 — 도달 정밀도는 도구가 도달이라 한 전체를 실행 뒤 따로 열어 본 값(evidence/java/reached-audit.md, 사후 검산)으로 낸다.
