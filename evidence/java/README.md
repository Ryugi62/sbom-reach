# Java(Maven) 실행 증거 — 2026-11-02

- 대상(교육용 아님, 고정 커밋은 `evidence/targets-java.json`): Apache DolphinScheduler · OpenRefine · JeecgBoot.
- 실행 결과: `evidence/runs/{dolphinscheduler,openrefine,jeecgboot}.json` (판정·근거 줄), trace의 `pom_stat`(선언 건수·외부 BOM으로 못 읽은 건수).
- 정답(`evidence/gold-java.jsonl`)은 Java 판정기 실행 전에 동결 — 첫 실행 `accuracy-java-first.md`(일치 66.7%, 도달 0건: groupId와 import 접두가 다른 부품 jackson·guava·hadoop을 UNSEEN으로 놓침) → 별칭표·일반 이름 보강 뒤 `accuracy-java.md`(100%, 사후 수정).
- 도달 정밀도는 정답 도달이 1건뿐이라 정답 묶음으로는 말할 수 없다. 대신 도구가 도달이라 한 2건을 실행 뒤 열어 봤다(사후 검산, `reached-audit.md`).
- 한계: pom.xml 직접 선언만(Gradle·외부 BOM 버전·전이 의존 없음), import 접두는 이름 규칙+별칭표 휴리스틱.
