# Java 도달 판정 2건 사후 검산 (실행 뒤 열어 봄 — 눈가림 아님)

| 저장소 | 부품 | 경보 | 근거 줄 | 판정 |
|---|---|---|---|---|
| dolphinscheduler | com.fasterxml.jackson.core:jackson-databind 2.13.2 | GHSA-3wrr-7qpf-2prh (JsonNode.toString 깊은 중첩 스택 오버플로) | `dolphinscheduler-task-plugin/.../task/http/HttpTask.java:273` `requestBodyJsonNode.toString()` (도구가 낸 근거 줄은 JsonNode 사용처 `DefaultHTMLTemplate.java:134` — 호출 줄 자체는 아님) | 도달 맞음 |
| dolphinscheduler | 같은 부품 2.13.4 | 같은 경보 | 같은 코드 | 도달 맞음(같은 advisory의 다른 버전) |

운영형 Java 101건 중 사람이 열어 볼 경보는 2건(둘 다 같은 advisory). 한계: 근거 줄이 호출 줄이 아니라 클래스 사용 줄이다.
