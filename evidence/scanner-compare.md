# 스캐너 비교 — 같은 고정 커밋, 경보 개수 (SPEC S19)

측정 2026-11-03 · 무료 단일 바이너리 · 결제 0 · 저장소는 읽기만(.git·우리 excludes 제외한 복사본)

도구 버전: osv-scanner `osv-scanner version: 2.7.0` · grype `Version:             0.121.0` · trivy `Version: 0.76.1`

| 저장소 | 그들은 경보 · osv-scanner | 그들은 경보 · grype | 그들은 경보 · trivy | 우리 전체 경보 | 우리는 사람이 볼 경보 M | 근거 줄 K |
|---|---|---|---|---|---|---|
| vulnerable-flask-app | 91 | 84 | 84 | 89 | 5건 | 7줄 |
| pygoat | 275 | 198 | 198 | 201 | 5건 | 14줄 |
| nodejs-goof | 269 | 237 | 245 | 235 | 15건 | 28줄 |
| nodegoat | 206 | 92 | 94 | 90 | 4건 | 12줄 |
| openrefine | 28 | 22 | 15 (Maven Central 429로 원격 pom 해석 생략(--offline-scan), 전이 의존 일부 누락 가능) | 8 | 0건 | 0줄 |
| jeecgboot | 276 | 14 | 14 (Maven Central 429로 원격 pom 해석 생략(--offline-scan), 전이 의존 일부 누락 가능) | 13 | 0건 | 0줄 |
| dolphinscheduler | 376 | 129 | 127 (Maven Central 429로 원격 pom 해석 생략(--offline-scan), 전이 의존 일부 누락 가능) | 80 | 2건 | 10줄 |
| healthchecks | 42 | 35 | 35 | 36 | 8건 | 34줄 |
| uptime-kuma | 370 | 204 | 203 | 204 | 54건 | 156줄 |

읽는 법
- 그들의 경보 = 패키지×버전×취약점 id 고유 건수(osv-scanner는 별칭 묶음 1건, grype·trivy는 보고서의 id 그대로라 같은 취약점이 CVE·GHSA로 따로 셀 수 있음).
- 우리 전체 경보 = 우리 파이프라인이 만든 Alert 수(별칭 중복 제거). M = 근거 줄이 있는 `REACHED`, K = 그 근거 줄 합.
- 개수 비교일 뿐이다. 이 도구들은 소스 호출 여부를 판정하지 않으므로(설계 목적이 다름) 정밀도 비교가 아니며 틀렸다는 뜻도 아니다. 도구마다 읽는 파일(잠금 파일·매니페스트·소스 트리)이 달라 개수가 다르다.
- 「실행 못 함」 칸은 숫자를 채우지 않고 오류 원문을 적었다.
