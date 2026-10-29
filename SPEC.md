# SPEC — sbomreach (SBOM 도달가능성 우선순위 에이전트)

작성 2026-10-30 · 대회 LOTTE AX Challenge 2026 예선 · 과제 문구 「SBOM 생성과 취약점 스캔 결과의 영향도·우선순위 연결 구조 설계」「AI 에이전트 기반 조치안 도출 및 개선」

## 1. 목적
SBOM(소프트웨어 부품 목록)과 취약점 스캔 결과는 따로 나와 경보가 수백 건이 된다. 보안 운영 담당은 그중 **이 저장소의 코드가 실제로 호출하는 것**을 하나씩 손으로 따진다. 이 도구는 (1) 저장소에서 SBOM을 만들고 (2) 알려진 취약점을 붙이고 (3) 취약 함수가 소스에서 호출되는지 **근거 줄(파일:줄)** 로 판정하고 (4) 급한 순서와 조치안(버전 올림)을 내고 (5) 조치를 적용한 가지(branch)에서 다시 스캔해 경보가 실제로 줄었는지 숫자로 확인한다.

핵심 원칙: **판정은 결정적 코드가 한다. LLM은 조치안 문장만 쓰고 판정·버전 숫자를 바꾸지 못한다.** 근거 줄이 없으면 「도달」이라 하지 않는다.

## 2. 유비쿼터스 언어 (코드 이름과 일치)
| 용어 | 뜻 |
|---|---|
| Component | SBOM의 부품 1개(이름·버전·생태계) |
| Advisory | 알려진 취약점 1건(OSV id·별칭·심각도·고쳐진 버전·취약 심볼 후보) |
| Alert | Component × Advisory 1쌍 = 경보 1건 |
| Symbol | 취약 함수·메서드 이름(예: `yaml.load`, `_.template`) |
| Evidence | 소스의 파일·줄·그 줄의 텍스트 |
| Verdict | 도달성 판정. `REACHED`(도달: 취약 심볼 호출 근거 줄 ≥1) · `USED`(사용: 패키지 import 근거 줄만 있고 취약 심볼 호출 근거 없음) · `UNSEEN`(미확인: 소스에 import 근거 줄 없음 — 전이 의존·동적 로딩 가능성을 배제하지 않음) |
| Priority | 우선순위 점수 = 심각도 가중 × 도달 가중 (가중표는 `domain/priority.py`) |
| Remediation | 조치안 1건(패키지·현재→목표 버전·근거 Advisory 목록·문장) |
| Rescan | 조치 적용 가지에서 SBOM·스캔을 다시 돌려 얻은 경보 수 |
| Gold | 사람이 아닌 AI(Claude)가 소스 줄을 직접 열어 검산해 **도구 실행 전에 동결**한 정답 |

## 3. 숫자 성공 조건 (예선 증거 기준)
| # | 조건 | 측정 |
|---|---|---|
| S1 | 공개 저장소 ≥3, 언어 ≥2(Python·JavaScript)에서 SBOM → 스캔 → 판정 → 우선순위 → 조치 → 재스캔이 끝까지 돈다 | `evidence/runs/*.json` 의 `stage_status` 전부 ok |
| S2 | Gold ≥30건(저장소당 ≥8건)과 도구 판정의 3분류(도달·사용·미확인) 일치율 표를 낸다. 목표 ≥80%, 못 미치면 못 미친 그대로 표에 쓴다 | `evidence/accuracy.md` |
| S3 | 모든 `REACHED` 판정은 근거 줄 ≥1을 갖는다(거짓 도달 0의 구조적 보장) | 시험 `test_reached_requires_evidence` |
| S4 | 조치 적용 가지에서 재스캔한 뒤 `REACHED` 경보가 저장소마다 감소(목표 0)하고, 전체 경보 감소 수를 낸다. 조치로 올린 패키지 수도 같이 낸다 | `evidence/rescan.md` |
| S5 | 시험 ≥40건이 네트워크 없이 10초 안에 통과한다. 도메인 계층은 표준 라이브러리 밖을 import하지 않는다(시험으로 집행) | `python3 -m pytest` |
| S6 | 가드레일 ≥3개가 코드로 집행되고 각각 시험이 있다. 실행마다 도구 호출 trace(JSONL)를 남긴다 | `tests/test_guardrails.py`, `evidence/trace-sample.jsonl` |
| S7 | 저장소 1개 종단 실행 ≤120초(네트워크 캐시 적중 기준) | 실행 로그의 elapsed |
| S8 | 「건당 분 절감」「인건비 단가」는 **가정값**이라 출력 첫 줄에 「가정」을 붙인다 | 시험 `test_effect_labelled_assumption` |

## 4. Given / When / Then
- G: requirements.txt에 `PyYAML==5.1`이 있고 소스에 `yaml.load(x)`가 있다 · W: 스캔 · T: 해당 Alert 판정 `REACHED`, Evidence에 그 파일·줄이 있다.
- G: 같은 패키지가 import되지만 취약 심볼(`yaml.load`)은 어디서도 호출되지 않는다(`yaml.safe_load`만) · T: `USED`.
- G: 패키지가 소스 어디서도 import되지 않는다(전이 의존) · T: `UNSEEN`, 우선순위는 `REACHED`보다 항상 낮다.
- G: 어드바이저리에서 취약 심볼을 못 뽑았다 · T: 판정은 `USED`(import만 확인) 이하이며 `REACHED`가 될 수 없다(거짓 도달 금지).
- G: LLM이 조치안 문장에 어드바이저리에 없는 버전 숫자를 썼다 · T: 가드레일이 문장을 버리고 템플릿 문장으로 바꾸고 trace에 `guardrail_block` 기록.
- G: LLM이 판정을 바꾸려는 출력을 냈다 · T: 판정은 불변, 위반 기록.
- G: 취약점 조회(OSV) 실패 · T: 재시도 2회 후 Alert를 만들지 않고 `scan_incomplete`로 표시 — 「경보 0 = 안전」으로 보고하지 않는다.
- G: syft 실행 파일이 없다 · T: 잠금 파일 파서로 대체하고 trace에 `fallback` 기록.
- G: 조치 적용 가지에서 패키지를 올렸다 · T: 재스캔 Alert 수가 조치 전과 나란히 출력되고 줄어든 수·남은 수·새로 생긴 수를 구분한다.

## 5. 계층 (Clean Architecture)
`domain/` ← `application/` ← `adapters/` ← `infrastructure/` 역방향 import 금지.
- domain: 모델, 도달 판정 규칙, 우선순위, 가드레일, 평가(일치율). 표준 라이브러리만.
- application: 파이프라인 사용 사례, 포트(Protocol).
- adapters: syft/CycloneDX 파서, OSV 응답 파서, Python·JS 소스 분석기, 매니페스트 편집, Gemini 프롬프트.
- infrastructure: HTTP, 프로세스 실행, 파일, trace 기록기, CLI.

## 6. 비목표 (하지 않는 것 — 허위 방지)
- 전이 의존의 패키지 간 호출 그래프는 만들지 않는다. 전이 의존은 `UNSEEN`이며 「안전」이 아니다.
- 동적 import·리플렉션·템플릿 문자열 속 호출은 못 본다. JS 분석은 정규식 기반(구문 분석 아님)이라 주석·문자열 제거 후 토큰 매칭이다.
- Python 호출 분석은 `ast` 기반 이름 해석(별칭 import 포함)이다. 인스턴스 메서드 타입 추론은 하지 않는다.
- 취약점 DB는 OSV(osv.dev) 하나다. NVD·벤더 전용 DB와 일치한다고 주장하지 않는다.
- 악용 가능성(EPSS)·네트워크 노출 여부는 판정하지 않는다.
- 롯데 실저장소·실데이터는 쓰지 않았다(예선). 효과 숫자(건당 분·단가)는 가정이다.
- 모델 학습 없음. 대용량 데이터 내려받기 없음. 대상 저장소의 코드는 **읽기만** 하고 실행·설치하지 않는다.
