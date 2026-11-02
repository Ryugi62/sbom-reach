# sbomreach — SBOM 도달가능성 우선순위 에이전트 (LOTTE AX Challenge 2026 예선 프로토타입)

SBOM 생성 → 취약점 조회(OSV) → 취약 함수 도달 판정(근거 줄) → 우선순위·조치안 → 조치 가지 적용 → 재스캔. 판정은 결정적 코드, LLM(Gemini)은 세 자리(조치안 설명 문장 · 약한 도달 근거의 「사람 확인 필요」 표시 · 판정 뒤 다음에 부를 도구 계획)에만 쓰이며 판정·버전 숫자는 바꾸지 못한다.
스펙은 [SPEC.md](SPEC.md), 정답 작성 규약은 [evidence/GOLD.md](evidence/GOLD.md).

## 실행
실행은 파이썬 3.9+ **표준 라이브러리만** 쓴다(스캔은 syft가 있으면 사용, 없으면 잠금 파일 파서). **시험은 pytest**다(`pip install pytest`). PDF 문서 빌드(`docs/build_docs.py`)만 playwright·pypdf가 더 필요하다.
```
python3 -m pytest -q                                  # 오프라인 시험
python3 scripts/clone_targets.py                      # 9저장소(targets*.json)를 고정 커밋으로 받기: 4곳은 ./untrusted/, Java 3곳·운영형 2곳은 ~/untrusted/(코드 실행·설치 없음)
mkdir -p data && tar xzf evidence/osv-snapshot-2026-10-30.tar.gz -C data   # OSV 응답 스냅샷 → data/osv-cache/
python3 -m sbomreach.infrastructure.cli scan --target nodejs-goof      # 대상: evidence/targets.json의 name
python3 -m sbomreach.infrastructure.cli remediate --target nodejs-goof --scope reached
python3 -m sbomreach.infrastructure.cli eval --gold gold-holdout.jsonl --out accuracy-v1-holdout.md
python3 -m sbomreach.infrastructure.cli plan --target all              # 에이전트 계획 단계(S18): 도구 선택만, 판정 불변 → evidence/plans/
python3 scripts/compare_scanners.py                                   # osv-scanner·grype·trivy 경보 수 비교(S19) → evidence/scanner-compare.md (바이너리는 tools/scanners/)
python3 -m sbomreach.infrastructure.cli summary                        # evidence/summary.json
```
`evidence/targets.json`의 `path`는 저장소 루트 기준 상대경로다. 조치안 문장(Gemini)은 `GEMINI_API_KEY` 환경변수나 `SBOMREACH_ENV_FILE`(기본 `~/.config/sbomreach/gemini.env`)에 키가 있을 때만 쓰고, 없으면 템플릿 문장으로 계속한다. syft는 `tools/bin/syft` 또는 PATH. syft 없이 돌리면 잠금 파일 파서로 대체되어 부품·경보 수가 달라진다(nodejs-goof 경보 235 → 315, 도달 16은 같음).

## 증거 위치
`evidence/runs-v1/`(판정·순위) · `evidence/rescan/`(재스캔) · `evidence/accuracy-*.md` · `evidence/gold*.jsonl` · `evidence/traces/`(도구 호출 trace) · `docs/`(구조도·문서 빌드)

## 외부 도구 설치 (무료 단일 바이너리, `tools/`는 .gitignore라 클론에 없다)
실측에 쓴 버전: syft 1.55.0 · osv-scanner 2.7.0 · grype 0.121.0 · trivy 0.76.1. 각 공식 GitHub 릴리스(anchore/syft, google/osv-scanner, anchore/grype, aquasecurity/trivy)에서 내 운영체제용 바이너리를 받아 syft는 `tools/bin/syft`(또는 PATH), 나머지 셋은 `tools/scanners/`에 둔다(`scripts/compare_scanners.py`가 이 경로를 본다). 패키지 관리자로 설치해도 되지만 버전이 다르면 경보 수가 달라질 수 있다. syft가 없어도 판정은 돌고(잠금 파일 파서로 대체) 스캐너 3종은 비교 스크립트에만 필요하다.

## 재현 가능한 범위
- 오프라인으로 재현되는 것: 시험 264건(`python3 -m pytest -q`), 동봉한 증거 파일의 숫자 읽기.
- 저장소 9곳을 `clone_targets.py`로 받으면 같은 고정 커밋에서 판정(`scan`)을 다시 돌릴 수 있다. OSV 응답은 2026-10-30 스냅샷(`evidence/osv-snapshot-2026-10-30.tar.gz`)을 풀면 같은 입력이고, 스냅샷에 없는 부품은 OSV를 새로 조회하므로(네트워크 필요) 날짜가 지나면 경보 수가 달라질 수 있다.
- 그대로 재현되지 않는 것: 조치안 설명 문장·확인 표시·도구 계획은 Gemini 호출이라 `GEMINI_API_KEY`가 없으면 템플릿 문장과 기본 계획으로 대체되고, 있어도 모델 응답은 실행마다 다를 수 있다(캐시한 응답은 저장소에 없다). 스캐너 비교의 trivy는 Java 3곳에서 Maven Central 429로 원격 pom 해석을 생략했다. 운영형 Python·JS 2곳(healthchecks·uptime-kuma)은 정답을 쓰지 않아 정밀도를 재지 않았다.
