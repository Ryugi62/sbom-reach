# sbomreach — SBOM 도달가능성 우선순위 에이전트 (LOTTE AX Challenge 2026 예선 프로토타입)

SBOM 생성 → 취약점 조회(OSV) → 취약 함수 도달 판정(근거 줄) → 우선순위·조치안 → 조치 가지 적용 → 재스캔. 판정은 결정적 코드, LLM(Gemini)은 조치안 문장만.
스펙은 [SPEC.md](SPEC.md), 정답 작성 규약은 [evidence/GOLD.md](evidence/GOLD.md).

## 실행
```
python3 -m pytest -q                                                   # 오프라인 시험
python3 -m sbomreach.infrastructure.cli scan --target nodejs-goof      # 대상은 evidence/targets.json
python3 -m sbomreach.infrastructure.cli remediate --target nodejs-goof --scope reached
python3 -m sbomreach.infrastructure.cli eval --gold gold-holdout.jsonl --out accuracy-v1-holdout.md
python3 -m sbomreach.infrastructure.cli summary                        # evidence/summary.json
```
대상 저장소는 ~/untrusted/에 읽기 전용으로 받아 두며(targets.json의 커밋 고정), 코드는 실행·설치하지 않는다. syft는 `tools/bin/syft`(없으면 잠금 파일 파서).
OSV 응답 스냅샷: `evidence/osv-snapshot-2026-10-30.tar.gz` (풀면 `data/osv-cache/`).

## 증거 위치
`evidence/runs-v1/`(판정·순위) · `evidence/rescan/`(재스캔) · `evidence/accuracy-*.md` · `evidence/gold*.jsonl` · `evidence/traces/`(도구 호출 trace) · `docs/`(구조도·문서 빌드)
