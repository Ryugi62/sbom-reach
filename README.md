# sbomreach — SBOM 도달가능성 우선순위 에이전트 (LOTTE AX Challenge 2026 예선 프로토타입)

SBOM 생성 → 취약점 조회(OSV) → 취약 함수 도달 판정(근거 줄) → 우선순위·조치안 → 조치 가지 적용 → 재스캔. 판정은 결정적 코드, LLM(Gemini)은 조치안 문장만.
스펙은 [SPEC.md](SPEC.md), 정답 작성 규약은 [evidence/GOLD.md](evidence/GOLD.md).

## 실행
실행은 파이썬 3.9+ **표준 라이브러리만** 쓴다(스캔은 syft가 있으면 사용, 없으면 잠금 파일 파서). **시험은 pytest**다(`pip install pytest`). PDF 문서 빌드(`docs/build_docs.py`)만 playwright·pypdf가 더 필요하다.
```
python3 -m pytest -q                                  # 오프라인 시험
python3 scripts/clone_targets.py                      # targets.json의 4저장소를 고정 커밋으로 untrusted/에 받기(코드 실행·설치 없음)
tar xzf evidence/osv-snapshot-2026-10-30.tar.gz       # OSV 응답 스냅샷 → data/osv-cache/
python3 -m sbomreach.infrastructure.cli scan --target nodejs-goof      # 대상: evidence/targets.json의 name
python3 -m sbomreach.infrastructure.cli remediate --target nodejs-goof --scope reached
python3 -m sbomreach.infrastructure.cli eval --gold gold-holdout.jsonl --out accuracy-v1-holdout.md
python3 -m sbomreach.infrastructure.cli summary                        # evidence/summary.json
```
`evidence/targets.json`의 `path`는 저장소 루트 기준 상대경로다. 조치안 문장(Gemini)은 `GEMINI_API_KEY` 환경변수나 `SBOMREACH_ENV_FILE`(기본 `~/.config/sbomreach/gemini.env`)에 키가 있을 때만 쓰고, 없으면 템플릿 문장으로 계속한다. syft는 `tools/bin/syft` 또는 PATH.

## 증거 위치
`evidence/runs-v1/`(판정·순위) · `evidence/rescan/`(재스캔) · `evidence/accuracy-*.md` · `evidence/gold*.jsonl` · `evidence/traces/`(도구 호출 trace) · `docs/`(구조도·문서 빌드)
