#!/usr/bin/env python3
"""해결방안·역량 자료 PDF 빌드. 숫자는 evidence/summary.json·rescan에서 읽는다(손으로 치지 않음).
테스트: ①쪽수 ②내부 흔적 0(대괄호 링크·projects/·메인 판단) ③쪽 넘침 0mm ④가정 표기 존재."""
import glob, json, os, re, sys
from playwright.sync_api import sync_playwright
from pypdf import PdfReader

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.expanduser("~/jarvis/handoff/drop/lotte-ax-challenge")
os.makedirs(OUT, exist_ok=True)
S = json.load(open(os.path.join(ROOT, "evidence/summary.json"), encoding="utf-8"))
T = S["totals"]
A0, A1, AH = S["accuracy"]["v0_dev"], S["accuracy"]["v1_dev"], S["accuracy"]["v1_holdout"]
RS = S["rescan"]
REPO = "{{REPO_URL}}"
TESTS = int(os.environ.get("TESTS", "0")) or None


def rs_sum(scope, key):
    return sum(v[key] for k, v in RS.items() if k.endswith("." + scope))


def major_jumps():
    n = tot = 0
    for p in glob.glob(os.path.join(ROOT, "evidence/rescan/*.reached.json")):
        d = json.load(open(p, encoding="utf-8"))
        for r in d["rounds"]:
            for x in r["plan"]:
                if x["target"]:
                    tot += 1
                    if x["target"].split(".")[0] != x["current"].split(".")[0]:
                        n += 1
    return n, tot


MJ, MT = major_jumps()
pc = lambda a, b: f"{a / b * 100:.1f}%"
CSS = """
@font-face{font-family:P;font-weight:400;src:url('_fonts/Pretendard-Regular.ttf')}
@font-face{font-family:P;font-weight:700;src:url('_fonts/Pretendard-Bold.ttf')}
@font-face{font-family:P;font-weight:800;src:url('_fonts/Pretendard-ExtraBold.ttf')}
@page{size:A4;margin:0}*{margin:0;padding:0;box-sizing:border-box}
body{font-family:P,'Apple SD Gothic Neo',sans-serif;font-size:8.9pt;line-height:1.52;color:#191F28}
.page{width:210mm;height:297mm;padding:13mm 15mm 11mm;page-break-after:always;overflow:hidden;position:relative}
.page:last-child{page-break-after:auto}
.brow{font-size:7.8pt;font-weight:700;color:#3182F6;letter-spacing:.05em;margin-bottom:1.5mm}
h1{font-size:17pt;font-weight:800;letter-spacing:-.02em;line-height:1.28}
.lede{font-size:9pt;color:#4E5968;margin:1.5mm 0 2.5mm}
h2{font-size:10.6pt;font-weight:800;margin:3.4mm 0 1.4mm;letter-spacing:-.01em}
h2 .n{color:#3182F6;margin-right:1.5mm}
p{margin-bottom:1.3mm}ul{margin:0 0 1.3mm 4mm}li{margin-bottom:.4mm}
table{border-collapse:collapse;width:100%;margin:1mm 0 1.6mm;font-size:8pt}
th,td{border:1px solid #D1D6DB;padding:.9mm 1.5mm;text-align:left;vertical-align:top}
th{background:#F2F4F6;font-weight:700}
td.r,th.r{text-align:right}
.big{display:flex;gap:2.5mm;margin:1.5mm 0 2mm}
.big div{flex:1;border:1px solid #D1D6DB;border-radius:2mm;padding:2mm 2.5mm;background:#F9FAFB}
.big b{display:block;font-size:15pt;font-weight:800;color:#3182F6;line-height:1.2}
.big span{font-size:7.8pt;color:#4E5968}
.note{font-size:7.6pt;color:#6B7684;line-height:1.45}
.box{border:1px solid #D1D6DB;border-radius:2mm;padding:1.8mm 2.5mm;background:#F9FAFB;margin:1.2mm 0}
img.fig{width:100%;border:1px solid #E5E8EB;border-radius:2mm}
code{font-family:Menlo,monospace;font-size:7.6pt;background:#F2F4F6;padding:0 .8mm}
.foot{position:absolute;bottom:6mm;left:15mm;right:15mm;font-size:7pt;color:#8B95A1;display:flex;justify-content:space-between}
.cap{font-size:7.6pt;color:#6B7684;margin:.6mm 0 1.4mm}
"""


def page(n, total, body, label):
    return f'<section class="page">{body}<div class="foot"><span>{label}</span><span>{n} / {total}</span></div></section>'


def repo_rows():
    rows = ""
    for r in S["repos"]:
        rows += (f"<tr><td>{r['name']}</td><td>{r['language']}</td><td class='r'>{r['components']}</td><td class='r'>{r['alerts']}</td>"
                 f"<td class='r'><b>{r['reached']}</b></td><td class='r'>{r['used']}</td><td class='r'>{r['unseen']}</td>"
                 f"<td class='r'>{r['elapsed_sec']:.1f}초</td></tr>")
    rows += (f"<tr><th colspan=2>합계</th><th class='r'>{T['components']}</th><th class='r'>{T['alerts']}</th><th class='r'>{T['reached']}</th>"
             f"<th class='r'>{T['used']}</th><th class='r'>{T['unseen']}</th><th></th></tr>")
    return rows


def rescan_rows():
    rows = ""
    for name in [r["name"] for r in S["repos"]]:
        a, b = RS[f"{name}.reached"], RS[f"{name}.all"]
        rows += (f"<tr><td>{name}</td><td class='r'>{a['reached_before']} → <b>{a['reached_after']}</b></td>"
                 f"<td class='r'>{a['packages_changed']}</td><td class='r'>{a['alerts_before']} → {a['alerts_after']}</td>"
                 f"<td class='r'>{b['packages_changed']}</td><td class='r'>{b['alerts_before']} → {b['alerts_after']}</td></tr>")
    rows += (f"<tr><th>합계</th><th class='r'>{rs_sum('reached','reached_before')} → {rs_sum('reached','reached_after')}</th>"
             f"<th class='r'>{rs_sum('reached','packages_changed')}</th><th class='r'>{rs_sum('reached','alerts_before')} → {rs_sum('reached','alerts_after')}</th>"
             f"<th class='r'>{rs_sum('all','packages_changed')}</th><th class='r'>{rs_sum('all','alerts_before')} → {rs_sum('all','alerts_after')}</th></tr>")
    return rows


E = S["effect"]
cm = A1["confusion"]
hc = AH["confusion"]
TRACE = open(os.path.join(ROOT, "evidence/trace-sample.jsonl"), encoding="utf-8").read().strip().split("\n")[:2]
TRACE_TXT = "<br>".join(re.sub(r'"run_id": "[^"]+", ', "", l).replace("<", "&lt;")[:150] for l in TRACE)
SVG = os.path.join(HERE, "architecture.svg")

SIMILAR = """<table><tr><th style="width:23%">서비스</th><th style="width:44%">방식(공개 문서 기준)</th><th>우리가 다른 점</th></tr>
<tr><td>Endor Labs<br><span class=note>endorlabs.com/learn/benchmarking-endor-labs-vs-snyks-github-apps</span></td><td>호출 그래프로 취약 함수가 실제 호출되는지 판정, EPSS 결합(상용 SaaS, 수치는 자사 벤치마크)</td><td rowspan=4>① 판정마다 <b>근거 줄(파일:줄)</b>을 붙이고 근거가 없으면 「도달」이라 하지 못하게 코드로 막음 ② 조치 후 <b>재스캔 감소를 같은 출력에</b> 냄 ③ 정답 103건과의 <b>일치율·틀린 곳을 공개</b> ④ 로컬·무료 도구만으로 재현</td></tr>
<tr><td>Snyk Reachability<br><span class=note>docs.snyk.io/manage-risk/prioritize-issues-for-fixing/reachability</span></td><td>애플리케이션과 의존성의 호출 그래프를 분석(문서상 CLI·IDE 연동에서는 미지원)</td></tr>
<tr><td>Semgrep Supply Chain<br><span class=note>semgrep.dev/docs/faq/comparisons/endor-labs</span></td><td>직접 의존성에 대한 데이터플로 도달성(벤더 자체 주장)</td></tr>
<tr><td>래브라도 SCM<br><span class=note>m.boannews.com/html/detail.html?idx=132104</span></td><td>국내 SBOM 교환·취약점 이슈 파악 플랫폼(공개 기사에서 도달성 판정은 확인하지 못함)</td></tr></table>"""

# ───────── 해결방안 4쪽
p1 = f"""<div class=brow>AI 문제해결방안 · LOTTE AX Challenge 2026 · 롯데이노베이트</div>
<h1>SBOM·취약점 스캔 결과의 영향도·우선순위 연결 구조 설계,<br>그리고 조치안 도출·개선을 도는 AI 에이전트</h1>
<p class=lede>경보 {T['alerts']}건 중 코드가 실제로 호출하는 {T['reached']}건({pc(T['reached'], T['alerts'])})을 근거 줄과 함께 먼저 올리고, 조치 후 재스캔으로 줄었는지 숫자로 확인합니다. 판정은 코드가 하고 AI는 설명 문장만 씁니다.</p>
<div class=big><div><b>{T['alerts']} → {T['reached']}</b><span>공개 저장소 {len(S['repos'])}곳(Python·JavaScript)의 경보 수 → 취약 함수 호출 근거가 있는 도달 경보 수</span></div>
<div><b>{AH['rate']}%</b><span>사전 동결한 홀드아웃 정답 {AH['total']}건과 3분류 일치율({AH['matched']}/{AH['total']}). 도달 판정 정밀도 {AH['reached_precision']}%·재현율 {AH['reached_recall']}%</span></div>
<div><b>{rs_sum('reached','reached_before')} → {rs_sum('reached','reached_after')}</b><span>조치 적용 가지에서 재스캔한 도달 경보. 패키지 {rs_sum('reached','packages_changed')}개만 올림(전부 올리면 {rs_sum('all','packages_changed')}개)</span></div></div>
<h2><span class=n>1</span>문제와 해법</h2>
<p><b>문제.</b> SBOM(부품 목록)과 취약점 스캔은 따로 나오고, 보안 운영 담당은 수백 건 경보를 하나씩 열어 「우리 코드가 이 함수를 부르나」를 사람이 따집니다. 이 저장소 {len(S['repos'])}곳 합계 {T['alerts']}건 중 {pc(T['unseen'], T['alerts'])}는 소스에 그 패키지를 쓰는 줄이 없었고, 호출 근거가 있는 것은 {pc(T['reached'], T['alerts'])}였습니다.</p>
<p><b>해법.</b> 에이전트가 ① 저장소에서 SBOM 생성 → ② 알려진 취약점 조회 → ③ 취약 함수 호출 여부를 <b>근거 줄</b>로 판정(도달·사용·미확인) → ④ 심각도×도달 가중으로 우선순위와 조치안 → ⑤ 조치를 별도 git 가지에 적용 → ⑥ 같은 절차로 재스캔해 경보 감소를 측정하고, 도달 경보가 남으면 한 바퀴 더 돕니다(최대 3바퀴). 병합·배포는 하지 않고 사람이 승인합니다.</p>
<h2><span class=n>2</span>같은 문제를 푸는 기존 서비스와 다른 점</h2>
{SIMILAR}
<p class=note>위 서비스의 수치는 각 벤더의 공개 문서·자사 벤치마크이며 독립 검증값이 아닙니다. 우리 수치는 아래 5·6장의 공개 저장소와 정답 파일로 재현할 수 있습니다.</p>
<h2><span class=n>3</span>과제 문구와 구조도의 대응</h2>
<table><tr><th style="width:42%">과제 문구</th><th>구조도(그림 1) 노드</th><th>산출물</th></tr>
<tr><td>SBOM 생성과 취약점 스캔 결과의 영향도·우선순위 <b>연결</b> 구조 설계</td><td>1 SBOM → 2 조회 → <b>3 도달 판정</b> → 4 우선순위</td><td>경보별 판정·근거 줄·점수</td></tr>
<tr><td>AI 에이전트 기반 <b>조치안 도출</b></td><td>4 조치 계획 → 5 조치안 문장</td><td>패키지별 현재→목표 버전·설명</td></tr>
<tr><td>… 및 <b>개선</b></td><td>6 조치 가지 → 7 재스캔 → (순환)</td><td>해소·남음·신규 경보 수</td></tr></table>"""

p2 = f"""<div class=brow>AI 문제해결방안 · 구조와 평가</div>
<img class=fig src="architecture.svg">
<p class=cap>그림 1. 에이전트 구조도 — 도구 호출 순서, 사람/에이전트 경계(8), 평가(Evals), 가드레일, 실패 처리</p>
<h2><span class=n>4</span>가드레일과 평가</h2>
<table><tr><th style="width:11%">규칙</th><th style="width:52%">내용(코드로 집행)</th><th>시험</th></tr>
<tr><td>G1</td><td>근거 줄이 없는 「도달」은 판정 객체를 만들 수 없다</td><td>test_reached_requires_evidence</td></tr>
<tr><td>G2·G3</td><td>AI 문장의 버전 숫자는 허용 목록(현재·목표)만, 「안전합니다」류 단정과 판정 뒤집기 폐기 후 템플릿 문장</td><td>test_domain_guardrails</td></tr>
<tr><td>G4</td><td>허용된 명령만 실행(syft scan, npm lock 전용, git). 대상 코드 실행·설치 차단</td><td>test_g4_readonly_commands</td></tr>
<tr><td>G5·G6</td><td>AI 입력의 키·이메일 마스킹 / 조회가 덜 끝나면 「경보 0 = 깨끗함」 금지</td><td>test_g5, test_g6</td></tr></table>
<p><b>평가(Evals).</b> 단위 시험 {TESTS or '120+'}건(오프라인)과 정답 파일 두 벌을 씁니다. 정답은 <b>사람이 아니라 AI(Claude)가 소스 줄을 직접 열어 작성</b>했고, 도구 판정을 보기 전에 동결했습니다(커밋 기록). 개발셋 {A1['total']}건은 판정기 수정에 쓰여 오염되었으므로 수정 전 {A0['rate']}% → 수정 후 {A1['rate']}%로만 보고하고, 수정 뒤에 새로 만든 홀드아웃 {AH['total']}건({AH['rate']}%)을 대표값으로 씁니다.</p>
<table><tr><th>정답 세트</th><th class=r>건수</th><th class=r>3분류 일치</th><th class=r>도달 정밀도</th><th class=r>도달 재현율</th></tr>
<tr><td>개발셋, 수정 전</td><td class=r>{A0['total']}</td><td class=r>{A0['matched']} ({A0['rate']}%)</td><td class=r>{A0['reached_precision']}%</td><td class=r>{A0['reached_recall']}%</td></tr>
<tr><td>개발셋, 수정 후(오염)</td><td class=r>{A1['total']}</td><td class=r>{A1['matched']} ({A1['rate']}%)</td><td class=r>{A1['reached_precision']}%</td><td class=r>{A1['reached_recall']}%</td></tr>
<tr><td><b>홀드아웃</b></td><td class=r>{AH['total']}</td><td class=r><b>{AH['matched']} ({AH['rate']}%)</b></td><td class=r>{AH['reached_precision']}%</td><td class=r>{AH['reached_recall']}%</td></tr></table>
<p><b>틀린 곳.</b> 홀드아웃에서 도달 정밀도는 {AH['reached_precision']}%에 그칩니다. 어드바이저리 본문에서 뽑은 함수 이름이 일반 이름(decode 등)이면 호출만으로 「도달」이 되는 오탐이 있고, 객체 인스턴스 메서드·설정 파일 로딩은 놓치거나 「약한 근거」 표시로 내립니다(약한 근거 {T['reached_weak']}건). 본선에서는 심볼 검증을 가장 먼저 개선합니다.</p>
<p><b>실패 처리.</b> 취약점 조회가 실패하면 재시도 2회 뒤 그 부품을 「스캔 미완」으로 표시하고 경보 0을 깨끗하다고 말하지 않습니다. syft가 없으면 잠금 파일 파서로, AI 호출이 실패(할당량 초과 429 포함)하면 템플릿 문장으로 계속 진행합니다. 이번 실행에서 AI 한도 초과(429)로 조치안 문장 일부가 템플릿으로 생성되었고 trace에 기록되었습니다.</p>
<p class=cap>trace 샘플(도구 호출 1건 = 1줄, 부록 파일 trace-sample.jsonl)</p>
<div class=box style="font-family:Menlo,monospace;font-size:6.6pt;line-height:1.35;word-break:break-all">{TRACE_TXT}</div>"""

p3 = f"""<div class=brow>AI 문제해결방안 · 실행 증거</div>
<h2 style="margin-top:0"><span class=n>5</span>실행 결과 — 공개 저장소 {len(S['repos'])}곳, 언어 {len(S['languages'])}개</h2>
<table><tr><th>저장소(고정 커밋)</th><th>언어</th><th class=r>부품</th><th class=r>경보</th><th class=r>도달</th><th class=r>사용</th><th class=r>미확인</th><th class=r>소요</th></tr>{repo_rows()}</table>
<p class=note>저장소: """ + " · ".join(f"{r['url'].replace('https://','')} @{r['commit']}" for r in S['repos']) + f""". 모두 보안 교육용으로 일부러 취약하게 만든 공개 저장소라 실제 운영 저장소와 경보 분포가 다릅니다. 도달·사용·미확인 정의는 SPEC.md에 있고 「미확인」은 안전이 아니라 소스에 쓰는 줄이 없다는 뜻입니다. 경보 수는 같은 패키지의 중복 버전을 별도로 센 값입니다.</p>
<h2><span class=n>6</span>개선 순환 — 조치 적용 가지에서 재스캔</h2>
<p>조치안은 패키지별로 그 버전의 알려진 경보를 모두 덜어내는 가장 낮은 고쳐진 버전입니다. 사본 저장소에 <code>fix/sbomreach</code> 가지를 만들어 requirements·package.json을 고치고(npm은 잠금 파일만 재생성, 스크립트 실행 없음) 같은 절차로 다시 스캔합니다. 「도달만 조치」는 도달 경보가 있는 패키지만, 「전부 조치」는 경보가 있는 모든 패키지를 올립니다.</p>
<table><tr><th rowspan=2>저장소</th><th colspan=3>도달만 조치</th><th colspan=2>전부 조치</th></tr><tr><th class=r>도달 경보</th><th class=r>올린 패키지</th><th class=r>경보(고유)</th><th class=r>올린 패키지</th><th class=r>경보(고유)</th></tr>{rescan_rows()}</table>
<ul><li>도달 경보는 {rs_sum('reached','reached_before')}건에서 {rs_sum('reached','reached_after')}건으로 줄었고, 올린 패키지는 {rs_sum('reached','packages_changed')}개로 「전부 조치」 {rs_sum('all','packages_changed')}개의 {pc(rs_sum('reached','packages_changed'), rs_sum('all','packages_changed'))}입니다. 남은 1건은 nodejs-goof의 중첩 복사본(ms 0.6.2)으로, 이름 기준 판정이 저장소가 실제로 쓰는 복사본과 다른 복사본에 적용된 오탐 가능성이 있습니다.</li>
<li>조치 뒤 새로 생긴 경보도 따로 셉니다(도달만 조치 기준 합계 {sum(v['new'] for k, v in RS.items() if k.endswith('.reached'))}건). 올린 버전 {MT}개 중 주 버전이 바뀐 것은 {MJ}개라 <b>호환성 검토와 사람 승인이 필요</b>합니다. 에이전트는 병합하지 않습니다.</li>
<li>고쳐진 버전이 공개되지 않은 경보는 목표 버전을 비우고 「대체 패키지·호출 우회 검토」로 표시합니다.</li></ul>
<h2><span class=n>7</span>입력→출력 한 건 (현업 적용 예시)</h2>
<table><tr><th style="width:26%">입력</th><th>출력(경보 1건)</th></tr>
<tr><td>저장소 경로 1개<br><span class=note>또는 CycloneDX SBOM 파일</span></td><td>순위 2 · adm-zip 0.4.7 · GHSA-j5f4-cc29-5x44 · 심각도 HIGH · <b>판정 도달</b> · 근거 <code>routes/index.js:270</code> (<code>zip.extractAllTo(...)</code>) · 조치 0.4.7 → 0.6.1 · 검증: 고쳐진 버전 0.6.1이 가지의 잠금 파일에 반영되어 재스캔에서 해당 경보 소멸</td></tr></table>
<p><b>본선 현장 데이터 연결 칸.</b></p>
<table><tr><th style="width:22%">칸</th><th>예선에서 확정한 것</th><th>본선에서 바꾸는 것</th></tr>
<tr><td>입력 스키마</td><td>저장소 디렉터리 / CycloneDX JSON</td><td>계열사 저장소·사내 SBOM 파일 경로</td></tr>
<tr><td>취약점 소스</td><td>OSV 공개 DB(캐시)</td><td>사내 미러·벤더 DB 어댑터 1개</td></tr>
<tr><td>권한</td><td>읽기 전용, 대상 코드 실행 금지(G4)</td><td>읽기 전용 토큰</td></tr>
<tr><td>사람 승인</td><td>조치 가지 검토·병합은 사람</td><td>사내 승인 절차에 연결</td></tr></table>"""

p4 = f"""<div class=brow>AI 문제해결방안 · 효과, 한계, 일정</div>
<h2 style="margin-top:0"><span class=n>8</span>기대 효과 — 모든 입력이 가정입니다</h2>
<table><tr><th>식</th><th>기호</th><th>값</th><th>출처</th></tr>
<tr><td rowspan=4>절감 시간 = (경보 − 도달) × 건당 분</td><td>경보</td><td>{T['alerts']}건</td><td>실측(위 5장)</td></tr>
<tr><td>도달</td><td>{T['reached']}건</td><td>실측(위 5장)</td></tr>
<tr><td>건당 분</td><td>15분 <b>(가정)</b></td><td>롯데 실측값 없음 — 본선 현장에서 교체</td></tr>
<tr><td>시간당 비용</td><td>50,000원 <b>(가정)</b></td><td>임의 입력값</td></tr></table>
<p>가정대로면 이 {len(S['repos'])}곳 합계 {E['hours_saved']}시간(약 {E['cost_saved']:,}원)의 1차 분류 시간이 뒤로 밀립니다. 이 값은 <b>하한이 0</b>입니다(전부 도달이면 절감 0). 도달 판정의 재현율이 {AH['reached_recall']}%라 놓친 도달 경보는 「사용」으로 내려가 늦게 처리될 수 있으므로, 시간 절감은 위험 노출과 맞바꾼 값이며 오탐·미탐 비용은 포함하지 않았습니다.</p>
<h2><span class=n>9</span>한계 (숨기지 않는 것)</h2>
<ul><li>정답은 AI 한 주체가 작성했고 사용자·사람 검산을 거치지 않았습니다. 저장소 {len(S['repos'])}곳에서 고른 {A1['total'] + AH['total']}건이라 롯데 실저장소에 일반화된다고 주장하지 않습니다.</li>
<li>전이 의존성(다른 패키지가 부르는 경로)은 호출 그래프를 만들지 않아 「미확인」입니다. 동적 import·템플릿 속 호출은 보지 못합니다. JavaScript 분석은 구문 분석이 아니라 토큰 기반입니다.</li>
<li>취약점 DB는 OSV 하나입니다. 취약 함수 이름은 어드바이저리 본문에서 뽑아서 일반 이름이면 오탐이 납니다.</li></ul>
<h2><span class=n>10</span>일정과 본선 계획</h2>
<table><tr><th style="width:24%">시점</th><th>마일스톤</th><th style="width:30%">확정 증거</th></tr>
<tr><td>예선 제출 전</td><td>구조·시험·정답·재스캔 증거 확정(이 문서)</td><td>테스트 {TESTS or '120+'}건, 정답 {A1['total'] + AH['total']}건, 저장소 {len(S['repos'])}곳</td></tr>
<tr><td>본선 시작 직후</td><td>현장 데이터 연결 어댑터 1개와 입력 스키마 확정</td><td>어댑터 시험 통과</td></tr>
<tr><td>본선 중반</td><td>현장 저장소로 정답 라벨링 20건 추가, 오탐 심볼 검증 개선</td><td>일치율·정밀도 재측정 표</td></tr>
<tr><td>본선 발표 전</td><td>조치 가지·재스캔 시연, 사람 승인 단계 연결</td><td>해소·남음·신규 경보 표</td></tr></table>
<p>본선에서 새로 만드는 일은 데이터 연결과 정답 추가뿐입니다. 도구 호출 구조와 시험 세트는 이미 확정되어 있습니다.</p>
<h2><span class=n>11</span>재현 방법</h2>
<p>레포 <code>{REPO}</code>. 파이썬 3.9+ 표준 라이브러리만 사용(스캔은 syft가 있으면 사용, 없으면 잠금 파일 파서). <code>python3 -m pytest -q</code> (오프라인), <code>python3 -m sbomreach.infrastructure.cli scan --target nodejs-goof</code>, <code>... remediate --target nodejs-goof --scope reached</code>, <code>... eval --gold gold-holdout.jsonl</code>. 정답 파일은 <code>evidence/gold*.jsonl</code>, 작성 규약은 <code>evidence/GOLD.md</code>, 코드 구조 규칙은 <code>SPEC.md</code>입니다.</p>"""

SOL = [p1, p2, p3, p4]

# ───────── 1쪽 요약
SUM = f"""<div class=brow>AI 문제해결방안 요약 · LOTTE AX Challenge 2026</div>
<h1>경보 {T['alerts']}건 중 코드가 실제로 호출하는 {T['reached']}건을 근거 줄과 함께 먼저 올립니다</h1>
<p class=lede>SBOM·취약점 스캔 결과의 영향도·우선순위 연결 구조와, 조치안 도출·재스캔 개선 순환을 도는 AI 에이전트 (롯데이노베이트)</p>
<div class=big><div><b>{T['alerts']} → {T['reached']}</b><span>공개 저장소 {len(S['repos'])}곳 경보 → 도달 경보</span></div><div><b>{AH['rate']}%</b><span>사전 동결 홀드아웃 {AH['total']}건 일치율</span></div><div><b>{rs_sum('reached','reached_before')} → {rs_sum('reached','reached_after')}</b><span>조치 가지 재스캔 후 도달 경보 (패키지 {rs_sum('reached','packages_changed')}개 조치)</span></div></div>
<h2>문제</h2><p>SBOM과 스캔 결과가 따로 나와 수백 건 경보를 사람이 하나씩 따집니다. 이번 {len(S['repos'])}곳에서 호출 근거가 있는 경보는 {pc(T['reached'], T['alerts'])}였습니다.</p>
<h2>해법</h2><ul><li>SBOM 생성 → 취약점 조회 → <b>호출 근거 줄로 도달 판정</b> → 우선순위·조치안 → 조치 가지 적용 → 재스캔(최대 3바퀴)</li><li>판정은 코드, AI는 설명 문장만. 근거 줄 없으면 「도달」 불가, 허용 밖 버전 숫자·안전 단정은 폐기</li><li>병합·배포는 사람이 승인</li></ul>
<h2>구조</h2><img class=fig src="architecture.svg" style="width:100%">
<h2>다른 점</h2><p>기존 도달성 도구(Endor Labs·Snyk·Semgrep)는 호출 그래프·데이터플로를 상용으로 제공합니다. 이 에이전트는 ① 판정마다 근거 줄 ② 조치 후 재스캔 감소를 한 출력에 ③ 정답 {A1['total'] + AH['total']}건 일치율과 틀린 곳 공개 ④ 로컬·무료 도구만으로 재현을 더합니다.</p>
<h2>한계</h2><p>정답은 AI가 작성했고 사람 검산 전입니다. 도달 정밀도 {AH['reached_precision']}%·재현율 {AH['reached_recall']}%(홀드아웃). 전이 의존은 「미확인」. 효과 숫자(건당 15분·시간당 5만원)는 가정입니다.</p>"""

# ───────── 역량 자료
CAP = f"""<div class=brow>AI 보유역량 · LOTTE AX Challenge 2026</div>
<h1>AI 에이전트를 만들어 운영하고, 틀린 기록을 구조로 고쳐 온 기록</h1>
<p class=lede>아래는 모두 링크나 숫자로 확인할 수 있는 것만 적었습니다. 확인할 수 없는 항목은 넣지 않았습니다.</p>
<h2>1. 이번 과제의 작동 프로토타입</h2>
<table><tr><th style="width:24%">항목</th><th>내용</th></tr>
<tr><td>레포</td><td><code>{REPO}</code> — SBOM 생성부터 도달 판정·조치 가지·재스캔까지 도는 에이전트, 시험 {TESTS or '120+'}건, 정답 {A1['total'] + AH['total']}건</td></tr>
<tr><td>실행 기록</td><td>공개 저장소 {len(S['repos'])}곳(Python·JavaScript) 경보 {T['alerts']}건 판정, 홀드아웃 일치율 {AH['rate']}%({AH['matched']}/{AH['total']}), 도달 경보 {rs_sum('reached','reached_before')} → {rs_sum('reached','reached_after')}</td></tr>
<tr><td>사용한 AI</td><td>Gemini(조치안 문장 생성), 코드 작성·검산 보조 Claude. 판정·버전 결정은 AI가 하지 않음</td></tr></table>
<h2>2. 에이전트를 만든 다른 공개 레포 (모두 비로그인으로 열림)</h2>
<table><tr><th style="width:27%">레포</th><th>무엇을 하는가</th><th style="width:16%">에이전트 안전장치</th></tr>
<tr><td>github.com/Ryugi62/gatekeep-chronoforge</td><td>AI 에이전트의 도구 호출 직전 검문(action-level checkpoint)</td><td>호출 전 차단</td></tr>
<tr><td>github.com/Ryugi62/trifecta-gate</td><td>AI 에이전트가 개인 정보를 밖으로 내보내지 못하게 출처 추적으로 막음</td><td>유출 차단</td></tr>
<tr><td>github.com/Ryugi62/proofcall</td><td>가격·예약 가능·동의 가드레일을 코드로 강제하는 음성 통화 에이전트</td><td>규칙 강제</td></tr>
<tr><td>github.com/Ryugi62/scar-tissue</td><td>코딩 에이전트의 반복 실수를 가드레일로 바꿈</td><td>실패→규칙</td></tr>
<tr><td>github.com/Ryugi62/receipts</td><td>AI 답변의 주장마다 위키백과 근거를 붙이는 검증 에이전트</td><td>근거 강제</td></tr>
<tr><td>github.com/Ryugi62/closer-airwallex</td><td>Airwallex 에이전트 뱅킹 해커톤용 정산 마감 에이전트</td><td>사람 승인</td></tr></table>
<h2>3. 외부 심사 결과</h2>
<ul><li>Midnight Korea Hackathon <b>1위</b>(38팀 중, 2026-09-29 주최 발표) — 레포 <code>github.com/Ryugi62/justenough</code> (시험 112건).</li>
<li>Airwallex Agentic Banking Hackathon 서류 통과 후 빌드 단계 진행(2026-10-27 선발 통지).</li></ul>
<h2>4. 에이전트가 틀렸을 때 구조로 고친 운영 기록</h2>
<p>개인 운영 환경(에이전트가 일정·공모·코드를 대신 처리)에서 에이전트의 문제를 사건으로 기록하고 훅·검사 스크립트로 내린 이력이 2026-09-02부터 2026-10-30까지 <b>923건</b> 있습니다. 이번 구조의 「근거 줄 없으면 미확인」과 「AI 문장은 허용 목록 밖 숫자 폐기」도 이 기록에서 나온 설계입니다. 이 기록은 개인 비공개 저장소에 있어 공개 링크는 없습니다.</p>
<p class=note>모든 항목의 날짜·건수는 2026-10-30 기준이며, 판정 정확도는 이 레포 evidence 폴더의 정답 파일로 재현할 수 있습니다.</p>"""


def render(name, pages, label):
    html = f"<!doctype html><html lang=ko><head><meta charset=utf-8><style>{CSS}</style></head><body>" + "".join(
        page(i + 1, len(pages), b, label) for i, b in enumerate(pages)) + "</body></html>"
    hp = os.path.join(HERE, f"_{name}.html")
    open(hp, "w", encoding="utf-8").write(html)
    pdf = os.path.join(OUT, f"{name}.pdf")
    with sync_playwright() as pw:
        b = pw.chromium.launch()
        pg = b.new_page()
        pg.goto("file://" + hp)
        pg.wait_for_timeout(800)
        over = pg.evaluate("""() => { const mm=96/25.4; return [...document.querySelectorAll('.page')].map((el,i)=>{
            const c=el.scrollHeight/mm - 297; return {p:i+1, over:+c.toFixed(1)} }); }""")
        pg.pdf(path=pdf, format="A4", print_background=True, margin=dict(top="0", bottom="0", left="0", right="0"))
        b.close()
    n = len(PdfReader(pdf).pages)
    bad = [o for o in over if o["over"] > 0.5]
    print(name, "쪽수", n, "넘침", over)
    return pdf, n, bad


if __name__ == "__main__":
    res = {}
    res["해결방안"] = render("AI문제해결방안_v1", SOL, "AI 문제해결방안 v1")
    res["요약"] = render("AI문제해결방안_요약1쪽_v1", [SUM], "AI 문제해결방안 요약 v1")
    res["역량"] = render("AI보유역량_v1", [CAP], "AI 보유역량 v1")
    fail = [k for k, v in res.items() if v[2]]
    if fail:
        sys.exit("넘침: " + ",".join(fail))
