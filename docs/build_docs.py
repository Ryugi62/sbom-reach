#!/usr/bin/env python3
"""해결방안·역량 자료 PDF 빌드. 숫자는 evidence/summary.json·rescan에서 읽는다(손으로 치지 않음).
테스트: ①쪽수 ②내부 흔적 0(대괄호 링크·projects/·메인 판단) ③쪽 넘침 0mm ④가정 표기 존재."""
import glob, json, os, re, subprocess, sys
# playwright·pypdf는 PDF를 만들 때(render)만 필요하다. 시험(pytest)은 이 둘 없이 돈다.

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.environ.get("DOCS_OUT") or os.path.join(HERE, "out")
VER = "v1.2"
sys.path.insert(0, ROOT)
from sbomreach.domain.evals import wilson  # noqa: E402
S = json.load(open(os.path.join(ROOT, "evidence/summary.json"), encoding="utf-8"))
T = S["totals"]
A0, A1, AH = S["accuracy"]["v0_dev"], S["accuracy"]["v1_dev"], S["accuracy"]["v1_holdout"]
RS = S["rescan"]
REPO = "https://github.com/Ryugi62/sbom-reach"


def count_tests():
    """실제 pytest 수집 개수. 시험이 이 모듈을 import할 때의 재귀를 막으려고 환경변수로 끊는다."""
    if os.environ.get("SBOMREACH_COUNTING"):
        return 0
    r = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q"], cwd=ROOT, capture_output=True, text=True,
                       env=dict(os.environ, SBOMREACH_COUNTING="1"), timeout=120)
    m = re.search(r"(\d+) tests? collected", r.stdout)
    if not m:
        raise RuntimeError("pytest 수집 개수를 읽지 못함: " + r.stdout[-200:])
    return int(m.group(1))


TESTS = count_tests()


def read_acc_md(path):
    """accuracy-*.md(평가 CLI가 만든 표)에서 일치율·정밀도·재현율·혼동행렬을 읽는다. 손으로 옮기지 않는다."""
    t = open(path, encoding="utf-8").read()
    m = re.search(r"정답 (\d+)건 중 일치 (\d+)건 = \*\*([\d.]+)%\*\*", t)
    q = re.search(r"정밀도 ([\d.]+)% · 재현율 ([\d.]+)%", t)
    rows = {k: [int(x) for x in re.search(r"\| %s \| (\d+) \| (\d+) \| (\d+) \|" % k, t).groups()] for k in ("REACHED", "USED", "UNSEEN")}
    return {"total": int(m[1]), "matched": int(m[2]), "rate": float(m[3]), "reached_precision": float(q[1]),
            "reached_recall": float(q[2]), "rows": rows}


def nontrivial(rows):
    """정답이 도달·사용인 경보(소스에 그 패키지를 쓰는 줄이 있는 것) — 미확인 경보는 맞히기 쉬워 따로 본다."""
    n = sum(sum(rows[k]) for k in ("REACHED", "USED"))
    ok = rows["REACHED"][0] + rows["USED"][1]
    lo, hi = wilson(ok, n)
    return {"n": n, "ok": ok, "rate": round(ok / n * 100, 1), "lo": round(lo * 100), "hi": round(hi * 100)}


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
FZ = read_acc_md(os.path.join(ROOT, "evidence/accuracy-v1a-holdout.md"))     # 홀드아웃 동결 직후 첫 실행
HX = read_acc_md(os.path.join(ROOT, "evidence/accuracy-v1-holdout.md"))      # 판정기 통합 누락을 고친 뒤 같은 정답
assert (HX["matched"], HX["total"]) == (AH["matched"], AH["total"])
NZ, NH = nontrivial(FZ["rows"]), nontrivial(HX["rows"])
WZ, WH = [round(x * 100) for x in wilson(FZ["matched"], FZ["total"])], [round(x * 100) for x in wilson(HX["matched"], HX["total"])]


def trace_counts():
    ok = fb = 0
    why = set()
    for p in glob.glob(os.path.join(ROOT, "evidence/traces/*.jsonl")):
        for l in open(p, encoding="utf-8"):
            d = json.loads(l)
            if d["tool"] == "llm_explain":
                ok += 1
            elif d["tool"] == "fallback" and d.get("stage") == "llm":
                fb += 1
                why.add(d["why"])
    return ok, fb, why


LLM_OK, LLM_FB, LLM_WHY = trace_counts()
assert LLM_WHY == {"HTTPError"}, LLM_WHY    # 429 같은 상태 코드는 trace에 없다 — 문서도 그렇게 쓴다
RS_UNIQ = rs_sum("reached", "alerts_before")  # 재스캔 표의 기준(고유 경보)
SVG_PATH = os.path.join(HERE, "architecture.svg")
SVG_TEXT = " ".join(re.findall(r"<text[^>]*>([^<]*)</text>", open(SVG_PATH, encoding="utf-8").read()))
pc = lambda a, b: f"{a / b * 100:.1f}%"
CSS = """
@font-face{font-family:P;font-weight:400;src:url('_fonts/Pretendard-Regular.ttf')}
@font-face{font-family:P;font-weight:700;src:url('_fonts/Pretendard-Bold.ttf')}
@font-face{font-family:P;font-weight:800;src:url('_fonts/Pretendard-ExtraBold.ttf')}
@page{size:A4;margin:0}*{margin:0;padding:0;box-sizing:border-box}
body{font-family:P,'Apple SD Gothic Neo',sans-serif;font-size:8.6pt;line-height:1.46;color:#191F28}
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
TL = open(os.path.join(ROOT, "evidence/trace-sample.jsonl"), encoding="utf-8").read().strip().split("\n")
TRACE = [l for l in TL if '"reach_judge"' in l][:1] + [l for l in TL if '"tool": "fallback"' in l][:1]
TRACE_TXT = "<br>".join(re.sub(r'"run_id": "[^"]+", ', "", l).replace("<", "&lt;")[:150] for l in TRACE)

RANK = [l for l in open(os.path.join(ROOT, "evidence/runs-v1/nodejs-goof.ranking.md"), encoding="utf-8").read().split("\n") if l.startswith("| ")]
RANK_ROWS = "".join("<tr>" + "".join(f"<td>{c.strip()}</td>" for c in l.strip("|").split("|")) + "</tr>" for l in RANK[1:6])
SIMILAR = """<table><tr><th style="width:23%">서비스</th><th style="width:44%">방식(공개 문서 기준)</th><th>우리가 다른 점</th></tr>
<tr><td>Endor Labs<br><span class=note>endorlabs.com/learn/benchmarking-endor-labs-vs-snyks-github-apps</span></td><td>호출 그래프로 취약 함수가 실제 호출되는지 판정, EPSS 결합(상용 SaaS, 수치는 자사 벤치마크)</td><td rowspan=5>① 판정마다 <b>근거 줄(파일:줄)</b>을 붙이고 근거가 없으면 「도달」이라 하지 못하게 코드로 막음 ② 조치 후 <b>재스캔 감소를 같은 출력에</b> 냄 ③ 정답 103건(AI가 작성)과의 <b>일치율·틀린 곳을 공개</b> ④ 로컬·무료 도구만으로 재현</td></tr>
<tr><td>Snyk Reachability<br><span class=note>docs.snyk.io/manage-risk/prioritize-issues-for-fixing/reachability</span></td><td>애플리케이션과 의존성의 호출 그래프를 분석(문서상 CLI·IDE 연동에서는 미지원)</td></tr>
<tr><td>Semgrep Supply Chain<br><span class=note>semgrep.dev/docs/faq/comparisons/endor-labs</span></td><td>직접 의존성에 대한 데이터플로 도달성(벤더 자체 주장)</td></tr>
<tr><td>래브라도 SCM<br><span class=note>m.boannews.com/html/detail.html?idx=132104</span></td><td>국내 SBOM 교환·취약점 이슈 파악 플랫폼(공개 기사에서 도달성 판정은 확인하지 못함)</td></tr>
<tr><td>롯데이노베이트 자사 SBOM·취약점 제품</td><td>2026-11-02 검색엔진 질의 7회(제품 소개·매뉴얼, 특허, 채용공고, 뉴스, 정부과제·논문 5유형)에서 <b>찾지 못함</b>. 특허청 KIPRIS·전자공시·채용 사이트 원문은 직접 열람하지 못했으므로 「없다」고 단정하지 않음</td></tr></table>"""

# ───────── 해결방안 4쪽
p1 = f"""<div class=brow>AI 문제해결방안 · LOTTE AX Challenge 2026 · 롯데이노베이트</div>
<h1>SBOM·취약점 스캔 결과의 영향도·우선순위 연결 구조 설계,<br>그리고 조치안 도출 및 개선을 도는 AI 에이전트</h1>
<p class=lede>과제 「SBOM 생성과 취약점 스캔 결과의 영향도·우선순위 연결 구조 설계」「AI 에이전트 기반 조치안 도출 및 개선」에 대한 작동 프로토타입입니다 — 공개 레포 <code>{REPO}</code>(비로그인 열림, 시험 {TESTS}건)에서 경보 {T['alerts']}건 중 코드가 실제로 호출하는 {T['reached']}건({pc(T['reached'], T['alerts'])})을 근거 줄과 함께 먼저 올리고, 조치 후 재스캔으로 줄었는지 숫자로 확인합니다. 도달 판정과 고칠 버전 선택은 코드가 하고, AI는 설명 문장만 씁니다.</p>
<div class=big><div><b>{T['alerts']} → {T['reached']}</b><span>공개 저장소 {len(S['repos'])}곳(Python·JavaScript)의 경보 수 → 취약 함수 호출 근거가 있는 도달 경보 수</span></div>
<div><b>{FZ['rate']}%</b><span>정답 동결 직후 홀드아웃 {FZ['total']}건 일치율({FZ['matched']}/{FZ['total']}, 95% 구간 {WZ[0]}~{WZ[1]}%). 판정기 수정 뒤 같은 정답 {AH['rate']}%는 사후 수정이라 독립 검증이 아님</span></div>
<div><b>{rs_sum('reached','reached_before')} → {rs_sum('reached','reached_after')}</b><span>조치 적용 가지에서 재스캔한 도달 경보. 패키지 {rs_sum('reached','packages_changed')}개만 올림(전부 올리면 {rs_sum('all','packages_changed')}개)</span></div></div>
<h2><span class=n>1</span>문제와 해법</h2>
<p><b>문제.</b> SBOM(부품 목록)과 취약점 스캔은 따로 나오고, 보안 운영 담당은 수백 건 경보를 하나씩 열어 「우리 코드가 이 함수를 부르나」를 사람이 따집니다. 이 저장소 {len(S['repos'])}곳 합계 {T['alerts']}건 중 {pc(T['unseen'], T['alerts'])}는 소스에 그 패키지를 쓰는 줄이 없었고, 호출 근거가 있는 것은 {pc(T['reached'], T['alerts'])}였습니다.</p>
<p><b>해법.</b> 에이전트가 ① 저장소에서 SBOM 생성 → ② 알려진 취약점 조회 → ③ 취약 함수 호출 여부를 <b>근거 줄</b>로 판정(도달·사용·미확인) → ④ 심각도×도달 가중으로 우선순위와 조치안을 <b>코드가</b> 정하고(패키지별 <b>고칠 버전</b> = OSV가 알려 준 고침 버전 중 최저), AI는 그 결정을 두 문장 이내 <b>설명 문장</b>으로만 풀어 씀 → ⑤ 조치를 별도 git 가지에 적용 → ⑥ 같은 절차로 재스캔해 경보 감소를 측정하고, 도달 경보가 남으면 한 바퀴 더 돕니다(최대 3바퀴). 병합·배포는 하지 않고 사람이 승인합니다.</p>
<p><b>코드와 AI의 역할.</b> 도달 판정, 우선순위, <b>고칠 버전 선택</b>은 코드가 합니다. AI(Gemini)는 이미 정해진 결정을 두 문장 이내 <b>설명 문장</b>으로 쓸 뿐이고, 버전 숫자 허용 목록(G2)과 판정 뒤집기 금지(G3)를 어기면 문장을 버리고 템플릿 문장을 씁니다.</p>
<h2><span class=n>2</span>같은 문제를 푸는 기존 서비스와 다른 점</h2>
{SIMILAR}
<p class=note>위 서비스의 수치는 각 벤더의 공개 문서·자사 벤치마크이며 독립 검증값이 아닙니다. 우리 수치는 아래 5·6장의 공개 저장소와 정답 파일로 재현할 수 있습니다.</p>
<h2><span class=n>3</span>과제 문구와 구조도의 대응</h2>
<table><tr><th style="width:42%">과제 문구</th><th>구조도(그림 1) 노드</th><th>산출물</th></tr>
<tr><td>SBOM 생성과 취약점 스캔 결과의 영향도·우선순위 <b>연결</b> 구조 설계</td><td>1 SBOM → 2 조회 → <b>3 도달 판정</b> → 4 우선순위</td><td>경보별 판정·근거 줄·점수</td></tr>
<tr><td>AI 에이전트 기반 <b>조치안 도출</b></td><td>4 조치 계획 → 5 조치안 문장</td><td>패키지별 현재→목표 버전·설명</td></tr>
<tr><td>… 및 <b>개선</b></td><td>6 조치 가지 → 7 재스캔 → (순환)</td><td>해소·남음·신규 경보 수</td></tr></table>"""

p2 = f"""<div class=brow>AI 문제해결방안 · 구조와 평가</div>
<img class=fig src="architecture.svg" style="width:74%;display:block;margin:0 auto">
<p class=cap>그림 1. 에이전트 구조도 — 도구 호출 순서, 사람/에이전트 경계(8), 평가(Evals), 가드레일, 실패 처리</p>
<h2><span class=n>4</span>가드레일과 평가</h2>
<table><tr><th style="width:11%">규칙</th><th style="width:52%">내용(코드로 집행)</th><th>시험</th></tr>
<tr><td>G1</td><td>근거 줄이 없는 「도달」은 판정 객체를 만들 수 없다</td><td>test_reached_requires_evidence</td></tr>
<tr><td>G2·G3</td><td>AI 문장의 버전 숫자는 허용 목록(현재·목표)만, 「안전합니다」류 단정과 판정 뒤집기 폐기 후 템플릿 문장</td><td>test_domain_guardrails</td></tr>
<tr><td>G4</td><td>허용된 명령만 실행(syft scan, npm lock 전용, git). 대상 코드 실행·설치 차단</td><td>test_g4_readonly_commands</td></tr>
<tr><td>G5·G6</td><td>AI 입력의 키·이메일 마스킹 / 조회가 덜 끝나면 「경보 0 = 깨끗함」 금지</td><td>test_g5, test_g6</td></tr></table>
<p><b>평가(Evals).</b> 단위 시험 {TESTS}건(pytest, 오프라인)과 정답 파일 두 벌을 씁니다. 정답은 <b>사람이 아니라 AI(Claude)가 소스 줄을 직접 열어 작성</b>했고 사람 검산 전입니다. 개발셋 {A1['total']}건은 판정기 수정에 쓰여 오염되었으므로 수정 전 {A0['rate']}% → 수정 후 {A1['rate']}%로만 보고합니다. 홀드아웃 {AH['total']}건은 개발셋 수정이 끝난 뒤 정답을 동결했고(커밋 기록), 동결 직후 처음 돌린 값은 <b>{FZ['rate']}%</b>입니다. 그 결과를 본 뒤 JS 분석 결과를 합치지 않던 연결 누락 4줄을 고쳐 같은 정답에서 <b>{AH['rate']}%</b>가 되었으나, 이는 <b>사후 수정</b>이라 독립 검증이 아닙니다. 두 값 모두 표본 {AH['total']}건이라 95% 구간(Wilson)은 {WZ[0]}~{WZ[1]}%, {WH[0]}~{WH[1]}%로 넓습니다.</p>
<table><tr><th>정답 세트</th><th class=r>건수</th><th class=r>3분류 일치</th><th class=r>도달 정밀도</th><th class=r>도달 재현율</th></tr>
<tr><td>개발셋, 수정 전</td><td class=r>{A0['total']}</td><td class=r>{A0['matched']} ({A0['rate']}%)</td><td class=r>{A0['reached_precision']}%</td><td class=r>{A0['reached_recall']}%</td></tr>
<tr><td>개발셋, 수정 후(오염)</td><td class=r>{A1['total']}</td><td class=r>{A1['matched']} ({A1['rate']}%)</td><td class=r>{A1['reached_precision']}%</td><td class=r>{A1['reached_recall']}%</td></tr>
<tr><td>홀드아웃, 동결 직후 첫 실행</td><td class=r>{FZ['total']}</td><td class=r><b>{FZ['matched']} ({FZ['rate']}%)</b></td><td class=r>{FZ['reached_precision']}%</td><td class=r>{FZ['reached_recall']}%</td></tr>
<tr><td>홀드아웃, 수정 뒤(사후 수정)</td><td class=r>{AH['total']}</td><td class=r>{AH['matched']} ({AH['rate']}%)</td><td class=r>{AH['reached_precision']}%</td><td class=r>{AH['reached_recall']}%</td></tr></table>
<p class=note>미확인(소스에 그 패키지를 쓰는 줄이 없음)은 홀드아웃 {FZ['rows']['UNSEEN'][2]}건 모두 맞혀 일치율을 올리므로, 정답이 도달·사용인 <b>비자명 {NH['n']}건</b>만 따로 보면 동결 직후 {NZ['ok']}/{NZ['n']}({NZ['rate']}%, 95% 구간 {NZ['lo']}~{NZ['hi']}%), 수정 뒤 {NH['ok']}/{NH['n']}(<b>{NH['rate']}%</b>, 95% 구간 {NH['lo']}~{NH['hi']}%)입니다. 합격선으로 둔 80%(SPEC S2)는 동결 직후 값으로는 넘지 못했습니다.</p>
<p><b>틀린 곳.</b> 홀드아웃에서 도달 정밀도는 동결 직후 {FZ['reached_precision']}%, 수정 뒤 {AH['reached_precision']}%에 그칩니다. 어드바이저리 본문에서 뽑은 함수 이름이 일반 이름(decode 등)이면 호출만으로 「도달」이 되는 오탐이 있고, 객체 인스턴스 메서드·설정 파일 로딩은 놓치거나 「약한 근거」 표시로 내립니다(약한 근거 {T['reached_weak']}건). 본선에서는 심볼 검증을 가장 먼저 개선합니다.</p>
<p class=cap>trace 샘플(도구 호출 1건 = 1줄, 부록 파일 trace-sample.jsonl) — 도달 판정 1줄, AI 호출 실패 1줄</p>
<div class=box style="font-family:Menlo,monospace;font-size:6.6pt;line-height:1.35;word-break:break-all">{TRACE_TXT}</div>
<p><b>실패 처리.</b> 취약점 조회가 실패하면 재시도 2회 뒤 그 부품을 「스캔 미완」으로 표시하고 경보 0을 깨끗하다고 말하지 않습니다. syft가 없으면 잠금 파일 파서로, AI 호출이 실패하면 템플릿 문장으로 계속 진행합니다. 이번 실행의 trace 전체(재스캔 포함)에서 AI 문장 {LLM_OK}건이 채택되었고 {LLM_FB}건은 AI 호출이 <code>HTTPError</code>로 실패해 템플릿 문장이 되었습니다. trace에는 예외 종류만 남기고 상태 코드는 기록하지 않아 실패 원인은 확정하지 못했습니다. 따라서 조치안 문장은 대부분 템플릿이고 조치안(버전)은 AI와 무관합니다.</p>"""

p3 = f"""<div class=brow>AI 문제해결방안 · 실행 증거</div>
<h2 style="margin-top:0"><span class=n>5</span>실행 결과 — 공개 저장소 {len(S['repos'])}곳, 언어 {len(S['languages'])}개</h2>
<table><tr><th>저장소(고정 커밋)</th><th>언어</th><th class=r>부품</th><th class=r>경보</th><th class=r>도달</th><th class=r>사용</th><th class=r>미확인</th><th class=r>소요</th></tr>{repo_rows()}</table>
<p class=note>저장소: """ + " · ".join(f"{r['url'].replace('https://','')} @{r['commit']}" for r in S['repos']) + f""". 모두 보안 교육용으로 일부러 취약하게 만든 공개 저장소라 실제 운영 저장소와 경보 분포가 다릅니다. 도달·사용·미확인 정의는 SPEC.md에 있고 「미확인」은 안전이 아니라 소스에 쓰는 줄이 없다는 뜻입니다. 경보 수 {T['alerts']}는 (부품 버전×어드바이저리) 행 수이고, 아래 6장 재스캔 표의 기준 {RS_UNIQ}는 같은 패키지·어드바이저리의 버전 중복을 합친 고유 경보 수라 합계가 다릅니다.</p>
<h2><span class=n>6</span>개선 순환 — 조치 적용 가지에서 재스캔</h2>
<p>조치안은 패키지별로 그 버전의 알려진 경보를 모두 덜어내는 가장 낮은 고쳐진 버전입니다. 사본 저장소에 <code>fix/sbomreach</code> 가지를 만들어 requirements·package.json을 고치고(npm은 잠금 파일만 재생성, 스크립트 실행 없음) 같은 절차로 다시 스캔합니다. 「도달만 조치」는 도달 경보가 있는 패키지만, 「전부 조치」는 경보가 있는 모든 패키지를 올립니다.</p>
<table><tr><th rowspan=2>저장소</th><th colspan=3>도달만 조치</th><th colspan=2>전부 조치</th></tr><tr><th class=r>도달 경보</th><th class=r>올린 패키지</th><th class=r>경보(고유)</th><th class=r>올린 패키지</th><th class=r>경보(고유)</th></tr>{rescan_rows()}</table>
<ul><li>도달 경보는 {rs_sum('reached','reached_before')}건에서 {rs_sum('reached','reached_after')}건으로 줄었고, 올린 패키지는 {rs_sum('reached','packages_changed')}개로 「전부 조치」 {rs_sum('all','packages_changed')}개의 {pc(rs_sum('reached','packages_changed'), rs_sum('all','packages_changed'))}입니다. 남은 1건은 nodejs-goof의 중첩 복사본(ms 0.6.2)으로, 이름 기준 판정이 저장소가 실제로 쓰는 복사본과 다른 복사본에 적용된 오탐 가능성이 있습니다.</li>
<li>조치 뒤 새로 생긴 경보도 따로 셉니다(도달만 조치 기준 합계 {sum(v['new'] for k, v in RS.items() if k.endswith('.reached'))}건). 올린 버전 {MT}개 중 주 버전이 바뀐 것은 {MJ}개라 <b>호환성 검토와 사람 승인이 필요</b>합니다. 에이전트는 병합하지 않습니다.</li>
<li>고쳐진 버전이 공개되지 않은 경보는 목표 버전을 비우고 「대체 패키지·호출 우회 검토」로 표시합니다.</li></ul>
<h2><span class=n>7</span>입력→출력 한 건 (현업 적용 예시)</h2>
<table><tr><th style="width:26%">입력</th><th>출력(경보 1건)</th></tr>
<tr><td>저장소 경로 1개<br><span class=note>또는 CycloneDX SBOM 파일</span></td><td>순위 2 · adm-zip 0.4.7 · GHSA-j5f4-cc29-5x44 · 심각도 HIGH · <b>판정 도달</b> · 근거 <code>routes/index.js:270</code> (<code>zip.extractAllTo(...)</code>) · 조치 0.4.7 → 0.6.1 · 검증: 고쳐진 버전 0.6.1이 가지의 잠금 파일에 반영되어 재스캔에서 해당 경보 소멸</td></tr></table>
<table style="font-size:7.3pt"><tr><th>순위</th><th>패키지</th><th>버전</th><th>경보</th><th>심각도</th><th>판정</th><th>근거 줄</th></tr>{RANK_ROWS}</table>
<p class=cap>그림 2. 사용자가 받는 순위 보고서 화면 — nodejs-goof 실행 결과의 상위 5건(레포 evidence/runs-v1/nodejs-goof.ranking.md 그대로, 도달 판정마다 파일:줄)</p>
<p><b>본선 현장 데이터 연결 칸.</b></p>
<table><tr><th style="width:22%">칸</th><th>예선에서 확정한 것</th><th>본선에서 바꾸는 것</th></tr>
<tr><td>입력 스키마</td><td>저장소 디렉터리 / CycloneDX JSON</td><td>계열사 저장소·사내 SBOM 파일 경로</td></tr>
<tr><td>취약점 소스</td><td>OSV 공개 DB(캐시)</td><td>사내 미러·벤더 DB 어댑터 1개</td></tr>
<tr><td>권한</td><td>읽기 전용, 대상 코드 실행 금지(G4)</td><td>읽기 전용 토큰</td></tr>
<tr><td>사람 승인</td><td>조치 가지 검토·병합은 사람</td><td>사내 승인 절차에 연결</td></tr></table>"""

p4 = f"""<div class=brow>AI 문제해결방안 · 효과, 한계, 일정</div>
<h2 style="margin-top:0"><span class=n>8</span>기대 효과 — 모든 입력이 가정입니다</h2>
<table><tr><th>식</th><th>기호</th><th>값</th><th>출처</th></tr>
<tr><td rowspan=4>1차 분류 순서 조정 시간 = (경보 − 도달) × 건당 분</td><td>경보</td><td>{T['alerts']}건</td><td>실측(위 5장)</td></tr>
<tr><td>도달</td><td>{T['reached']}건</td><td>실측(위 5장)</td></tr>
<tr><td>건당 분</td><td>15분 <b>(가정)</b></td><td>롯데 실측값 없음 — 본선 현장에서 교체</td></tr>
<tr><td>시간당 비용</td><td>50,000원 <b>(가정)</b></td><td>임의 입력값</td></tr>
<tr><td>놓친 도달 비용 = 놓친 도달 수 × 건당 처리 지연·사고 비용</td><td>놓친 도달 수</td><td>홀드아웃 정답 도달 {HX['rows']['REACHED'][0] + HX['rows']['REACHED'][1] + HX['rows']['REACHED'][2]}건 중 {HX['rows']['REACHED'][1]}건을 「사용」으로 내림</td><td>건당 비용은 <b>미추정</b>(근거 없는 가정값을 만들지 않음)</td></tr></table>
<p>가정대로면 이 {len(S['repos'])}곳 합계 {E['hours_saved']}시간(약 {E['cost_saved']:,}원)어치의 경보를 1차 분류 순서에서 뒤로 돌릴 수 있습니다. 이는 사람이 줄이는 시간이 아니라 <b>처리 순서를 바꾸는 값</b>이며 하한이 0입니다(전부 도달이면 0). 도달 재현율이 동결 직후 {FZ['reached_recall']}%·수정 뒤 {AH['reached_recall']}%라 놓친 도달 경보는 「사용」으로 내려가 늦게 처리될 수 있습니다. 이 놓친 도달 비용과 오탐 확인 시간은 위 값에서 빼지 않았고 추정하지도 않았으므로, 위 시간을 순이익으로 읽으면 안 됩니다.</p>
<h2><span class=n>9</span>한계 (숨기지 않는 것)</h2>
<ul><li>정답은 AI 한 주체가 작성했고 사람 검산을 거치지 않았습니다. 저장소 {len(S['repos'])}곳에서 고른 {A1['total'] + AH['total']}건이라 실제 운영 저장소에 일반화된다고 주장하지 않습니다. 홀드아웃의 {FZ['rate']}→{AH['rate']}%는 사후 수정을 포함하고 95% 구간이 {WZ[0]}~{WH[1]}%에 걸칩니다.</li>
<li>대상 저장소 {len(S['repos'])}곳은 모두 보안 교육용으로 일부러 취약하게 만든 공개 저장소입니다. 실제 서비스 코드는 호출 패턴·의존 구조가 달라 도달 비율이 다를 수 있습니다.</li>
<li><b>Java(Maven·Gradle)는 미지원</b>입니다. SBOM 생성과 취약점 조회는 언어와 무관하지만 호출 근거를 찾는 소스 분석이 Python·JavaScript뿐이라 Java 저장소의 경보는 모두 「미확인」으로 남습니다. 본선 범위에서 Java 어댑터를 추가합니다(예선 시점 미구현).</li>
<li>전이 의존성(다른 패키지가 부르는 경로)은 호출 그래프를 만들지 않아 「미확인」입니다. 동적 import·템플릿 속 호출은 보지 못합니다. JavaScript 분석은 구문 분석이 아니라 토큰 기반입니다.</li>
<li>취약점 DB는 OSV 하나입니다. 취약 함수 이름은 어드바이저리 본문에서 뽑아서 일반 이름이면 오탐이 납니다.</li></ul>
<h2><span class=n>10</span>일정·자원·목표치</h2>
<table><tr><th style="width:25%">날짜</th><th>마일스톤</th><th style="width:30%">확정 증거</th></tr>
<tr><td>2026-11-03 (예선 제출 내부 마감, 공고 마감 2026-11-04 23:59)</td><td>구조·시험·정답·재스캔 증거 확정(이 문서)</td><td>시험 {TESTS}건(pytest), 정답 {A1['total'] + AH['total']}건, 저장소 {len(S['repos'])}곳</td></tr>
<tr><td>2026-11-24 ~ 11-25 (본선, 공고 원문 1박2일)</td><td>첫날 현장 데이터 연결 어댑터 1개와 입력 스키마 확정 → 현장 저장소로 정답 라벨 20건 추가, Java(Maven·Gradle) 소스 분석 어댑터 추가(예선 시점 미구현), 오탐 심볼 검증 개선</td><td>어댑터 시험 통과, 일치율·정밀도 재측정 표</td></tr>
<tr><td>2026-11-25 (본선 발표 전)</td><td>조치 가지·재스캔 시연, 사람 승인 단계 연결</td><td>해소·남음·신규 경보 표</td></tr>
<tr><td>합격 발표 11월 둘째 주 이후(공고)</td><td>본선 진출 시에만 위 두 줄 수행</td><td>—</td></tr></table>
<p><b>투입 자원</b>: 1인, 로컬 머신, 무료 도구만(OSV 공개 DB·syft·git), 대상 코드는 읽기만. <b>목표치 3개</b>: ① 3분류 일치율 ≥80%(SPEC S2 — 동결 직후 값은 {FZ['rate']}%로 미달, 본선 추가 라벨 20건 포함 재측정) ② 현장 저장소 정답 라벨 추가 20건 ③ 조치 가지 재스캔 후 도달 경보 0(예선 결과 {rs_sum('reached','reached_after')}건 남음). 본선에서 새로 만드는 일은 데이터 연결, Java 어댑터, 정답 추가입니다. 도구 호출 구조와 시험 세트는 이미 확정되어 있습니다.</p>
<h2><span class=n>11</span>재현 방법</h2>
<p>레포 <code>{REPO}</code> (공개, 로그인 없이 열림). <b>실행은 표준 라이브러리만</b>(파이썬 3.9+, 스캔은 syft가 있으면 사용·없으면 잠금 파일 파서), <b>시험은 pytest</b>입니다. 새 클론에서 순서대로:</p>
<ul><li><code>python3 -m pytest -q</code> — 시험 {TESTS}건, 오프라인, 1초 안팎.</li>
<li><code>python3 scripts/clone_targets.py</code> — <code>evidence/targets.json</code>(저장소 루트 기준 상대경로·고정 커밋)의 4저장소를 <code>untrusted/</code> 아래에 받음(받기만 하고 코드는 실행하지 않음).</li>
<li><code>mkdir -p data &amp;&amp; tar xzf evidence/osv-snapshot-2026-10-30.tar.gz -C data</code> — OSV 응답 스냅샷을 <code>data/osv-cache/</code>로 풀어 같은 날 조회 결과를 재사용(없는 부품만 새로 조회).</li>
<li><code>python3 -m sbomreach.infrastructure.cli scan --target nodejs-goof</code> → <code>... remediate --target nodejs-goof --scope reached</code> → <code>... eval --gold gold-holdout.jsonl</code> (대상은 4저장소 이름 모두 가능).</li></ul>
<p class=note>syft 없이 새 클론에서 nodejs-goof를 돌리면 잠금 파일 파서로 대체되어 부품·경보 수가 다릅니다(경보 235 → 315건 실측). 도달 16건은 같았습니다. 위 5장 수치는 syft 사용 실행 기준입니다.</p>
<p>정답 파일은 <code>evidence/gold*.jsonl</code>, 작성 규약은 <code>evidence/GOLD.md</code>, 코드 구조 규칙은 <code>SPEC.md</code>입니다.</p>"""

SOL = [p1, p2, p3, p4]

# ───────── 1쪽 요약
SUM = f"""<div class=brow>AI 문제해결방안 요약 · LOTTE AX Challenge 2026</div>
<h1>경보 {T['alerts']}건 중 코드가 실제로 호출하는 {T['reached']}건을 근거 줄과 함께 먼저 올립니다</h1>
<p class=lede>SBOM·취약점 스캔 결과의 영향도·우선순위 연결 구조와, 조치안 도출 및 개선(재스캔 순환)을 도는 AI 에이전트 (롯데이노베이트)</p>
<div class=big><div><b>{T['alerts']} → {T['reached']}</b><span>공개 저장소 {len(S['repos'])}곳 경보 → 도달 경보</span></div><div><b>{FZ['rate']}%</b><span>정답 동결 직후 홀드아웃 {AH['total']}건 일치율(수정 뒤 {AH['rate']}%는 사후 수정)</span></div><div><b>{rs_sum('reached','reached_before')} → {rs_sum('reached','reached_after')}</b><span>조치 가지 재스캔 후 도달 경보 (패키지 {rs_sum('reached','packages_changed')}개 조치)</span></div></div>
<h2>문제</h2><p>SBOM과 스캔 결과가 따로 나와 수백 건 경보를 사람이 하나씩 따집니다. 이번 {len(S['repos'])}곳에서 호출 근거가 있는 경보는 {pc(T['reached'], T['alerts'])}였습니다.</p>
<h2>해법</h2><ul><li>SBOM 생성 → 취약점 조회 → <b>호출 근거 줄로 도달 판정</b> → 우선순위·조치안 → 조치 가지 적용 → 재스캔(최대 3바퀴)</li><li>판정과 고칠 버전 선택은 코드, AI는 설명 문장만. 근거 줄 없으면 「도달」 불가, 허용 밖 버전 숫자·안전 단정은 폐기</li><li>병합·배포는 사람이 승인</li></ul>
<h2>구조</h2><img class=fig src="architecture.svg" style="width:100%">
<h2>다른 점</h2><p>기존 도달성 도구(Endor Labs·Snyk·Semgrep)는 호출 그래프·데이터플로를 상용으로 제공합니다. 이 에이전트는 ① 판정마다 근거 줄 ② 조치 후 재스캔 감소를 한 출력에 ③ 정답 {A1['total'] + AH['total']}건 일치율과 틀린 곳 공개 ④ 로컬·무료 도구만으로 재현을 더합니다. 정답은 AI가 작성했습니다.</p>
<h2>한계</h2><p>정답은 AI가 작성했고 사람 검산 전입니다. 홀드아웃 비자명 {NH['n']}건 일치 {NH['rate']}%(95% 구간 {NH['lo']}~{NH['hi']}%, Wilson), 도달 정밀도 {AH['reached_precision']}%·재현율 {AH['reached_recall']}%. 대상은 교육용 취약 저장소 {len(S['repos'])}곳, Java 미지원(본선 범위). 전이 의존은 「미확인」. 효과 숫자(건당 15분·시간당 5만원)는 가정이며 시간을 줄이는 값이 아니라 1차 분류 순서 조정 값입니다.</p>"""

# ───────── 역량 자료
CAP = f"""<div class=brow>AI 보유역량 · LOTTE AX Challenge 2026</div>
<h1>AI 에이전트를 만들어 운영하고, 틀린 기록을 구조로 고쳐 온 기록</h1>
<p class=lede>1~3항은 공개 링크나 숫자로 확인할 수 있습니다. 4항의 923건만 <b>비공개·건수만</b> 적은 예외이며 외부에서 검증할 수 없으므로 평가에 넣지 않으셔도 됩니다.</p>
<h2>1. 이번 과제의 작동 프로토타입</h2>
<table><tr><th style="width:24%">항목</th><th>내용</th></tr>
<tr><td>레포</td><td><code>{REPO}</code> — SBOM 생성부터 도달 판정·조치 가지·재스캔까지 도는 에이전트, 시험 {TESTS}건, 정답 {A1['total'] + AH['total']}건</td></tr>
<tr><td>실행 기록</td><td>공개 저장소 {len(S['repos'])}곳(Python·JavaScript) 경보 {T['alerts']}건 판정, 홀드아웃 일치율 동결 직후 {FZ['rate']}%({FZ['matched']}/{FZ['total']}), 판정기 수정 뒤 {AH['rate']}%(사후 수정), 도달 경보 {rs_sum('reached','reached_before')} → {rs_sum('reached','reached_after')}</td></tr>
<tr><td>사용한 AI</td><td>Gemini(조치안 설명 문장), 코드 작성·정답 작성 Claude. 판정·고칠 버전 결정은 코드가 하고 AI는 설명 문장만 씀</td></tr></table>
<h2>2. 에이전트를 만든 다른 공개 레포 (모두 비로그인으로 열림)</h2>
<table><tr><th style="width:27%">레포</th><th>무엇을 하는가</th><th style="width:16%">에이전트 안전장치</th></tr>
<tr><td>github.com/Ryugi62/gatekeep-chronoforge</td><td>AI 에이전트의 도구 호출 직전 검문(action-level checkpoint)</td><td>호출 전 차단</td></tr>
<tr><td>github.com/Ryugi62/trifecta-gate</td><td>AI 에이전트가 개인 정보를 밖으로 내보내지 못하게 출처 추적으로 막음</td><td>유출 차단</td></tr>
<tr><td>github.com/Ryugi62/proofcall</td><td>가격·예약 가능·동의 가드레일을 코드로 강제하는 음성 통화 에이전트</td><td>규칙 강제</td></tr>
<tr><td>github.com/Ryugi62/scar-tissue</td><td>코딩 에이전트의 반복 실수를 가드레일로 바꿈</td><td>실패→규칙</td></tr>
<tr><td>github.com/Ryugi62/receipts</td><td>AI 답변의 주장마다 위키백과 근거를 붙이는 검증 에이전트</td><td>근거 강제</td></tr>
<tr><td>github.com/Ryugi62/closer-airwallex</td><td>Airwallex 에이전트 뱅킹 해커톤용 정산 마감 에이전트</td><td>사람 승인</td></tr></table>
<h2>2-1. 운영 중인 공개 URL (2026-11-02 비로그인 요청 HTTP 200 실측)</h2>
<table><tr><th style="width:42%">URL</th><th>사실 한 줄</th></tr>
<tr><td><code>ryugi62.github.io/trifecta-gate/</code></td><td>AI 에이전트 도구 목록을 붙여 넣으면 유출 삼각형을 검사하는 데모(입력칸 있음), 마지막 갱신 2026-10-06, 위 trifecta-gate 레포의 공개 페이지</td></tr>
<tr><td><code>ryugi62.github.io/justenough/</code></td><td>Midnight Korea Hackathon 1위 작품 데모 페이지, 마지막 갱신 2026-09-30</td></tr></table>
<h2>3. 외부 심사 결과</h2>
<ul><li>Midnight Korea Hackathon <b>1위</b>(38팀 중, 2026-09-29 주최 발표) — 레포 <code>github.com/Ryugi62/justenough</code> (시험 112건).</li>
<li>Airwallex Agentic Banking Hackathon 서류 통과 후 빌드 단계 진행(2026-10-27 선발 통지).</li></ul>
<h2>4. 에이전트가 틀렸을 때 구조로 고친 운영 기록</h2>
<p>개인 운영 환경(에이전트가 일정·공모·코드를 대신 처리)에서 에이전트의 문제를 사건으로 기록하고 훅·검사 스크립트로 내린 이력이 2026-09-02부터 2026-10-30까지 <b>923건</b> 있습니다. 이번 구조의 「근거 줄 없으면 미확인」과 「AI 문장은 허용 목록 밖 숫자 폐기」도 이 기록에서 나온 설계입니다. 이 기록은 개인 비공개 저장소에 있어 <b>공개 링크가 없고 건수만 적었습니다</b>.</p>
<p class=note>모든 항목의 날짜·건수는 2026-10-30 기준(2-1항 URL만 2026-11-02)이며, 판정 정확도는 이 레포 evidence 폴더의 정답 파일로 재현할 수 있습니다.</p>"""


def render(name, pages, label):
    html = f"<!doctype html><html lang=ko><head><meta charset=utf-8><style>{CSS}</style></head><body>" + "".join(
        page(i + 1, len(pages), b, label) for i, b in enumerate(pages)) + "</body></html>"
    hp = os.path.join(HERE, f"_{name}.html")
    open(hp, "w", encoding="utf-8").write(html)
    os.makedirs(OUT, exist_ok=True)
    pdf = os.path.join(OUT, f"{name}.pdf")
    from playwright.sync_api import sync_playwright
    from pypdf import PdfReader
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
    res["해결방안"] = render(f"AI문제해결방안_{VER}", SOL, f"AI 문제해결방안 {VER}")
    res["요약"] = render(f"AI문제해결방안_요약1쪽_{VER}", [SUM], f"AI 문제해결방안 요약 {VER}")
    res["역량"] = render(f"AI보유역량_{VER}", [CAP], f"AI 보유역량 {VER}")
    fail = [k for k, v in res.items() if v[2]]
    if fail:
        sys.exit("넘침: " + ",".join(fail))
