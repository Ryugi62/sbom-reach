#!/usr/bin/env python3
"""해결방안·역량 자료 PDF 빌드. 숫자는 evidence/summary.json·rescan에서 읽는다(손으로 치지 않음).
테스트: ①쪽수 ②내부 흔적 0(대괄호 링크·projects/·메인 판단) ③쪽 넘침 0mm ④가정 표기 존재."""
import glob, json, os, re, subprocess, sys
# playwright·pypdf는 PDF를 만들 때(render)만 필요하다. 시험(pytest)은 이 둘 없이 돈다.

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.environ.get("DOCS_OUT") or os.path.join(HERE, "out")
VER = "v1.3"
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

RANK = [l for l in open(os.path.join(ROOT, "evidence/runs/nodejs-goof.ranking.md"), encoding="utf-8").read().split("\n") if l.startswith("| ")]
RANK_ROWS = "".join("<tr>" + "".join(f"<td>{c.strip()}</td>" for c in l.strip("|").split("|")) + "</tr>" for l in RANK[1:6])

# ───────── v1.3 데이터 (모두 evidence 파일에서 읽는다)
from sbomreach.application.v13_summary import llm_stats, reduction  # noqa: E402
from sbomreach.domain.evals import cohen_kappa, precision_by_flag  # noqa: E402

EVD = os.path.join(ROOT, "evidence")
rows_of = lambda p: [json.loads(x) for x in open(p, encoding="utf-8") if x.strip()]
JT = json.load(open(os.path.join(EVD, "targets-java.json"), encoding="utf-8"))
PYJS = [r["name"] for r in S["repos"]]
JAVA = [t["name"] for t in JT]
RUNS = {n: json.load(open(os.path.join(EVD, "runs", f"{n}.json"), encoding="utf-8")) for n in PYJS + JAVA}
GOLD_ALL = sum((rows_of(os.path.join(EVD, f)) for f in ("gold.jsonl", "gold-holdout.jsonl", "gold-holdout2.jsonl", "gold-java.jsonl")), [])
RA = reduction(RUNS, GOLD_ALL)
RP = reduction({n: RUNS[n] for n in PYJS}, GOLD_ALL)
RJ = reduction({n: RUNS[n] for n in JAVA}, GOLD_ALL)
H2_V12 = read_acc_md(os.path.join(EVD, "accuracy-holdout2-v1.2.md"))
H2_FIRST = read_acc_md(os.path.join(EVD, "accuracy-holdout2-v1.3-first.md"))
H2_FINAL = read_acc_md(os.path.join(EVD, "accuracy-holdout2-v1.3.md"))
JV_FIRST = read_acc_md(os.path.join(EVD, "accuracy-java-first.md"))
JV_FINAL = read_acc_md(os.path.join(EVD, "accuracy-java.md"))
KAP = json.load(open(os.path.join(EVD, "kappa.md.json"), encoding="utf-8"))
KAP_N = len(KAP)
KAP_AGREE = sum(r["claude"] == r["gemini"] for r in KAP)
KAP_K = cohen_kappa([(r["claude"], r["gemini"]) for r in KAP])


def _flag_table(goldfile):
    gold = {(g["repo"], f'{g["package"].lower()}@{g["version"]}|{g["advisory"]}'): g["verdict"] for g in rows_of(os.path.join(EVD, goldfile))}
    pred, flagged = {}, set()
    for n, r in RUNS.items():
        for x in r["alerts"]:
            k = (n, f'{x["package"].lower()}@{x["version"]}|{x["advisory"]}')
            pred[k] = x["verdict"]
            if (x.get("review") or {}).get("flagged"):
                flagged.add(k)
    return precision_by_flag(gold, pred, flagged)


FT2 = _flag_table("gold-holdout2.jsonl")
FT1 = _flag_table("gold-holdout.jsonl")
REM_ROWS = []
for _p in glob.glob(os.path.join(EVD, "traces", "*.remediate-*.jsonl")):
    REM_ROWS += rows_of(_p)
LS = llm_stats(REM_ROWS)
REV_ROWS = []
for _p in glob.glob(os.path.join(EVD, "traces", "*.jsonl")):
    if ".remediate-" not in _p and "alerts" not in _p and "goldcheck" not in _p:
        REV_ROWS += rows_of(_p)
LR = llm_stats(REV_ROWS)
ST = LS["status"]


def java_rows():
    out = ""
    for n in JAVA:
        r = RUNS[n]
        c = r["counts"]
        ps = next(json.loads(x).get("pom_stat") for x in open(os.path.join(EVD, "traces", f"{n}.alerts.jsonl"), encoding="utf-8") if '"tool": "sbom"' in x)
        t = next(t for t in JT if t["name"] == n)
        out += (f"<tr><td>{t['url'].replace('https://github.com/', '')} @{t['commit']}</td><td>Java</td><td class='r'>{r['components']}</td>"
                f"<td class='r'>{c['alerts']}</td><td class='r'><b>{c['REACHED']}</b></td><td class='r'>{c['USED']}</td><td class='r'>{c['UNSEEN']}</td>"
                f"<td class='r'>{r['elapsed_sec']:.1f}초</td></tr>")
        JAVA_STAT.append((n, ps))
    return out


JAVA_STAT = []
JAVA_ROWS = java_rows()
JS_UNRES = sum(p["unresolved"] for _, p in JAVA_STAT)
JS_DECL = sum(p["total_declared"] for _, p in JAVA_STAT)
JS_RES = sum(p["resolved"] for _, p in JAVA_STAT)
J_TOT = {k: sum(RUNS[n]["counts"][k] for n in JAVA) for k in ("alerts", "REACHED", "USED", "UNSEEN")}
J_COMP = sum(RUNS[n]["components"] for n in JAVA)
INC_N = 948

SIMILAR = """<table><tr><th style="width:23%">서비스</th><th style="width:44%">방식(공개 문서 기준)</th><th>우리가 다른 점</th></tr>
<tr><td>Endor Labs<br><span class=note>endorlabs.com/learn/benchmarking-endor-labs-vs-snyks-github-apps</span></td><td>호출 그래프로 취약 함수가 실제 호출되는지 판정, EPSS 결합(상용 SaaS, 수치는 자사 벤치마크)</td><td rowspan=5>① 판정마다 <b>근거 줄(파일:줄)</b>을 붙이고 근거가 없으면 「도달」이라 하지 못하게 코드로 막음 ② 조치 후 <b>재스캔 감소를 같은 출력에</b> 냄 ③ 정답 103건(AI가 작성)과의 <b>일치율·틀린 곳을 공개</b> ④ 로컬·무료 도구만으로 재현</td></tr>
<tr><td>Snyk Reachability<br><span class=note>docs.snyk.io/manage-risk/prioritize-issues-for-fixing/reachability</span></td><td>애플리케이션과 의존성의 호출 그래프를 분석(문서상 CLI·IDE 연동에서는 미지원)</td></tr>
<tr><td>Semgrep Supply Chain<br><span class=note>semgrep.dev/docs/faq/comparisons/endor-labs</span></td><td>직접 의존성에 대한 데이터플로 도달성(벤더 자체 주장)</td></tr>
<tr><td>래브라도 SCM<br><span class=note>m.boannews.com/html/detail.html?idx=132104</span></td><td>국내 SBOM 교환·취약점 이슈 파악 플랫폼(공개 기사에서 도달성 판정은 확인하지 못함)</td></tr>
<tr><td>롯데이노베이트 자사 SBOM·취약점 제품</td><td>2026-11-02 검색엔진 질의 7회(제품 소개·매뉴얼, 특허, 채용공고, 뉴스, 정부과제·논문 5유형)에서 <b>찾지 못함</b>. 특허청 KIPRIS·전자공시·채용 사이트 원문은 직접 열람하지 못했으므로 「없다」고 단정하지 않음</td></tr></table>"""

# ───────── 해결방안 4쪽 (v1.3)
NALL, RALL, FLAG, UNFL = RA["alerts"], RA["reached"], RA["flagged"], RA["unflagged"]
p1 = f"""<div class=brow>AI 문제해결방안 · LOTTE AX Challenge 2026 · 롯데이노베이트</div>
<h1>SBOM·취약점 스캔 결과의 영향도·우선순위 연결 구조 설계,<br>그리고 조치안 도출 및 개선을 돌리는 코드 파이프라인과 AI 보조</h1>
<p class=lede>과제 「SBOM 생성과 취약점 스캔 결과의 영향도·우선순위 연결 구조 설계」「AI 에이전트 기반 조치안 도출 및 개선」에 대한 작동 프로토타입입니다 — 공개 레포 <code>{REPO}</code>(비로그인 열림, 시험 {TESTS}건)에서 경보 {NALL}건 중 코드가 실제로 호출하는 {RALL}건을 근거 줄과 함께 먼저 올리고, 그중 근거가 약해 보이는 {FLAG}건에는 「사람 확인 필요」를 붙여 사람이 먼저 열 {UNFL}건으로 좁힙니다. 도달 판정과 고칠 버전은 코드가 하고, AI(Gemini)는 <b>두 자리</b>만 맡습니다: ① 조치안 설명 문장 ② 약한 도달 판정에 「사람 확인 필요」 표시(판정을 올리지 못함).</p>
<div class=big><div><b>{NALL} → {RALL} → {UNFL}</b><span>사람이 열어 볼 경보 수: 전체 → 도달 → 「확인 필요」 표시 제외. 표시 제외 {RA['unflagged_labeled']}건 중 정답도 도달 {RA['unflagged_tp']}건(precision@{UNFL} {RA['precision_unflagged']}%, 정답 있는 것만)</span></div>
<div><b>{H2_FIRST['reached_precision']}%</b><span>새 홀드아웃2({H2_FIRST['total']}건) 첫 실행 도달 정밀도(대표값). 같은 정답에 v1.2 판정기는 {H2_V12['reached_precision']}%. 표시 제외 후 {FT2.unflagged_precision * 100:.0f}%</span></div>
<div><b>{LS['adopted']}/{LS['requested']}</b><span>AI 조치안 문장 채택(v1.2는 7/187). 실패 원인을 trace에 남기고 고친 뒤 재실행</span></div></div>
<h2><span class=n>1</span>문제와 해법</h2>
<p><b>문제.</b> SBOM(부품 목록)과 취약점 스캔은 따로 나오고, 보안 운영 담당은 수백 건 경보를 하나씩 열어 「우리 코드가 이 함수를 부르나」를 사람이 따집니다. 실행한 {len(PYJS) + len(JAVA)}곳 합계 {NALL}건 중 {pc(T['unseen'] + J_TOT['UNSEEN'], NALL)}는 소스에 그 패키지를 쓰는 줄이 없었고, 호출 근거가 있는 것은 {pc(RALL, NALL)}였습니다.</p>
<p><b>해법.</b> 파이프라인이 ① 저장소에서 SBOM 생성 → ② 알려진 취약점 조회 → ③ 취약 함수 호출 여부를 <b>근거 줄</b>로 판정(도달·사용·미확인) → ④ 심각도×도달 가중으로 우선순위와 <b>고칠 버전</b>(OSV가 알려 준 고침 버전 중 최저)을 코드가 정함 → ⑤ AI가 조치안 설명 문장을 쓰고, 도달 중 약한 근거에 「사람 확인 필요」를 붙임 → ⑥ 조치를 별도 git 가지에 적용 → ⑦ 재스캔으로 경보 감소를 측정(도달이 남으면 최대 3바퀴). 병합·배포는 하지 않고 사람이 승인합니다.</p>
<p><b>코드와 AI의 역할 — 실체에 맞게.</b> 도구를 부르는 순서·판정·우선순위·고칠 버전은 모두 코드라서, 이것은 「모델이 계획을 세우는 자율 에이전트」가 아니라 <b>코드 파이프라인 위에 AI 두 자리를 얹은 구조</b>입니다. AI 자리 ①은 버전 숫자 허용 목록(G2)·판정 뒤집기 금지(G3)를 어기면 문장을 버립니다. 자리 ②는 결과 타입에 판정 필드가 없고 사용·미확인을 도달로 올리는 호출 경로가 없어(G1 유지, 시험 test_review_flag) 도달 목록을 <b>좁히는 정보</b>만 줍니다.</p>
<h2><span class=n>2</span>같은 문제를 푸는 기존 서비스와 다른 점</h2>
{SIMILAR}
<p class=note>위 서비스의 수치는 각 벤더의 공개 문서·자사 벤치마크이며 독립 검증값이 아닙니다. 우리 수치는 아래 공개 저장소와 정답 파일로 재현할 수 있습니다.</p>
<h2><span class=n>3</span>과제 문구와 구조도의 대응</h2>
<table><tr><th style="width:42%">과제 문구</th><th>구조도(그림 1) 노드</th><th>산출물</th></tr>
<tr><td>SBOM 생성과 취약점 스캔 결과의 영향도·우선순위 <b>연결</b> 구조 설계</td><td>1 SBOM → 2 조회 → <b>3 도달 판정</b> → 4 우선순위</td><td>경보별 판정·근거 줄·점수</td></tr>
<tr><td>AI 에이전트 기반 <b>조치안 도출</b></td><td>4 조치 계획 → 5 AI 두 자리(설명 문장·확인 표시)</td><td>패키지별 현재→목표 버전·설명</td></tr>
<tr><td>… 및 <b>개선</b></td><td>6 조치 가지 → 7 재스캔 → (순환)</td><td>해소·남음·신규 경보 수</td></tr></table>"""

p2 = f"""<div class=brow>AI 문제해결방안 · 구조와 평가</div>
<img class=fig src="architecture.svg" style="width:70%;display:block;margin:0 auto">
<p class=cap>그림 1. 구조도 — 도구 호출 순서, 사람/코드/AI 경계(8), 평가(Evals), 가드레일, 실패 처리</p>
<h2><span class=n>4</span>가드레일과 평가</h2>
<table><tr><th style="width:11%">규칙</th><th style="width:56%">내용(코드로 집행)</th><th>시험</th></tr>
<tr><td>G1</td><td>근거 줄이 없는 「도달」은 판정 객체를 만들 수 없다. AI 표시 결과 타입에는 판정 필드가 없다</td><td>test_reached_requires_evidence, test_review_flag</td></tr>
<tr><td>G2·G3</td><td>AI 문장의 버전 숫자는 허용 목록만, 「안전합니다」류 단정·판정 뒤집기는 폐기 후 템플릿</td><td>test_domain_guardrails</td></tr>
<tr><td>G4~G6</td><td>허용 명령만 실행(대상 코드 실행·설치 차단) / AI 입력 키·이메일 마스킹 / 조회 미완이면 「경보 0 = 깨끗함」 금지</td><td>test_g4~g6</td></tr></table>
<p><b>평가(Evals).</b> 정답은 <b>사람이 아니라 AI(Claude)가 소스 줄을 직접 열어 작성</b>했고 사람 검산 전입니다. 개발셋 66건·홀드아웃1 37건은 판정기를 고치는 데 쓰여 대표값에서 뺍니다(홀드아웃1의 v1.2 값 동결 직후 78.4%·수정 뒤 81.1%는 사후 수정이었음). 대신 <b>수정 코드를 쓰기 전에 새 홀드아웃2 {H2_FIRST['total']}건을 동결·커밋</b>하고 처음 돌린 값을 대표값으로 씁니다. 같은 정답에 v1.2 판정기를 돌린 값을 나란히 둡니다.</p>
<table><tr><th>정답 묶음 · 판정기</th><th class=r>건수</th><th class=r>3분류 일치</th><th class=r>도달 정밀도</th><th class=r>도달 재현율</th></tr>
<tr><td>홀드아웃2 · v1.2 판정기(비교용)</td><td class=r>{H2_V12['total']}</td><td class=r>{H2_V12['matched']} ({H2_V12['rate']}%)</td><td class=r>{H2_V12['reached_precision']}%</td><td class=r>{H2_V12['reached_recall']}%</td></tr>
<tr><td><b>홀드아웃2 · v1.3 첫 실행(대표값)</b></td><td class=r>{H2_FIRST['total']}</td><td class=r><b>{H2_FIRST['matched']} ({H2_FIRST['rate']}%)</b></td><td class=r><b>{H2_FIRST['reached_precision']}%</b></td><td class=r>{H2_FIRST['reached_recall']}%</td></tr>
<tr><td>홀드아웃2 · 사후 수정(언어 내장 이름 제외)</td><td class=r>{H2_FINAL['total']}</td><td class=r>{H2_FINAL['matched']} ({H2_FINAL['rate']}%)</td><td class=r>{H2_FINAL['reached_precision']}%</td><td class=r>{H2_FINAL['reached_recall']}%</td></tr>
<tr><td>└ 「사람 확인 필요」 표시 제외 후</td><td class=r>도달 {FT2.reached}→{FT2.unflagged_reached}</td><td class=r>—</td><td class=r><b>{FT2.unflagged_precision * 100:.1f}%</b> ({FT2.unflagged_tp}/{FT2.unflagged_reached})</td><td class=r>—</td></tr>
<tr><td>Java 운영형 3곳 정답 {JV_FIRST['total']}건 · 첫 실행 → 사후 수정</td><td class=r>{JV_FIRST['total']}</td><td class=r>{JV_FIRST['rate']}% → {JV_FINAL['rate']}%</td><td class=r colspan=2>정답 도달 1건뿐이라 정밀도는 말하지 않음</td></tr></table>
<p class=note>목표 80%·정밀도 70%는 첫 실행으로 넘지 못했습니다. 표본이 작아(도달 후보 {H2_FIRST['rows']['REACHED'][0] + H2_FIRST['rows']['USED'][0] + H2_FIRST['rows']['UNSEEN'][0]}건) 구간이 넓고, 홀드아웃2 후보 목록은 규칙을 만들 때 v1.2 판정을 이미 본 상태라 완전한 눈가림은 아닙니다. 정답 독립성: 홀드아웃2 {KAP_N}건을 <b>다른 모델(Gemini)</b>이 도구 판정을 모른 채 글자 검색 줄만 보고 다시 판정해 일치 {KAP_AGREE}/{KAP_N}건, <b>Cohen kappa {KAP_K:.2f}</b>(두 모델 모두 AI라 사람 검산을 대신하지 못함).</p>
<p><b>AI 판정 보조의 효과(Evals).</b> 도달 중 약한 근거 후보 {LR['review_confirm'] + LR['review_doubt']}건을 AI가 근거 줄을 읽고 {LR['review_confirm']}건은 통과, {LR['review_doubt']}건에 「사람 확인 필요」를 붙였습니다. 표시 전→후 도달 정밀도는 홀드아웃2 {FT2.precision * 100:.0f}%→{FT2.unflagged_precision * 100:.0f}%({FT2.tp}/{FT2.reached} → {FT2.unflagged_tp}/{FT2.unflagged_reached}), 홀드아웃1 {FT1.precision * 100:.0f}%→{FT1.unflagged_precision * 100:.0f}%입니다. 표시 기준은 홀드아웃2의 오류를 본 뒤 정했으므로 낙관적입니다. 표시는 순위를 바꾸지 않습니다.</p>
<p><b>실패 처리와 AI 채택률.</b> 취약점 조회가 실패하면 재시도 2회 뒤 「스캔 미완」으로 표시하고 경보 0을 깨끗하다고 말하지 않습니다. v1.2는 AI 문장 7건 채택·180건 <code>HTTPError</code>였고 원인을 남기지 않았습니다. 이번에는 trace에 상태 코드·원문을 남기고 원인을 실측했습니다: 같은 키로 gemini-2.5-flash에 연속 8회 호출하면 6회가 429(RESOURCE_EXHAUSTED, 무료 한도)였고, 후속 모델 gemini-3.5-flash-lite는 thinkingBudget 인자를 거부(400)했습니다. 모델 교체·호출 간격 4.5초·429 재시도·디스크 캐시로 고쳐 재실행한 결과 <b>AI 문장 {LS['adopted']}/{LS['requested']}건 채택({LS['adopt_rate']}%)</b>, 호출 상태 200 {ST.get('200', 0)}건·429 {ST.get('429', 0)}건(재시도로 회복)·캐시 {ST.get('cache', 0)}건입니다. v1.2의 180건 실패를 같은 조건으로 되돌려 확인하지는 못했습니다.</p>"""

p3 = f"""<div class=brow>AI 문제해결방안 · 실행 증거</div>
<h2 style="margin-top:0"><span class=n>5</span>실행 결과 — 공개 저장소 {len(PYJS) + len(JAVA)}곳, 언어 3개(Python·JavaScript·Java)</h2>
<table><tr><th>저장소(고정 커밋)</th><th>언어</th><th class=r>부품</th><th class=r>경보</th><th class=r>도달</th><th class=r>사용</th><th class=r>미확인</th><th class=r>소요</th></tr>{repo_rows()}{JAVA_ROWS}
<tr><th colspan=2>합계(Java 포함)</th><th class=r>{T['components'] + J_COMP}</th><th class=r>{NALL}</th><th class=r>{RALL}</th><th class=r>{T['used'] + J_TOT['USED']}</th><th class=r>{T['unseen'] + J_TOT['UNSEEN']}</th><th></th></tr>
<tr><td colspan=8 class=note>소요 시간 전제: OSV 응답을 디스크 캐시(<code>data/osv-cache</code>)에서 읽은 값이라 네트워크 조회는 포함하지 않습니다. 캐시가 비면 부품 수에 비례해 길어집니다(저장소 1곳 최초 조회 수십 초~분 단위로 실측하지는 않음).</td></tr></table>
<p class=note>저장소: """ + " · ".join(f"{r['url'].replace('https://','')} @{r['commit']}" for r in S['repos']) + f""". 앞 4곳(Python·JS)은 보안 교육용으로 일부러 취약하게 만든 저장소이고, 뒤 3곳(Java)은 <b>교육용이 아닌 운영형 오픈소스</b>(워크플로 스케줄러·데이터 정제 서버·기업용 플랫폼)입니다. 「미확인」은 안전이 아니라 소스에 쓰는 줄이 없다는 뜻입니다. Java 부품은 pom.xml에서 읽은 직접 선언 {JS_RES}개이고, 선언 {JS_DECL}건 중 외부 BOM이 버전을 정해 읽지 못한 {JS_UNRES}건은 제외했습니다(전이 의존 미포함). 재스캔 표의 기준 {RS_UNIQ}는 같은 패키지·어드바이저리의 버전 중복을 합친 고유 경보 수라 {T['alerts']}와 다릅니다.</p>
<h2><span class=n>6</span>사람이 열어 볼 경보 수 — 주 지표</h2>
<table><tr><th>범위</th><th class=r>전체 경보</th><th class=r>도달</th><th class=r>확인 필요 표시</th><th class=r>먼저 열 경보 N</th><th class=r>precision@N(정답 있는 것)</th></tr>
<tr><td>Python·JS 4곳</td><td class=r>{RP['alerts']}</td><td class=r>{RP['reached']}</td><td class=r>{RP['flagged']}</td><td class=r><b>{RP['unflagged']}</b></td><td class=r>{RP['precision_unflagged']}% ({RP['unflagged_tp']}/{RP['unflagged_labeled']})</td></tr>
<tr><td>Java 운영형 3곳</td><td class=r>{RJ['alerts']}</td><td class=r>{RJ['reached']}</td><td class=r>{RJ['flagged']}</td><td class=r><b>{RJ['unflagged']}</b></td><td class=r>{RJ['precision_unflagged']}% ({RJ['unflagged_tp']}/{RJ['unflagged_labeled']}, 사후 검산)</td></tr>
<tr><th>합계</th><th class=r>{RA['alerts']}</th><th class=r>{RA['reached']}</th><th class=r>{RA['flagged']}</th><th class=r>{RA['unflagged']}</th><th class=r>{RA['precision_unflagged']}% ({RA['unflagged_tp']}/{RA['unflagged_labeled']})</th></tr></table>
<p class=note>precision@N은 정답이 있는 도달 경보로만 냈고(정답 없는 {RA['reached'] - RA['labeled_reached']}건은 같은 advisory의 다른 버전), 개발셋·홀드아웃1이 섞여 있어 <b>낙관적</b>입니다. 대표값은 위 4장의 홀드아웃2 첫 실행값입니다. 건당 처리 시간(분)·단가(원)는 롯데 실측값이 없어 가정값이 필요하므로 금액으로 환산하지 않았습니다.</p>
<h2><span class=n>7</span>개선 순환 — 조치 적용 가지에서 재스캔 (Python·JS)</h2>
<p>조치안은 패키지별로 그 버전의 알려진 경보를 모두 덜어내는 가장 낮은 고쳐진 버전입니다. 사본 저장소에 <code>fix/sbomreach</code> 가지를 만들어 requirements·package.json을 고치고(npm은 잠금 파일만 재생성, 스크립트 실행 없음) 같은 절차로 다시 스캔합니다.</p>
<table><tr><th rowspan=2>저장소</th><th colspan=3>도달만 조치</th><th colspan=2>전부 조치</th></tr><tr><th class=r>도달 경보</th><th class=r>올린 패키지</th><th class=r>경보(고유)</th><th class=r>올린 패키지</th><th class=r>경보(고유)</th></tr>{rescan_rows()}</table>
<ul><li>도달 경보는 {rs_sum('reached','reached_before')}건에서 {rs_sum('reached','reached_after')}건으로 줄었고, 올린 패키지는 {rs_sum('reached','packages_changed')}개로 「전부 조치」 {rs_sum('all','packages_changed')}개의 {pc(rs_sum('reached','packages_changed'), rs_sum('all','packages_changed'))}입니다. 남은 1건은 nodejs-goof의 중첩 복사본(ms 0.6.2)입니다. 조치 뒤 새로 생긴 경보 {sum(v['new'] for k, v in RS.items() if k.endswith('.reached'))}건(도달만 조치 기준). 올린 버전 {MT}개 중 주 버전이 바뀐 것은 {MJ}개라 <b>호환성 검토와 사람 승인이 필요</b>합니다.</li></ul>
"""

p4 = f"""<div class=brow>AI 문제해결방안 · 현업 예시, 한계, 일정, 재현</div>
<h2 style="margin-top:0"><span class=n>8</span>입력→출력 한 건 (현업 적용 예시)</h2>
<table><tr><th style="width:26%">입력</th><th>출력(경보 1건)</th></tr>
<tr><td>저장소 경로 1개<br><span class=note>또는 CycloneDX SBOM 파일 · Maven pom.xml</span></td><td>adm-zip 0.4.7 · GHSA-j5f4-cc29-5x44 · 심각도 HIGH · <b>판정 도달</b> · 근거 <code>routes/index.js:270</code> (<code>zip.extractAllTo(...)</code>) · 조치 0.4.7 → 0.6.1 · 검증: 재스캔에서 해당 경보 소멸</td></tr></table>
<table style="font-size:7.3pt"><tr><th>순위</th><th>패키지</th><th>버전</th><th>경보</th><th>심각도</th><th>판정</th><th>근거 줄</th></tr>{RANK_ROWS}</table>
<p class=cap>그림 2. 사용자가 받는 순위 보고서 화면 — nodejs-goof 상위 5건(레포 evidence/runs/nodejs-goof.ranking.md 그대로 — 1위 mongoose는 정답이 「사용」인 오탐이라 한계에 포함)</p><h2><span class=n>9</span>한계 (숨기지 않는 것)</h2>
<ul><li>정답은 AI 한 주체가 작성했고 사람 검산 전입니다(독립 재판정 kappa {KAP_K:.2f}는 다른 AI와의 일치). 홀드아웃2 {H2_FIRST['total']}건, 도달 후보가 {H2_FIRST['rows']['REACHED'][0] + H2_FIRST['rows']['USED'][0]}건뿐이라 정밀도 {H2_FIRST['reached_precision']}%의 구간이 넓고, 목표 70%는 넘지 못했습니다.</li>
<li>Java는 <b>최소 어댑터</b>입니다: pom.xml 직접 선언(속성·dependencyManagement·저장소 안 부모·BOM 해석)과 import·클래스·메서드 이름 근거 줄뿐이며 Gradle·외부 BOM 버전·전이 의존·타입 추론은 없습니다. 선언 {JS_DECL}건 중 {JS_UNRES}건은 버전을 읽지 못해 빠졌습니다. 패키지 접두 매핑은 이름 규칙+별칭표 휴리스틱이라 맞지 않으면 「미확인」입니다. Java 정답은 {JV_FIRST['total']}건(도달 1건)이라 정밀도를 주장하지 않습니다. 운영형 Java 도달은 2건(같은 advisory의 두 버전)뿐입니다.</li>
<li>Python·JS 4곳은 교육용 취약 저장소입니다. 전이 의존은 호출 그래프를 만들지 않아 「미확인」이며, 동적 import·템플릿 속 호출은 보지 못합니다. JS 분석은 토큰 기반입니다.</li>
<li>취약점 DB는 OSV 하나이고, 취약 함수 이름은 어드바이저리 본문에서 뽑아 본문 속 예시가 섞입니다(AI 표시로 일부만 걸러짐).</li></ul>
<h2><span class=n>10</span>일정·자원·목표치</h2>
<table><tr><th style="width:25%">날짜</th><th>마일스톤</th><th style="width:30%">확정 증거</th></tr>
<tr><td>2026-11-03 (내부 마감, 공고 마감 2026-11-04 23:59)</td><td>구조·시험·정답·재스캔·Java 실행 증거 확정(이 문서)</td><td>시험 {TESTS}건, 정답 {A1['total'] + AH['total'] + H2_FIRST['total'] + JV_FIRST['total']}건, 저장소 {len(PYJS) + len(JAVA)}곳</td></tr>
<tr><td>2026-11-24 ~ 11-25 (본선, 공고 원문 1박2일)</td><td>현장 데이터 연결 어댑터와 입력 스키마 확정 → 현장 저장소 정답 20건 추가, Java Gradle·외부 BOM 해석 추가, 오탐 심볼 검증 개선</td><td>어댑터 시험 통과, 정밀도 재측정 표</td></tr>
<tr><td>2026-11-25 (본선 발표 전)</td><td>조치 가지·재스캔 시연, 사람 승인 단계 연결</td><td>해소·남음·신규 경보 표</td></tr></table>
<p><b>투입 자원</b>: 1인, 로컬 머신, 무료 도구(OSV 공개 DB·syft·git·Gemini 무료 한도), 대상 코드는 읽기만. <b>목표치 3개</b>: ① 홀드아웃 도달 정밀도 ≥70%(예선 첫 실행 {H2_FIRST['reached_precision']}%, 표시 후 {FT2.unflagged_precision * 100:.0f}%) ② 현장 저장소 정답 추가 20건 ③ 조치 가지 재스캔 후 도달 경보 0(예선 {rs_sum('reached','reached_after')}건 남음).</p>
<h2><span class=n>11</span>재현 방법</h2>
<p>레포 <code>{REPO}</code> (공개, 로그인 없이 열림). <b>실행은 표준 라이브러리만</b>(파이썬 3.9+, 스캔은 syft가 있으면 사용·없으면 잠금 파일 파서), <b>시험은 pytest</b>입니다.</p>
<ul><li><code>python3 -m pytest -q</code> — 시험 {TESTS}건, 오프라인.</li>
<li><code>python3 scripts/clone_targets.py</code> — <code>evidence/targets.json</code>의 Python·JS 4저장소를 <code>untrusted/</code> 아래에 고정 커밋으로 받음. Java 3곳은 <code>evidence/targets-java.json</code>의 URL·커밋으로 홈 폴더의 <code>untrusted/</code>에 받음(코드 실행 없음).</li>
<li><code>mkdir -p data &amp;&amp; tar xzf evidence/osv-snapshot-2026-10-30.tar.gz -C data</code> — OSV 스냅샷(Java 부품은 새로 조회).</li>
<li><code>python3 -m sbomreach.infrastructure.cli scan --target nodejs-goof --review</code> → <code>... remediate ...</code> → <code>... eval --gold gold-holdout2.jsonl</code> (Java: <code>--target dolphinscheduler</code>).</li></ul>
<p class=note>syft 없이 nodejs-goof를 돌리면 잠금 파일 파서로 대체되어 부품·경보 수가 다릅니다(경보 235 → 315건 실측). 정답 파일은 <code>evidence/gold*.jsonl</code>, 규약은 <code>evidence/GOLD*.md</code>, 구조 규칙은 <code>SPEC.md</code>입니다.</p>"""

SOL = [p1, p2, p3, p4]

# ───────── 1쪽 요약
SUM = f"""<div class=brow>AI 문제해결방안 요약 · LOTTE AX Challenge 2026</div>
<h1>경보 {NALL}건 중 사람이 먼저 열 {UNFL}건을 근거 줄과 함께 올립니다</h1>
<p class=lede>SBOM·취약점 스캔 결과의 영향도·우선순위 연결 구조와, 조치안 도출 및 개선(재스캔 순환)을 돌리는 코드 파이프라인과 AI 보조 (롯데이노베이트)</p>
<div class=big><div><b>{NALL} → {RALL} → {UNFL}</b><span>전체 경보 → 도달 → 「확인 필요」 표시 제외. 운영형 Java 3곳 포함 {len(PYJS) + len(JAVA)}곳</span></div><div><b>{H2_FIRST['reached_precision']}%</b><span>새 홀드아웃2 첫 실행 도달 정밀도(v1.2 판정기 {H2_V12['reached_precision']}%), 표시 제외 후 {FT2.unflagged_precision * 100:.0f}%</span></div><div><b>{rs_sum('reached','reached_before')} → {rs_sum('reached','reached_after')}</b><span>조치 가지 재스캔 후 도달 경보 (패키지 {rs_sum('reached','packages_changed')}개 조치)</span></div></div>
<h2>문제</h2><p>SBOM과 스캔 결과가 따로 나와 수백 건 경보를 사람이 하나씩 따집니다. 이번 {len(PYJS) + len(JAVA)}곳에서 호출 근거가 있는 경보는 {pc(RALL, NALL)}였습니다.</p>
<h2>해법</h2><ul><li>SBOM 생성 → 취약점 조회 → <b>호출 근거 줄로 도달 판정</b> → 우선순위·조치안 → 조치 가지 적용 → 재스캔(최대 3바퀴). Python·JavaScript·Java(Maven 최소 어댑터)</li><li>판정과 고칠 버전은 코드. AI는 두 자리: 조치안 설명 문장(채택 {LS['adopted']}/{LS['requested']}), 약한 도달 판정에 「사람 확인 필요」 표시(판정을 올리지 못함)</li><li>병합·배포는 사람이 승인</li></ul>
<h2>구조</h2><img class=fig src="architecture.svg" style="width:100%">
<h2>다른 점</h2><p>기존 도달성 도구(Endor Labs·Snyk·Semgrep)는 호출 그래프·데이터플로를 상용으로 제공합니다. 이 도구는 ① 판정마다 근거 줄 ② 조치 후 재스캔 감소를 한 출력에 ③ 정답 일치율과 틀린 곳 공개(다른 AI 재판정 kappa {KAP_K:.2f}) ④ 로컬·무료 도구만으로 재현을 더합니다.</p>
<h2>한계</h2><p>정답은 AI가 작성했고 사람 검산 전입니다. 홀드아웃2 {H2_FIRST['total']}건 첫 실행 일치 {H2_FIRST['rate']}%·도달 정밀도 {H2_FIRST['reached_precision']}%(목표 70% 미달). Java는 pom.xml 직접 선언만(Gradle·외부 BOM·전이 의존 제외). Python·JS 대상 4곳은 교육용 취약 저장소. 전이 의존은 「미확인」. 효과는 금액이 아니라 사람이 열어 볼 경보 수로만 냈습니다.</p>"""


# ───────── 역량 자료
CAP = f"""<div class=brow>AI 보유역량 · LOTTE AX Challenge 2026</div>
<h1>AI 에이전트를 만들어 운영하고, 틀린 기록을 구조로 고쳐 온 기록</h1>
<p class=lede>모든 항목은 공개 링크나 숫자로 확인할 수 있습니다. 4항은 개인 운영 기록이라 공개 링크가 없으므로 날짜·원인·고친 장치 파일명을 발췌 3건으로 직접 보입니다(개인정보·계정 없음).</p>
<h2>1. 이번 과제의 작동 프로토타입</h2>
<table><tr><th style="width:24%">항목</th><th>내용</th></tr>
<tr><td>레포</td><td><code>{REPO}</code> — SBOM 생성부터 도달 판정·조치 가지·재스캔까지 도는 에이전트, 시험 {TESTS}건, 정답 {A1['total'] + AH['total']}건</td></tr>
<tr><td>실행 기록</td><td>공개 저장소 {len(PYJS) + len(JAVA)}곳(Python·JavaScript·운영형 Java 3곳) 경보 {NALL}건 판정, 새 홀드아웃2 첫 실행 도달 정밀도 {H2_FIRST['reached_precision']}%(v1.2 판정기 {H2_V12['reached_precision']}%), 사람이 먼저 열 경보 {NALL} → {RALL} → {UNFL}, AI 문장 채택 {LS['adopted']}/{LS['requested']}</td></tr>
<tr><td>사용한 AI</td><td>Gemini(조치안 설명 문장·약한 도달 판정에 확인 표시·정답 독립 재판정), 코드 작성·정답 작성 Claude. 판정·고칠 버전 결정은 코드가 함</td></tr></table>
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
</ul>
<h2>4. 에이전트가 틀렸을 때 구조로 고친 운영 기록</h2>
<p>개인 운영 환경(에이전트가 일정·공모·코드를 대신 처리)에서 에이전트의 문제를 시스템 이슈로 기록하고 훅·검사 스크립트로 내린 이력이 있습니다. 기록 파일(비공개) 줄 수 실측: 2026-09-02~10-30 사이 {INC_N}건(2026-11-02 집계). 아래는 그중 3건의 발췌입니다.</p>
<table><tr><th style="width:19%">일시</th><th>원인(발췌)</th><th style="width:30%">고친 장치</th></tr>
<tr><td>2026-10-10 17:00</td><td>훅 32개가 예외가 나면 조용히 통과(fail-open) — 고장 나도 기록이 0이라 장치가 돈다는 것이 자기보고였음</td><td><code>_system/lint.py</code> 의 <code>check_hook_errors</code></td></tr>
<tr><td>2026-10-12 10:24</td><td>공고 목록 파일을 두 작업이 동시에 읽고 고쳐 써서, 먼저 처리한 8건 중 7건이 덮여 되돌아감(잠금 없음)</td><td><code>_system/opps.py</code> 쓰기 명령에 배타 잠금, 시험 <code>test_opps.py</code></td></tr>
<tr><td>2026-10-14 02:40</td><td>병렬 호출의 사후 훅이 잠금 없이 읽기-고치기-쓰기를 해 일정 3건이 스냅숏에서 사라짐. 재현 시험 3/3 실패 → 잠금 후 3/3 통과</td><td><code>_system/hook-post-ticktick.py</code> 의 <code>_locked</code></td></tr></table>
<p class=note>3항 이전 항목의 날짜·건수는 2026-10-30 기준(2-1항 URL만 2026-11-02, 4항 건수는 11-02)이며, 판정 정확도는 이 레포 evidence 폴더의 정답 파일로 재현할 수 있습니다.</p>"""


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
