"""사내 환경 입력 어댑터 표(S17) — 작은 픽스처를 만들어 실제 SBOM 단계에 넣어 읽힌 개수로 칸을 채운다. 말로 채우지 않는다."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class Probe:
    label: str
    kind: str                 # "maven"(pom 해석기) | "syft"(syft, 없으면 잠금 파일 파서)
    files: Dict[str, str]
    expected: int             # 이 픽스처에 사람이 보기엔 선언된 부품 수
    how: str                  # 못 읽거나 일부만 읽힐 때 사내에서 어떻게 하는가
    how_read: str = "그대로 읽는다"


@dataclass
class ProbeResult:
    label: str
    found: int
    expected: int
    unresolved: int
    status: str
    how: str
    measured: bool
    advisories: Optional[int] = None
    found_nosyft: Optional[int] = None    # kind=="syft" 인 줄만: syft 실행 파일이 없을 때(잠금 파일 파서 대체)


_POM = """<project><modelVersion>4.0.0</modelVersion>{head}<groupId>g</groupId><artifactId>a</artifactId><version>1</version>
{props}<dependencies>{deps}</dependencies></project>"""


def _dep(g, a, v=None):
    return f"<dependency><groupId>{g}</groupId><artifactId>{a}</artifactId>" + (f"<version>{v}</version>" if v else "") + "</dependency>"


PROBES: Tuple[Probe, ...] = (
    Probe("Maven pom.xml 직접 선언", "maven",
          {"pom.xml": _POM.format(head="", props="", deps=_dep("org.yaml", "snakeyaml", "1.30") + _dep("com.google.guava", "guava", "31.0-jre"))}, 2,
          "그대로 읽는다"),
    Probe("Maven 외부 BOM(버전 생략)", "maven",
          {"pom.xml": _POM.format(head="<parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.2.0</version></parent>",
                                  props="", deps=_dep("org.yaml", "snakeyaml", "1.30") + _dep("org.springframework.boot", "spring-boot-starter-web"))}, 2,
          "사내 BOM의 pom을 저장소에 함께 두거나, mvn dependency:list 출력을 입력으로 받는 어댑터 필요"),
    Probe("Maven 모노레포(부모 속성·모듈)", "maven",
          {"pom.xml": _POM.format(head="", props="<properties><snake.v>1.30</snake.v></properties>", deps=""),
           "mod/pom.xml": _POM.format(head="<parent><groupId>g</groupId><artifactId>a</artifactId><version>1</version><relativePath>../pom.xml</relativePath></parent>",
                                      props="", deps=_dep("org.yaml", "snakeyaml", "${snake.v}") + _dep("com.google.guava", "guava", "31.0-jre"))}, 2,
          "저장소 안 부모 pom만 풀린다. 저장소 밖 부모는 위 BOM 줄과 같다", "저장소 안 부모·속성은 풀어서 읽는다(저장소 밖 부모는 BOM 줄)"),
    Probe("Gradle build.gradle", "maven",
          {"build.gradle": "dependencies {\n  implementation 'org.yaml:snakeyaml:1.30'\n  implementation 'com.google.guava:guava:31.0-jre'\n}\n"}, 2,
          "스크립트라 실행 없이 버전이 정해지지 않는다 — `gradle dependencies --write-locks` 로 gradle.lockfile을 만들어 넣는다(다음 줄)"),
    Probe("Gradle gradle.lockfile", "maven",
          {"gradle.lockfile": "# lock\norg.yaml:snakeyaml:1.30=compileClasspath\ncom.google.guava:guava:31.0-jre=compileClasspath\nempty=\n"}, 2,
          "그대로 읽는다"),
    Probe("npm 모노레포(루트+하위 잠금 파일)", "syft",
          {"package-lock.json": '{"lockfileVersion":3,"packages":{"":{},"node_modules/lodash":{"version":"4.17.20"}}}',
           "packages/web/package-lock.json": '{"lockfileVersion":3,"packages":{"":{},"node_modules/minimist":{"version":"1.2.5"}}}'}, 2,
          "그대로 읽는다"),
    Probe("yarn.lock", "syft",
          {"yarn.lock": '# yarn lockfile v1\n\nlodash@^4.17.0:\n  version "4.17.20"\n  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"\n'}, 1,
          "npm install --package-lock-only 로 package-lock.json을 만들어 넣는다", "syft 필요(syft 없을 때 열 참조)"),
    Probe("Python requirements.txt(== 고정 / >= 범위)", "syft",
          {"requirements.txt": "flask==2.0.0\nrequests>=2.0\n"}, 2,
          "`>=` 범위는 버전이 정해지지 않아 못 읽는다 — pip freeze 결과를 입력으로 받는다"),
    Probe("Python poetry.lock", "syft",
          {"poetry.lock": '[[package]]\nname = "flask"\nversion = "2.0.0"\n\n[[package]]\nname = "requests"\nversion = "2.25.0"\n'}, 2,
          "syft가 없으면 못 읽는다 — requirements.txt로 내보내 넣는다", "syft 필요(syft 없을 때 열 참조)"),
    Probe("사설 레지스트리 패키지(@acme/billing)", "syft",
          {"package-lock.json": '{"lockfileVersion":3,"packages":{"":{},"node_modules/@acme/billing":{"version":"1.0.0","resolved":"https://npm.acme.internal/@acme/billing/-/billing-1.0.0.tgz"}}}'}, 1,
          "부품 목록에는 오른다. 공개 DB(OSV)에 없는 사내 패키지는 경보가 0이다 — 안전이 아니라 모른다는 뜻",
          "목록에는 오른다. 공개 DB(OSV)에 없는 사내 패키지는 경보 0 — 안전이 아니라 모른다는 뜻"),
)


def run_probes(sbom_fn: Callable[[str, str], Tuple[int, int]], workdir: str,
               advisories_fn: Optional[Callable[[str, str, str], int]] = None) -> List[ProbeResult]:
    """sbom_fn(kind, 폴더) -> (읽힌 부품 수, 못 읽은 선언 수). kind: maven | syft | fallback(syft 없이 잠금 파일 파서만). advisories_fn(이름, 버전, 생태계) -> 공개 DB 경보 수(없으면 미실측)."""
    out: List[ProbeResult] = []
    for i, p in enumerate(PROBES):
        root = os.path.join(workdir, f"probe{i}")
        for rel, text in p.files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, "w", encoding="utf-8").write(text)
        found, unres = sbom_fn(p.kind, root)
        nosyft = sbom_fn("fallback", root)[0] if p.kind == "syft" else None
        status = "읽는다" if found >= p.expected else "일부만 읽는다" if found > 0 else "못 읽는다"
        adv = None
        if "사설" in p.label and advisories_fn is not None:
            adv = advisories_fn("@acme/billing", "1.0.0", "npm")
        out.append(ProbeResult(p.label, found, p.expected, unres, status, p.how_read if status == "읽는다" else p.how, True, adv, nosyft))
    return out


def render_matrix_md(rows: List[ProbeResult]) -> str:
    md = ["# 사내 환경 입력 어댑터 표 — 픽스처 실행 결과 (S17)", "",
          "| 입력 | 읽힌 부품/선언 | syft 없을 때 | 결과 | 사내에서 어떻게 |", "|---|---|---|---|---|"]
    for r in rows:
        how = r.how
        if "사설" in r.label:
            how += (" · 공개 DB 경보 %d건(안전이 아니다)" % r.advisories) if r.advisories is not None else " · 공개 DB 경보 수는 미실측"
        ns = "-" if r.found_nosyft is None else f"{r.found_nosyft}/{r.expected}"
        md.append(f"| {r.label} | {r.found}/{r.expected} | {ns} | {r.status} | {how} |")
    md += ["", "각 행은 작은 픽스처 폴더를 만들어 실제 SBOM 단계에 넣어 읽힌 개수를 센 값이다(손으로 채운 칸 없음)."]
    return "\n".join(md) + "\n"
