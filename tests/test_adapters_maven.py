from sbomreach.adapters.maven_pom import components_from_poms, direct_names_from_poms

ROOT = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId><artifactId>parent</artifactId><version>2.0.0</version>
  <packaging>pom</packaging>
  <properties><fastjson.version>1.2.24</fastjson.version><snake.v>1.30</snake.v></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>${snake.v}</version></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-dependencies</artifactId><version>2.7.0</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>com.alibaba</groupId><artifactId>fastjson</artifactId><version>${fastjson.version}</version></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version><scope>test</scope></dependency>
    <dependency><groupId>org.springframework</groupId><artifactId>spring-web</artifactId></dependency>
  </dependencies>
</project>"""

CHILD = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>2.0.0</version></parent>
  <artifactId>child</artifactId>
  <dependencies>
    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId></dependency>
    <dependency><groupId>com.acme</groupId><artifactId>other-module</artifactId><version>${project.version}</version></dependency>
    <dependency><groupId>commons-io</groupId><artifactId>commons-io</artifactId><version>${missing.prop}</version></dependency>
  </dependencies>
</project>"""


def test_properties_and_management_and_parent_chain_resolve():
    comps, stat = components_from_poms({"pom.xml": ROOT, "child/pom.xml": CHILD})
    got = {(c.name, c.version) for c in comps}
    assert ("com.alibaba:fastjson", "1.2.24") in got
    assert ("org.yaml:snakeyaml", "1.30") in got          # 자식은 부모 dependencyManagement 에서
    assert all(c.ecosystem == "Maven" for c in comps)


def test_test_scope_and_internal_modules_excluded_and_unresolved_counted():
    comps, stat = components_from_poms({"pom.xml": ROOT, "child/pom.xml": CHILD})
    names = {c.name for c in comps}
    assert "junit:junit" not in names                      # 시험 범위는 제품에 안 들어간다
    assert "com.acme:other-module" not in names            # 같은 저장소 모듈
    assert stat["test_scope"] == 1 and stat["internal"] == 1
    # spring-web(버전 없음, 외부 BOM) · commons-io(속성 못 찾음)
    assert stat["unresolved"] == 2 and stat["total_declared"] >= 6


def test_manifest_path_recorded_and_duplicates_collapsed():
    comps, _ = components_from_poms({"pom.xml": ROOT, "child/pom.xml": CHILD})
    snake = [c for c in comps if c.name == "org.yaml:snakeyaml"]
    assert len(snake) == 1 and snake[0].manifest in ("pom.xml", "child/pom.xml")


def test_direct_names_lowercased_group_artifact():
    names = direct_names_from_poms({"pom.xml": ROOT})
    assert "com.alibaba:fastjson" in names


def test_broken_xml_is_skipped_not_fatal():
    comps, stat = components_from_poms({"pom.xml": "<project><oops>", "b/pom.xml": ROOT})
    assert comps and stat["parse_errors"] == 1


BOM = """<project><groupId>com.acme</groupId><artifactId>acme-bom</artifactId><version>2.0.0</version>
  <properties><guava.v>31.0-jre</guava.v></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>${guava.v}</version></dependency>
  </dependencies></dependencyManagement></project>"""

APP = """<project><groupId>com.acme.app</groupId><artifactId>app</artifactId><version>1</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.acme</groupId><artifactId>acme-bom</artifactId><version>2.0.0</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId></dependency></dependencies></project>"""


def test_in_repo_bom_import_is_resolved_with_its_own_properties():
    comps, stat = components_from_poms({"bom/pom.xml": BOM, "app/pom.xml": APP})
    assert ("com.google.guava:guava", "31.0-jre") in {(c.name, c.version) for c in comps}
    assert stat["unresolved"] == 0
