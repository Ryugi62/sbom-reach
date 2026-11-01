from sbomreach.adapters.java_source import analyze_java
from sbomreach.domain.packages import modules_for

SRC = '''package demo;

import org.yaml.snakeyaml.Yaml;
import com.alibaba.fastjson.JSON;
import static org.apache.commons.lang3.StringUtils.isBlank;
// import org.fake.Commented;
public class A {
  String s = "import org.fake.InString; Yaml(";
  void f(String x) {
    Yaml y = new Yaml();
    Object o = y.load(x);
    JSON.parseObject(x);
    if (isBlank(x)) { }
  }
}
'''


def test_modules_for_maven_candidates():
    assert "org.yaml.snakeyaml" in modules_for("Maven", "org.yaml:snakeyaml")
    assert "com.alibaba.fastjson" in modules_for("Maven", "com.alibaba:fastjson")
    assert "org.apache.commons.lang3" in modules_for("Maven", "org.apache.commons:commons-lang3")
    assert "org.springframework.web" in modules_for("Maven", "org.springframework:spring-web")
    assert "org.apache.logging.log4j.core" in modules_for("Maven", "org.apache.logging.log4j:log4j-core")


def test_imports_registered_at_every_prefix_with_line_evidence():
    idx = analyze_java({"src/main/java/demo/A.java": SRC})
    assert idx.imports["org.yaml.snakeyaml"][0].line == 3
    assert idx.imports["org.yaml"][0].path.endswith("A.java")
    assert "org.apache.commons.lang3" in idx.imports        # static import 도 import
    assert "org.fake" not in idx.imports                      # 주석·문자열 속 import 는 근거가 아니다


def test_finder_class_use_needs_the_class_to_be_imported_from_the_package():
    idx = analyze_java({"src/main/java/demo/A.java": SRC})
    assert [e.line for e in idx.finder("Yaml", ("org.yaml.snakeyaml",), "class")] == [10, 10] or \
        [e.line for e in idx.finder("Yaml", ("org.yaml.snakeyaml",), "class")] == [10]
    assert idx.finder("Yaml", ("com.alibaba.fastjson",), "class") == []    # 다른 패키지에서 가져온 클래스가 아님


def test_finder_call_only_in_files_importing_the_package():
    files = {"src/main/java/demo/A.java": SRC, "src/main/java/demo/B.java": "package demo;\nclass B { void g(){ load(1); } }\n"}
    idx = analyze_java(files)
    hits = idx.finder("load", ("org.yaml.snakeyaml",), "call")
    assert [(e.path.split("/")[-1], e.line) for e in hits] == [("A.java", 11)]     # B.java 는 import 가 없어 제외
    assert [e.line for e in idx.finder("parseObject", ("com.alibaba.fastjson",), "call")] == [12]


def test_names_inside_comments_and_strings_do_not_count():
    idx = analyze_java({"a/A.java": SRC})
    lines = [e.line for e in idx.finder("Yaml", ("org.yaml.snakeyaml",), "class")]
    assert 8 not in lines and 10 in lines    # 8번 줄 문자열 속 Yaml 은 제외
