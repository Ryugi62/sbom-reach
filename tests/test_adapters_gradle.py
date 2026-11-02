from sbomreach.adapters.gradle_lock import components_from_gradle_lock
from sbomreach.adapters.maven_pom import components_from_poms

LOCK = """# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
org.yaml:snakeyaml:1.30=compileClasspath,runtimeClasspath
com.google.guava:guava:31.0-jre=compileClasspath
junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath
org.yaml:snakeyaml:1.30=runtimeClasspath
bad line
empty=
"""


def test_gradle_lock_reads_group_artifact_version_as_maven_components_deduped():
    comps = components_from_gradle_lock({"app/gradle.lockfile": LOCK})
    names = sorted((c.name, c.version) for c in comps)
    assert ("org.yaml:snakeyaml", "1.30") in names and ("com.google.guava:guava", "31.0-jre") in names
    assert len([c for c in comps if c.name == "org.yaml:snakeyaml"]) == 1
    assert all(c.ecosystem == "Maven" and c.manifest == "app/gradle.lockfile" for c in comps)


def test_gradle_lock_skips_test_only_configurations():
    comps = components_from_gradle_lock({"gradle.lockfile": LOCK})
    assert "junit:junit" not in {c.name for c in comps}


def test_gradle_lock_ignores_other_files_and_noise():
    assert components_from_gradle_lock({"build.gradle": "implementation 'a:b:1'"}) == []
    assert components_from_gradle_lock({"gradle.lockfile": "empty=\n# c\n"}) == []


def test_maven_sbom_merges_pom_and_gradle_lock_components():
    from sbomreach.infrastructure.maven_sbom import MavenSbom
    import tempfile, os
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "gradle.lockfile"), "w").write(LOCK)
        comps, fb = MavenSbom().generate(d)
    assert fb is False and {c.name for c in comps} == {"org.yaml:snakeyaml", "com.google.guava:guava"}
