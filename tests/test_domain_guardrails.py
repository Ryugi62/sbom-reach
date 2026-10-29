from sbomreach.domain import guardrails as g
from sbomreach.domain.models import Verdict


def test_g2_blocks_unknown_version_number():
    r = g.check_llm_text("lodash를 9.9.9로 올리세요", allowed_versions={"4.17.4", "4.17.21"}, verdict=Verdict.REACHED)
    assert not r.ok and r.rule == "G2"


def test_g2_passes_allowed_versions():
    r = g.check_llm_text("lodash를 4.17.4에서 4.17.21로 올리세요", {"4.17.4", "4.17.21"}, Verdict.REACHED)
    assert r.ok


def test_g3_blocks_safe_claims():
    for t in ("이 경보는 안전합니다", "취약하지 않습니다", "위험 없음"):
        assert not g.check_llm_text(t, set(), Verdict.USED).ok


def test_g3_blocks_reached_claim_when_not_reached():
    r = g.check_llm_text("취약 함수가 도달 가능합니다", set(), Verdict.UNSEEN)
    assert not r.ok and r.rule == "G3"
    assert g.check_llm_text("취약 함수가 도달 가능합니다", set(), Verdict.REACHED).ok


def test_g4_readonly_commands():
    assert g.check_command(["syft", "scan", "dir:/x", "-o", "cyclonedx-json"]).ok
    assert g.check_command(["npm", "install", "--package-lock-only", "--ignore-scripts"]).ok
    assert not g.check_command(["npm", "install"]).ok
    assert not g.check_command(["pip", "install", "-r", "requirements.txt"]).ok
    assert not g.check_command(["python3", "app.py"]).ok
    assert not g.check_command(["node", "server.js"]).ok
    assert not g.check_command(["sh", "-c", "rm -rf /"]).ok


def test_g5_masks_secrets_before_llm():
    s = "key=AIzaSyA1234567890abcdefghijklmnopqrstuv mail me@x.com token ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    m = g.mask_secrets(s)
    assert "AIza" not in m and "me@x.com" not in m and "ghp_" not in m


def test_g6_incomplete_scan_cannot_report_zero_as_safe():
    assert g.safe_to_say_clean(alert_count=0, scan_incomplete=True) is False
    assert g.safe_to_say_clean(alert_count=0, scan_incomplete=False) is True
    assert g.safe_to_say_clean(alert_count=3, scan_incomplete=False) is False
