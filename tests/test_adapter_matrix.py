from sbomreach.application.adapter_matrix import PROBES, render_matrix_md, run_probes


def test_every_probe_has_label_files_and_expected_count():
    assert len(PROBES) >= 8
    for p in PROBES:
        assert p.label and p.files and p.expected >= 1 and p.kind in ("maven", "syft")
    assert len({p.label for p in PROBES}) == len(PROBES)


def test_run_probes_writes_fixture_files_and_classifies_read_partial_none(tmp_path):
    seen = []

    def fake(kind, root):
        import os
        names = sorted(os.listdir(root))
        seen.append((kind, names))
        # 첫 probe는 전부, 둘째는 일부, 나머지는 0
        return (PROBES[0].expected if len(seen) == 1 else 1 if len(seen) == 2 else 0), 0
    res = run_probes(fake, str(tmp_path))
    assert len(res) == len(PROBES) and len(seen) == len(PROBES) + sum(p.kind == 'syft' for p in PROBES)
    assert res[0].status == "읽는다" and res[1].status == "일부만 읽는다" and res[2].status == "못 읽는다"
    assert all(r.measured for r in res)
    assert all((r.found_nosyft is not None) == (p.kind == "syft") for r, p in zip(res, PROBES))


def test_unmeasured_advisory_check_is_marked_not_faked(tmp_path):
    res = run_probes(lambda k, r: (1, 0), str(tmp_path), advisories_fn=None)
    priv = [r for r in res if "사설" in r.label][0]
    assert priv.advisories is None
    md = render_matrix_md(res)
    assert "미실측" in md and priv.label in md


def test_private_registry_zero_advisories_is_stated_not_called_safe(tmp_path):
    res = run_probes(lambda k, r: (1, 0), str(tmp_path), advisories_fn=lambda name, ver, eco: 0)
    priv = [r for r in res if "사설" in r.label][0]
    assert priv.advisories == 0
    md = render_matrix_md(res)
    assert "안전이 아니다" in md
