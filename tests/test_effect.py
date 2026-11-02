from sbomreach.domain.effect import estimate


def test_effect_labelled_assumption():
    e = estimate(total_alerts=100, reached=10, minutes_per_alert=15, hourly_cost=50000)
    assert e.label.startswith("가정")
    assert e.minutes_saved == 90 * 15  # 도달 아닌 경보를 1차 분류에서 덜 보는 몫
    assert e.cost_saved == e.minutes_saved / 60 * 50000


def test_effect_lower_bound_zero_when_all_reached():
    assert estimate(10, 10, 15, 50000).minutes_saved == 0


def test_sensitivity_gives_hours_for_each_assumed_minute_and_labels_assumption():
    """S16 (v1.4): 가정 5·10·20분마다 전체를 모두 여는 시간 vs 먼저 열 N건만 여는 시간."""
    from sbomreach.domain.effect import sensitivity
    rows = sensitivity(total_alerts=120, first_open=20, minutes=(5, 10, 20))
    assert [r.minutes for r in rows] == [5, 10, 20]
    assert rows[0].all_hours == 10.0 and rows[0].first_hours == round(20 * 5 / 60, 1)
    assert rows[2].all_hours == 40.0 and rows[2].first_hours == round(20 * 20 / 60, 1)
    assert all(r.label.startswith("가정") and "안전" in r.label for r in rows)
    assert rows[1].deferred_hours == round(rows[1].all_hours - rows[1].first_hours, 1)


def test_sensitivity_never_negative_when_first_open_exceeds_total():
    from sbomreach.domain.effect import sensitivity
    assert sensitivity(5, 9, (10,))[0].deferred_hours == 0.0
