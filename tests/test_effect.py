from sbomreach.domain.effect import estimate


def test_effect_labelled_assumption():
    e = estimate(total_alerts=100, reached=10, minutes_per_alert=15, hourly_cost=50000)
    assert e.label.startswith("가정")
    assert e.minutes_saved == 90 * 15  # 도달 아닌 경보를 1차 분류에서 덜 보는 몫
    assert e.cost_saved == e.minutes_saved / 60 * 50000


def test_effect_lower_bound_zero_when_all_reached():
    assert estimate(10, 10, 15, 50000).minutes_saved == 0
