
from pqcbench import registry
from pqcbench_cli.runners.common import measure


def _noop() -> None:
    return None

def test_registry_has_placeholders():
    items = registry.list()
    assert "rsa-oaep" in items
    assert "rsa-pss" in items
    assert "kyber" in items
    assert "bike" in items
    assert "classic-mceliece" in items
    assert "frodokem" in items
    assert "ntru" in items
    assert "ntruprime" in items
    assert "dilithium" in items


def test_measure_reports_extended_stats():
    stats = measure(_noop, runs=3)
    assert stats.median_ms >= 0.0
    assert stats.range_ms >= 0.0
    assert stats.stddev_ms >= 0.0
    assert stats.ci95_low_ms <= stats.mean_ms <= stats.ci95_high_ms
    if stats.mem_series_kb:
        assert stats.mem_mean_kb is not None
        assert stats.mem_median_kb is not None
        assert stats.mem_range_kb is not None
        assert stats.mem_stddev_kb is not None
        assert stats.mem_range_kb >= 0.0
        assert stats.mem_ci95_low_kb is not None
        assert stats.mem_ci95_high_kb is not None
        assert stats.mem_ci95_low_kb <= stats.mem_mean_kb <= stats.mem_ci95_high_kb
    else:
        assert stats.mem_mean_kb is None
        assert stats.mem_median_kb is None
        assert stats.mem_range_kb is None
        assert stats.mem_stddev_kb is None
        assert stats.mem_ci95_low_kb is None
        assert stats.mem_ci95_high_kb is None
