from __future__ import annotations

import numpy as np

from apps.gui.src.webapp.entropy_tools import _entropy_from_counts


def test_entropy_counts_all_zero() -> None:
    counts = np.zeros(256, dtype=np.float64)
    assert _entropy_from_counts(counts) == 0.0


def test_entropy_counts_point_mass() -> None:
    counts = np.zeros(256, dtype=np.float64)
    counts[42] = 1000.0
    assert _entropy_from_counts(counts) == 0.0


def test_entropy_counts_uniform() -> None:
    counts = np.ones(256, dtype=np.float64)
    entropy = _entropy_from_counts(counts)
    assert abs(entropy - 8.0) < 1e-12

