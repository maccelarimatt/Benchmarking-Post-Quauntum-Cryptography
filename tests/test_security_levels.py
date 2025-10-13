from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
CORE_SRC = ROOT / "libs" / "core" / "src"
core_str = str(CORE_SRC)
if core_str not in sys.path:
    sys.path.insert(0, core_str)

from pqcbench.security_levels import resolve_security_override  # noqa: E402


def test_ntruprime_category_one_maps_to_sntrup653():
    override = resolve_security_override("ntruprime", 1)
    assert override is not None, "expected override for NTRU-Prime category 1"
    assert override.value == "sntrup653"
    assert override.applied_category == 1
    assert override.matched


def test_ntruprime_category_five_maps_to_sntrup1277():
    override = resolve_security_override("ntruprime", 5)
    assert override is not None, "expected override for NTRU-Prime category 5"
    assert override.value == "sntrup1277"
    assert override.applied_category == 5
