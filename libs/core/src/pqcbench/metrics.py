
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Any, List

"""Lightweight benchmark result containers used by batch scripts.

The CLI/GUI primarily return per-operation timing summaries; these dataclasses
are used by the `benchmarks/` scripts for simple aggregation and export.
"""

@dataclass
class MetricRecord:
    algo: str
    op: str  # e.g., 'keygen', 'encapsulate', 'decapsulate', 'sign', 'verify'
    runs: int
    mean_ms: float
    stddev_ms: float
    extra: Dict[str, Any] = field(default_factory=dict)

@dataclass
class BenchmarkResult:
    records: List[MetricRecord]
    notes: str = ""
