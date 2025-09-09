
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Any, List

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
