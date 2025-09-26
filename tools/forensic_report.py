#!/usr/bin/env python3
"""Post-process forensic probe outputs to highlight likely side-channel risks.

Usage:
    python tools/forensic_report.py results/forensic_quick.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

SEVERITY_THRESHOLDS = {
    0: "info",
    1: "medium",
    2: "high",
    3: "critical",
}

SEVERITY_LEVELS = {"info": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class LeakIndicator:
    metric: str
    description: str
    value: float
    pvalue: Optional[float]
    mutual_information: Optional[float]
    mi_pvalue: Optional[float]


@dataclass
class ScenarioLeakReport:
    algorithm: str
    parameter: Optional[str]
    scenario: str
    severity: str
    indicators: List[LeakIndicator]


@dataclass
class AlgorithmSummary:
    algorithm: str
    parameter: Optional[str]
    severity: str
    scenarios: List[ScenarioLeakReport]


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarise forensic probe leakage flags.")
    parser.add_argument("input", type=pathlib.Path, help="Path to forensic JSON output")
    parser.add_argument("--format", choices={"text", "markdown", "json"}, default="text", help="Output format")
    parser.add_argument("--output", type=pathlib.Path, help="Optional file to write the report")
    return parser.parse_args(argv)


def load_forensic_report(path: pathlib.Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def build_leak_report(data: Dict[str, Any]) -> List[AlgorithmSummary]:
    analysis_entries = data.get("analysis", [])
    summaries: Dict[str, AlgorithmSummary] = {}
    for entry in analysis_entries:
        algorithm = entry.get("algorithm")
        parameter = entry.get("parameter_name")
        scenario = entry.get("scenario_name")
        metrics: Dict[str, Any] = entry.get("metrics", {})
        indicators: List[LeakIndicator] = []

        if metrics.get("time_leak_flag"):
            indicators.append(
                LeakIndicator(
                    metric="time",
                    description="Timing variance between leakage classes exceeds TVLA threshold",
                    value=abs(metrics.get("t_stat_time", 0.0)),
                    pvalue=metrics.get("t_pvalue_time"),
                    mutual_information=metrics.get("mi_time"),
                    mi_pvalue=metrics.get("mi_pvalue_time"),
                )
            )
        if metrics.get("cpu_leak_flag"):
            indicators.append(
                LeakIndicator(
                    metric="cpu",
                    description="CPU usage differences significant across classes",
                    value=abs(metrics.get("t_stat_cpu", 0.0)),
                    pvalue=metrics.get("t_pvalue_cpu"),
                    mutual_information=metrics.get("mi_cpu"),
                    mi_pvalue=metrics.get("mi_pvalue_cpu"),
                )
            )
        if metrics.get("rss_leak_flag"):
            indicators.append(
                LeakIndicator(
                    metric="rss",
                    description="Memory-resident footprint varies with leakage classification",
                    value=abs(metrics.get("t_stat_rss", 0.0)),
                    pvalue=metrics.get("t_pvalue_rss"),
                    mutual_information=metrics.get("mi_rss"),
                    mi_pvalue=metrics.get("mi_pvalue_rss"),
                )
            )

        if not indicators:
            continue

        indicator_count = min(len(indicators), max(SEVERITY_THRESHOLDS))
        severity = SEVERITY_THRESHOLDS.get(indicator_count, "high")
        scenario_report = ScenarioLeakReport(
            algorithm=algorithm,
            parameter=parameter,
            scenario=scenario,
            severity=severity,
            indicators=indicators,
        )
        key = f"{algorithm}::{parameter}"
        summary = summaries.setdefault(
            key,
            AlgorithmSummary(
                algorithm=algorithm,
                parameter=parameter,
                severity="info",
                scenarios=[],
            ),
        )
        current_level = SEVERITY_LEVELS.get(summary.severity, 0)
        new_level = SEVERITY_LEVELS.get(severity, current_level)
        if new_level > current_level:
            summary.severity = severity
        summary.scenarios.append(scenario_report)
    return list(summaries.values())


def format_indicator(indicator: LeakIndicator) -> str:
    base = f"- {indicator.metric.upper()} leak: {indicator.description} (|t|={indicator.value:.2f})"
    extras = []
    if indicator.pvalue is not None:
        extras.append(f"p={indicator.pvalue:.2e}")
    if indicator.mutual_information is not None:
        extras.append(f"MI={indicator.mutual_information:.4f}")
    if indicator.mi_pvalue is not None:
        extras.append(f"MI-p={indicator.mi_pvalue:.2e}")
    if extras:
        base += " [" + ", ".join(extras) + "]"
    return base


def render_text(summaries: List[AlgorithmSummary]) -> str:
    lines: List[str] = []
    if not summaries:
        return "No leakage indicators found."
    for summary in summaries:
        header = f"Algorithm: {summary.algorithm} ({summary.parameter or 'parameter unknown'}) | Severity: {summary.severity}"
        lines.append(header)
        for scenario in summary.scenarios:
            lines.append(f"  Scenario: {scenario.scenario} (severity: {scenario.severity})")
            for indicator in scenario.indicators:
                lines.append("    " + format_indicator(indicator))
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def render_markdown(summaries: List[AlgorithmSummary]) -> str:
    if not summaries:
        return "No leakage indicators found."
    sections: List[str] = []
    for summary in summaries:
        section_lines = [f"### {summary.algorithm} ({summary.parameter or 'parameter unknown'}) — {summary.severity.title()} risk"]
        for scenario in summary.scenarios:
            section_lines.append(f"- **Scenario:** `{scenario.scenario}` ({scenario.severity})")
            for indicator in scenario.indicators:
                section_lines.append(f"  {format_indicator(indicator)}")
        sections.append("\n".join(section_lines))
    return "\n\n".join(sections) + "\n"


def render_json(summaries: List[AlgorithmSummary]) -> str:
    payload = []
    for summary in summaries:
        payload.append(
            {
                "algorithm": summary.algorithm,
                "parameter": summary.parameter,
                "severity": summary.severity,
                "scenarios": [
                    {
                        "scenario": scenario.scenario,
                        "severity": scenario.severity,
                        "indicators": [
                            {
                                "metric": indicator.metric,
                                "description": indicator.description,
                                "t_stat_abs": indicator.value,
                                "pvalue": indicator.pvalue,
                                "mutual_information": indicator.mutual_information,
                                "mi_pvalue": indicator.mi_pvalue,
                            }
                            for indicator in scenario.indicators
                        ],
                    }
                    for scenario in summary.scenarios
                ],
            }
        )
    return json.dumps(payload, indent=2)


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    report_data = load_forensic_report(args.input)
    summaries = build_leak_report(report_data)
    if args.format == "text":
        output = render_text(summaries)
    elif args.format == "markdown":
        output = render_markdown(summaries)
    else:
        output = render_json(summaries)
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
