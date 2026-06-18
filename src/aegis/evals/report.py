"""Eval artifacts — required local JSONL + Markdown summary (PRD §7.3 fallback)."""

from __future__ import annotations

import json
from pathlib import Path

from aegis.evals.runner import SuiteResult

DEFAULT_OUT_DIR = Path("evals/reports")


def write_artifacts(suites: dict[str, SuiteResult], out_dir: Path | str = DEFAULT_OUT_DIR) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    jsonl_path = out / "results.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for mode, suite in suites.items():
            for case in suite.cases:
                fh.write(
                    json.dumps(
                        {
                            "mode": mode,
                            "id": case.id,
                            "category": case.category,
                            "severity": case.severity,
                            "passed": case.passed,
                            "worst_action": str(case.worst_action),
                            "baseline_leaked": case.baseline_leaked,
                            "steps": [
                                {
                                    "guard": s.guard,
                                    "expect": s.expect,
                                    "action": str(s.action),
                                    "met": s.met,
                                    "fired": s.fired,
                                }
                                for s in case.steps
                            ],
                        }
                    )
                    + "\n"
                )

    md_path = out / "summary.md"
    md_path.write_text(render_markdown(suites), encoding="utf-8")

    # Machine-readable aggregates for the dashboard (no recompute needed downstream).
    metrics_path = out / "metrics.json"
    metrics_path.write_text(
        json.dumps({mode: suite.metrics for mode, suite in suites.items()}, indent=2),
        encoding="utf-8",
    )
    return {"jsonl": jsonl_path, "markdown": md_path, "metrics": metrics_path}


def render_markdown(suites: dict[str, SuiteResult]) -> str:
    modes = list(suites)
    lines: list[str] = ["# Aegis Eval Report", ""]

    # Headline metrics per mode.
    lines += ["## Summary by policy mode", ""]
    lines += ["| Metric | " + " | ".join(modes) + " |"]
    lines += ["| --- |" + " --- |" * len(modes)]
    rows = [
        ("pass rate", "pass_rate"),
        ("attack detection rate", "attack_detection_rate"),
        ("benign allow rate", "benign_allow_rate"),
        ("benign false blocks", "benign_false_blocks"),
        ("evidence completeness", "evidence_completeness"),
        ("avg latency (ms)", "avg_latency_ms"),
    ]
    for label, key in rows:
        cells = " | ".join(str(suites[m].metrics[key]) for m in modes)
        lines.append(f"| {label} | {cells} |")

    # Success criteria (balanced is the headline mode).
    headline = "balanced" if "balanced" in suites else modes[0]
    lines += ["", f"## Success criteria ({headline} mode)", ""]
    for crit, ok in suites[headline].metrics["success_criteria"].items():
        lines.append(f"- [{'x' if ok else ' '}] {crit}")

    # Baseline vs protected (PRD §7.4).
    lines += ["", f"## Baseline vs protected ({headline})", "",
              "| Case | Category | Baseline | Aegis |", "| --- | --- | --- | --- |"]
    for case in suites[headline].cases:
        if not case.is_attack:
            continue
        baseline = "LEAKS" if case.baseline_leaked else "—"
        lines.append(f"| {case.id} | {case.category} | {baseline} | {case.worst_action} |")

    # Detector hit distribution.
    dist = suites[headline].metrics["detector_hit_distribution"]
    lines += ["", f"## Detector hit distribution ({headline})", ""]
    for name, count in sorted(dist.items(), key=lambda kv: -kv[1]):
        lines.append(f"- {name}: {count}")

    return "\n".join(lines) + "\n"
