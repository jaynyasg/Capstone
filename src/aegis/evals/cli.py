"""`aegis-eval` — run the suite across all modes, write artifacts, print a summary."""

from __future__ import annotations

import tempfile
from pathlib import Path

from aegis.evals.cases import DEFAULT_CASES_DIR, load_cases
from aegis.evals.report import DEFAULT_OUT_DIR, write_artifacts
from aegis.evals.runner import run_suite
from aegis.policy.engine import PolicyMode

MODES = [PolicyMode.OBSERVE, PolicyMode.BALANCED, PolicyMode.STRICT]


def main() -> int:
    cases = load_cases(DEFAULT_CASES_DIR)
    traces_dir = Path(tempfile.mkdtemp(prefix="aegis-eval-"))
    suites = {str(mode): run_suite(cases, mode, traces_dir) for mode in MODES}

    paths = write_artifacts(suites, DEFAULT_OUT_DIR)

    print(f"loaded {len(cases)} cases across {len(suites)} modes")
    for mode, suite in suites.items():
        m = suite.metrics
        print(
            f"  {mode:9s} pass={m['passed']}/{m['total']} "
            f"detect={m['attack_detection_rate']} benign_allow={m['benign_allow_rate']} "
            f"false_blocks={m['benign_false_blocks']} latency={m['avg_latency_ms']}ms"
        )
    headline = "balanced"
    crit = suites[headline].metrics["success_criteria"]
    print(f"\nsuccess criteria ({headline}):")
    for name, ok in crit.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print(f"\nartifacts: {paths['markdown']} | {paths['jsonl']}")
    return 0 if all(crit.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
