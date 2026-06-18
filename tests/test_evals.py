"""C13 — eval harness covers the 7 categories with repeatable, deterministic results.

`expect` in each case is the BALANCED-mode contract (observe under-enforces, strict
over-enforces by design), so assertions here target balanced as the headline mode.
"""

from __future__ import annotations

from aegis.evals.cases import (
    ATTACK_CATEGORIES,
    BENIGN_CATEGORIES,
    EvalCase,
    EvalStep,
    load_cases,
)
from aegis.evals.report import write_artifacts
from aegis.evals.runner import run_case, run_suite
from aegis.policy.engine import PolicyMode


def test_all_seven_categories_present() -> None:
    cases = load_cases()
    cats = {c.category for c in cases}
    assert ATTACK_CATEGORIES <= cats
    assert BENIGN_CATEGORIES <= cats


def test_balanced_meets_all_success_criteria(tmp_path) -> None:
    cases = load_cases()
    suite = run_suite(cases, PolicyMode.BALANCED, tmp_path / "traces")
    m = suite.metrics
    assert m["pass_rate"] == 1.0
    assert m["attack_detection_rate"] == 1.0
    assert m["benign_allow_rate"] == 1.0
    assert m["benign_false_blocks"] == 0
    assert m["evidence_completeness"] == 1.0
    assert all(m["success_criteria"].values())


def test_baseline_would_leak_the_attacks(tmp_path) -> None:
    cases = load_cases()
    suite = run_suite(cases, PolicyMode.BALANCED, tmp_path / "traces")
    # The whole point: an unguarded agent leaks on these egress cases; Aegis blocks them.
    assert suite.metrics["baseline_leaked_attacks"] >= 3


def test_observe_mode_never_blocks(tmp_path) -> None:
    cases = load_cases()
    suite = run_suite(cases, PolicyMode.OBSERVE, tmp_path / "traces")
    assert suite.metrics["attack_detection_rate"] == 0.0
    assert suite.metrics["benign_false_blocks"] == 0


def test_drip_case_trips_cumulative_in_balanced(tmp_path) -> None:
    drip = next(c for c in load_cases() if c.category == "multi_turn_drip")
    result = run_case(drip, PolicyMode.BALANCED, tmp_path / "traces")
    assert result.passed
    # First turn warns (below budget); final turn blocks (budget tripped).
    assert result.steps[0].action.value == "WARN"
    assert result.steps[-1].action.value in ("BLOCK", "ESCALATE")


def test_harness_reports_expectation_mismatch(tmp_path) -> None:
    # A benign step that (wrongly) expects a block must be reported as NOT passed.
    bogus = EvalCase(
        id="bogus-001",
        title="benign text wrongly expected to block",
        category="benign_normal",
        steps=[EvalStep(guard="response", text="hello world", expect="block")],
    )
    result = run_case(bogus, PolicyMode.BALANCED, tmp_path / "traces")
    assert result.passed is False


def test_artifacts_written(tmp_path) -> None:
    cases = load_cases()
    suites = {
        "balanced": run_suite(cases, PolicyMode.BALANCED, tmp_path / "traces"),
        "observe": run_suite(cases, PolicyMode.OBSERVE, tmp_path / "traces"),
    }
    paths = write_artifacts(suites, tmp_path / "reports")
    assert paths["markdown"].exists()
    assert paths["jsonl"].exists()
    assert "Success criteria" in paths["markdown"].read_text(encoding="utf-8")
