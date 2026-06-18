"""C6 — policy engine maps detector evidence to actions under observe/balanced/strict."""

from __future__ import annotations

from aegis.contracts import Action, DetectorResult
from aegis.policy.engine import PolicyEngine, PolicyMode


def _hit(action: Action, score: float, confidence: float) -> DetectorResult:
    return DetectorResult(
        detector_name="t",
        score=score,
        confidence=confidence,
        recommended_action=action,
    )


def test_observe_never_blocks_but_records() -> None:
    engine = PolicyEngine(PolicyMode.OBSERVE)
    decision = engine.decide([_hit(Action.BLOCK, 0.95, 1.0)])
    assert decision.action == Action.ALLOW
    assert decision.risk_score >= 0.9  # still recorded
    assert decision.detector_hits  # evidence retained


def test_balanced_blocks_high_confidence_leak() -> None:
    engine = PolicyEngine(PolicyMode.BALANCED)
    decision = engine.decide([_hit(Action.BLOCK, 0.95, 0.95)])
    assert decision.action == Action.BLOCK


def test_balanced_downgrades_low_confidence_to_warn() -> None:
    engine = PolicyEngine(PolicyMode.BALANCED)
    decision = engine.decide([_hit(Action.BLOCK, 0.6, 0.3)])
    assert decision.action == Action.WARN


def test_strict_blocks_ambiguous_but_high_score() -> None:
    engine = PolicyEngine(PolicyMode.STRICT)
    decision = engine.decide([_hit(Action.WARN, 0.6, 0.4)])
    assert decision.action == Action.BLOCK


def test_most_severe_wins() -> None:
    engine = PolicyEngine(PolicyMode.BALANCED)
    decision = engine.decide(
        [_hit(Action.ALLOW, 0.0, 1.0), _hit(Action.WARN, 0.4, 0.9), _hit(Action.BLOCK, 0.9, 0.9)]
    )
    assert decision.action == Action.BLOCK


def test_empty_evidence_allows() -> None:
    for mode in PolicyMode:
        decision = PolicyEngine(mode).decide([])
        assert decision.action == Action.ALLOW
        assert decision.risk_score == 0.0


def test_non_allow_decision_has_reason() -> None:
    engine = PolicyEngine(PolicyMode.BALANCED)
    decision = engine.decide([_hit(Action.BLOCK, 0.95, 0.95)])
    assert decision.reasons  # explainability: every non-allow must carry a reason
