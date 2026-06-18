"""C5 — Nimbus-lite ledger accumulates per-session leakage and trips thresholds."""

from __future__ import annotations

from aegis.contracts import Action
from aegis.detectors.nimbus import NimbusLedger


def test_low_rate_drip_trips_threshold() -> None:
    ledger = NimbusLedger(warn_threshold=0.6, block_threshold=1.0)

    r1 = ledger.record("s1", turn_score=0.4)
    assert r1.recommended_action == Action.ALLOW  # 0.4 cumulative

    r2 = ledger.record("s1", turn_score=0.4)
    assert r2.recommended_action == Action.WARN  # 0.8 cumulative

    r3 = ledger.record("s1", turn_score=0.4)
    assert r3.recommended_action in (Action.BLOCK, Action.ESCALATE)  # 1.2 cumulative
    assert r3.evidence["cumulative_score"] >= 1.0
    assert r3.evidence["session_id"] == "s1"
    assert r3.evidence["turn_score"] == 0.4


def test_sessions_are_isolated() -> None:
    ledger = NimbusLedger(warn_threshold=0.6, block_threshold=1.0)
    ledger.record("s1", turn_score=0.9)
    other = ledger.record("s2", turn_score=0.1)
    assert other.recommended_action == Action.ALLOW
    assert other.evidence["cumulative_score"] == 0.1


def test_benign_session_stays_allow() -> None:
    ledger = NimbusLedger()
    for _ in range(5):
        result = ledger.record("calm", turn_score=0.0)
    assert result.recommended_action == Action.ALLOW
    assert result.evidence["cumulative_score"] == 0.0


def test_contract_fields() -> None:
    ledger = NimbusLedger()
    result = ledger.record("s", turn_score=0.5)
    assert result.detector_name == "nimbus_lite_ledger"
    assert 0.0 <= result.score <= 1.0
    assert "warn_threshold" in result.evidence
    assert "block_threshold" in result.evidence
