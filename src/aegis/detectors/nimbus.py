"""Nimbus-lite leakage ledger (C5 / FR-7).

A per-session cumulative risk signal for low-rate multi-turn leakage — NOT a formal
information-flow bound (PRD §12 claim discipline). Each turn's score is added to the
session total; crossing thresholds escalates the recommended action.
"""

from __future__ import annotations

from aegis.contracts import Action, DetectorResult
from aegis.detectors.base import timed


class NimbusLedger:
    name = "nimbus_lite_ledger"

    def __init__(self, warn_threshold: float = 0.6, block_threshold: float = 1.0) -> None:
        self.warn_threshold = warn_threshold
        self.block_threshold = block_threshold
        self._cumulative: dict[str, float] = {}

    def cumulative(self, session_id: str) -> float:
        return self._cumulative.get(session_id, 0.0)

    def record(self, session_id: str, turn_score: float) -> DetectorResult:
        with timed() as elapsed:
            total = self._cumulative.get(session_id, 0.0) + turn_score
            self._cumulative[session_id] = total
            if total >= self.block_threshold:
                action = Action.BLOCK
            elif total >= self.warn_threshold:
                action = Action.WARN
            else:
                action = Action.ALLOW
            ms = elapsed()
        return DetectorResult(
            detector_name=self.name,
            score=min(total / self.block_threshold, 1.0) if self.block_threshold else 0.0,
            confidence=0.8,
            recommended_action=action,
            evidence={
                "turn_score": turn_score,
                "cumulative_score": total,
                "warn_threshold": self.warn_threshold,
                "block_threshold": self.block_threshold,
                "session_id": session_id,
            },
            latency_ms=ms,
        )
