"""Policy engine (C6 / FR-8) — map detector evidence to one action under three modes.

MVP combinator: rules are independent; the engine takes the most severe effective action.
No nested logic (PRD §6.3).
"""

from __future__ import annotations

from enum import StrEnum

from aegis.contracts import Action, AegisDecision, DetectorResult, most_severe

# Confidence below which a balanced-mode block is downgraded to a warning.
_BALANCED_CONFIDENCE_FLOOR = 0.7
# Score at/above which strict mode elevates any non-allow signal to a block.
_STRICT_ELEVATE_SCORE = 0.5


class PolicyMode(StrEnum):
    OBSERVE = "observe"
    BALANCED = "balanced"
    STRICT = "strict"


class PolicyEngine:
    def __init__(self, mode: PolicyMode | str = PolicyMode.BALANCED) -> None:
        self.mode = PolicyMode(mode)

    def decide(self, results: list[DetectorResult]) -> AegisDecision:
        risk = max((r.score for r in results), default=0.0)

        if self.mode is PolicyMode.OBSERVE:
            # Record everything; never block.
            return AegisDecision(
                action=Action.ALLOW,
                risk_score=risk,
                reasons=[],
                detector_hits=results,
            )

        effective = [self._effective(r) for r in results]
        action = most_severe(effective)
        reasons = [
            self._reason(r, eff)
            for r, eff in zip(results, effective, strict=True)
            if eff.is_non_allow()
        ]
        return AegisDecision(
            action=action,
            risk_score=risk,
            reasons=reasons,
            detector_hits=results,
        )

    def _effective(self, r: DetectorResult) -> Action:
        rec = r.recommended_action
        if self.mode is PolicyMode.BALANCED:
            # High-confidence signals are authoritative; low-confidence caps at WARN.
            if rec.severity > Action.WARN.severity and r.confidence < _BALANCED_CONFIDENCE_FLOOR:
                return Action.WARN
            return rec
        # STRICT: conservative posture — elevate any non-allow signal with real score.
        if rec is not Action.ALLOW and r.score >= _STRICT_ELEVATE_SCORE:
            return max(rec, Action.BLOCK, key=lambda a: a.severity)
        return rec

    @staticmethod
    def _reason(r: DetectorResult, eff: Action) -> str:
        return (
            f"{r.detector_name} -> {eff.value} "
            f"(rec={r.recommended_action.value}, score={r.score:.2f}, conf={r.confidence:.2f})"
        )
