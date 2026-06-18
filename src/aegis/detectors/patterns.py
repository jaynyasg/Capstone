"""Secret pattern scanner — direct credential shapes in text (C1 / FR-4)."""

from __future__ import annotations

from aegis.contracts import Action, DetectorResult
from aegis.detectors._credutil import find_credentials
from aegis.detectors.base import ScanContext, timed


class SecretPatternScanner:
    name = "secret_pattern_scanner"

    def scan(self, ctx: ScanContext) -> DetectorResult:
        with timed() as elapsed:
            matches = find_credentials(ctx.text)
            ms = elapsed()
        if matches:
            return DetectorResult(
                detector_name=self.name,
                score=0.95,
                confidence=0.95,
                recommended_action=Action.BLOCK,
                evidence={"matches": matches, "count": len(matches)},
                latency_ms=ms,
            )
        return DetectorResult(
            detector_name=self.name,
            score=0.0,
            confidence=0.9,
            recommended_action=Action.ALLOW,
            evidence={"matches": []},
            latency_ms=ms,
        )
