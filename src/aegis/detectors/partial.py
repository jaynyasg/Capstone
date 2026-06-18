"""Partial-leak detector — moderate WARN on credential *fragments* (drip fuel for Nimbus).

A single fragment is below the per-turn blocking bar, but its score accumulates in the
session ledger, so low-rate multi-turn leakage trips the cumulative budget (PRD §7.1 drip).
Defers to the full secret_pattern_scanner when a complete credential is present.
"""

from __future__ import annotations

import re

from aegis.contracts import Action, DetectorResult
from aegis.detectors._credutil import _looks_placeholder, find_credentials, redact
from aegis.detectors.base import ScanContext, timed

# Credential prefixes followed by a short-but-nontrivial run (not a full credential).
_FRAGMENT = re.compile(r"(ghp_|sk-proj-|sk-|AKIA|xox[baprs]-)([A-Za-z0-9_-]{4,})")

_FRAGMENT_SCORE = 0.4


class PartialLeakDetector:
    name = "partial_leak_detector"

    def scan(self, ctx: ScanContext) -> DetectorResult:
        with timed() as elapsed:
            action, evidence = self._evaluate(ctx.text)
            ms = elapsed()
        score = _FRAGMENT_SCORE if action is Action.WARN else 0.0
        return DetectorResult(
            detector_name=self.name,
            score=score,
            confidence=0.5,
            recommended_action=action,
            evidence=evidence,
            latency_ms=ms,
        )

    def _evaluate(self, text: str) -> tuple[Action, dict]:
        if not text or find_credentials(text):
            # Empty, or a full credential the pattern scanner already owns.
            return Action.ALLOW, {}
        for m in _FRAGMENT.finditer(text):
            fragment = m.group(0)
            if _looks_placeholder(fragment, m.group(2)):
                continue
            return Action.WARN, {"prefix": m.group(1), "preview": redact(fragment)}
        return Action.ALLOW, {}
