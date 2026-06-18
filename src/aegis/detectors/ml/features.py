"""Feature extraction for the ML risk probe (PRD §6.2) — pure Python, no torch.

Turns a normalized event + the deterministic detectors' output into a fixed-length vector.
Kept torch-free so it is testable on the offline gate and the model stays swappable.
"""

from __future__ import annotations

import math
from collections import Counter

from aegis.contracts import Action, DetectorResult, Phase
from aegis.detectors.base import ScanContext

# Fixed order — the trained model depends on this. Append only; never reorder.
FEATURE_NAMES = [
    "detector_hit_count",
    "max_detector_score",
    "mean_detector_score",
    "char_entropy",
    "decoded_payload_indicator",
    "honeytoken_proximity",
    "suspicious_term_count",
    "secret_handle_ref_count",
    "nimbus_cumulative",
    "log_length",
    "is_tool_call",
]
FEATURE_DIM = len(FEATURE_NAMES)

_SUSPICIOUS_TERMS = (
    "ignore previous",
    "exfiltrate",
    "api key",
    "password",
    "send to",
    "base64",
    "secret",
    "token",
    "credential",
    "decode",
)


def _char_entropy(text: str) -> float:
    """Shannon entropy over characters, normalized to ~[0,1] (cap 6 bits)."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    bits = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return min(bits / 6.0, 1.0)


def _non_allow(results: list[DetectorResult]) -> list[DetectorResult]:
    return [r for r in results if r.recommended_action != Action.ALLOW]


def _fired(results: list[DetectorResult], name: str) -> bool:
    return any(r.detector_name == name and r.recommended_action != Action.ALLOW for r in results)


def extract_features(
    ctx: ScanContext,
    detector_results: list[DetectorResult],
    nimbus_cumulative: float,
) -> list[float]:
    """Build the model input vector. Order matches FEATURE_NAMES exactly."""
    text = ctx.text or ""
    low = text.lower()
    scores = [r.score for r in detector_results] or [0.0]
    hits = _non_allow(detector_results)

    return [
        min(len(hits) / 5.0, 1.0),
        max(scores),
        sum(scores) / len(scores),
        _char_entropy(text),
        1.0 if _fired(detector_results, "encoding_scanner") else 0.0,
        1.0 if _fired(detector_results, "honeytoken_detector") else 0.0,
        min(sum(low.count(t) for t in _SUSPICIOUS_TERMS) / 3.0, 1.0),
        min(low.count("secret://") / 2.0, 1.0),
        min(nimbus_cumulative, 1.0),
        min(math.log1p(len(text)) / 8.0, 1.0),
        1.0 if ctx.phase is Phase.TOOL_CALL else 0.0,
    ]
