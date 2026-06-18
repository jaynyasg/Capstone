"""Partial-leak detector — moderate WARN on credential fragments so drip accumulates."""

from __future__ import annotations

from aegis.contracts import Action
from aegis.detectors.partial import PartialLeakDetector
from tests.conftest import FAKE_GITHUB_PAT, request_ctx

detector = PartialLeakDetector()


def test_fragment_warns_not_blocks() -> None:
    result = detector.scan(request_ctx("here is a piece: ghp_0123abcd"))
    assert result.recommended_action == Action.WARN
    assert 0.2 <= result.score < 0.6  # moderate — must not block on its own


def test_full_secret_is_left_to_pattern_scanner() -> None:
    # Avoid double-counting: when the full credential is present, this detector defers.
    result = detector.scan(request_ctx(FAKE_GITHUB_PAT))
    assert result.recommended_action == Action.ALLOW
    assert result.score == 0.0


def test_benign_text_does_not_fire() -> None:
    result = detector.scan(request_ctx("Set GITHUB_TOKEN in your environment, see the docs."))
    assert result.recommended_action == Action.ALLOW


def test_placeholder_fragment_does_not_fire() -> None:
    result = detector.scan(request_ctx("example format: ghp_YOUR_TOKEN_HERE"))
    assert result.recommended_action == Action.ALLOW


def test_contract_fields() -> None:
    result = detector.scan(request_ctx("ghp_0123abcd"))
    assert result.detector_name == "partial_leak_detector"
    assert 0.0 <= result.confidence <= 1.0
    assert result.latency_ms >= 0.0
