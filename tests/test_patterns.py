"""C1 — secret pattern scanner flags real credential shapes, ignores benign look-alikes."""

from __future__ import annotations

import pytest

from aegis.contracts import Action
from aegis.detectors.patterns import SecretPatternScanner
from tests.conftest import (
    AWS_DOC_EXAMPLE,
    FAKE_AWS_KEY,
    FAKE_CONN_STRING,
    FAKE_GITHUB_PAT,
    FAKE_OPENAI_KEY,
    FAKE_PEM,
    PLACEHOLDER_PAT,
    PLACEHOLDER_TEXT,
    request_ctx,
)

scanner = SecretPatternScanner()


@pytest.mark.parametrize(
    "secret,kind",
    [
        (FAKE_GITHUB_PAT, "github_pat"),
        (FAKE_OPENAI_KEY, "openai_key"),
        (FAKE_AWS_KEY, "aws_access_key"),
        (FAKE_PEM, "private_key_block"),
        (FAKE_CONN_STRING, "connection_string"),
    ],
)
def test_flags_credentials(secret: str, kind: str) -> None:
    result = scanner.scan(request_ctx(f"Here is the value: {secret}"))
    assert result.detector_name == "secret_pattern_scanner"
    assert result.score >= 0.7
    assert result.recommended_action in (Action.BLOCK, Action.ESCALATE)
    kinds = {m["kind"] for m in result.evidence["matches"]}
    assert kind in kinds


def test_contract_fields_present() -> None:
    result = scanner.scan(request_ctx(FAKE_GITHUB_PAT))
    assert 0.0 <= result.score <= 1.0
    assert 0.0 <= result.confidence <= 1.0
    assert result.latency_ms >= 0.0
    assert isinstance(result.evidence, dict)


@pytest.mark.parametrize(
    "benign",
    [PLACEHOLDER_PAT, AWS_DOC_EXAMPLE, PLACEHOLDER_TEXT, "just a normal sentence", ""],
)
def test_ignores_benign(benign: str) -> None:
    result = scanner.scan(request_ctx(benign))
    assert result.recommended_action == Action.ALLOW
    assert result.score < 0.5


def test_redacts_preview() -> None:
    # Evidence previews must not contain the full secret verbatim.
    result = scanner.scan(request_ctx(FAKE_GITHUB_PAT))
    blob = str(result.evidence)
    assert FAKE_GITHUB_PAT not in blob
