"""C3 — honeytoken detector matches registered canaries in output and tool args."""

from __future__ import annotations

from aegis.contracts import Action, Phase
from aegis.detectors.base import ScanContext
from aegis.detectors.honeytokens import HoneytokenDetector, HoneytokenRegistry
from tests.conftest import response_ctx, tool_ctx


def test_registered_canary_in_text_blocks() -> None:
    reg = HoneytokenRegistry()
    token = reg.register(service="github", session_id="s1")
    detector = HoneytokenDetector(reg)

    result = detector.scan(response_ctx(f"the secret is {token}", session_id="s1"))
    assert result.recommended_action in (Action.BLOCK, Action.ESCALATE)
    assert result.score >= 0.9
    assert result.evidence["service"] == "github"
    assert result.evidence["canary_id"]
    assert result.evidence["location"] == "response"


def test_canary_in_tool_argument_blocks() -> None:
    reg = HoneytokenRegistry()
    token = reg.register(service="aws", session_id="s1")
    detector = HoneytokenDetector(reg)

    result = detector.scan(tool_ctx("send_email", {"body": f"key={token}"}, session_id="s1"))
    assert result.recommended_action in (Action.BLOCK, Action.ESCALATE)
    assert "body" in result.evidence["location"]


def test_unregistered_value_allows() -> None:
    reg = HoneytokenRegistry()
    reg.register(service="github", session_id="s1")
    detector = HoneytokenDetector(reg)

    result = detector.scan(response_ctx("aegis_canary_github_deadbeef_unregistered"))
    assert result.recommended_action == Action.ALLOW
    assert result.score == 0.0


def test_normalized_match_survives_whitespace() -> None:
    reg = HoneytokenRegistry()
    token = reg.register(service="stripe", session_id="s1")
    detector = HoneytokenDetector(reg)

    spaced = " ".join(token)  # canary smeared with spaces
    result = detector.scan(
        ScanContext(session_id="s1", phase=Phase.RESPONSE, text=spaced)
    )
    assert result.recommended_action in (Action.BLOCK, Action.ESCALATE)


def test_planted_canary_in_request_does_not_fire() -> None:
    # Egress-only: a canary present in ingress/request context is the planting site,
    # not a leak. It must only alarm on response/tool-call egress.
    from tests.conftest import request_ctx

    reg = HoneytokenRegistry()
    token = reg.register(service="github", session_id="s1")
    detector = HoneytokenDetector(reg)

    result = detector.scan(request_ctx(f"retrieved doc says: {token}", session_id="s1"))
    assert result.recommended_action == Action.ALLOW


def test_token_only_visible_in_untrusted_context() -> None:
    # Registry exposes the raw token so it can be planted; detection is the point.
    reg = HoneytokenRegistry()
    token = reg.register(service="github", session_id="s1")
    assert token.startswith("aegis_canary_")
    assert reg.is_canary(token)
