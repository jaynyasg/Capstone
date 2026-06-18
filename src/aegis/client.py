"""AegisClient — the SDK guard surface (FR-1). Source of truth for security decisions.

The gateway and dashboard call these same three methods; they never reimplement the
pipeline. Pipeline per turn: Inspect (detectors + broker) -> Score (nimbus ledger) ->
Enforce (policy) -> trace.
"""

from __future__ import annotations

from typing import Any

from aegis.config import Settings
from aegis.contracts import (
    Action,
    AegisDecision,
    AegisEvent,
    DetectorResult,
    Phase,
    TrustBoundary,
    most_severe,
)
from aegis.detectors._credutil import redact_text
from aegis.detectors.base import ScanContext
from aegis.detectors.encodings import EncodingScanner
from aegis.detectors.honeytokens import HoneytokenDetector, HoneytokenRegistry
from aegis.detectors.nimbus import NimbusLedger
from aegis.detectors.partial import PartialLeakDetector
from aegis.detectors.patterns import SecretPatternScanner
from aegis.detectors.tool_args import ToolCallArgumentScanner
from aegis.policy.engine import PolicyEngine
from aegis.secrets.broker import CredentialBroker
from aegis.tracing import Tracer

_SUMMARY_LIMIT = 240


class AegisClient:
    def __init__(
        self,
        settings: Settings | None = None,
        broker: CredentialBroker | None = None,
        registry: HoneytokenRegistry | None = None,
        tracer: Tracer | None = None,
    ) -> None:
        self.settings = settings or Settings.load()
        self.broker = broker or CredentialBroker()
        self.registry = registry or HoneytokenRegistry()
        self.tracer = tracer or Tracer(self.settings.traces_dir)
        self.policy = PolicyEngine(self.settings.policy_mode)

        # Content detectors run on text; tool_args only fires on tool_call phase.
        self._content = [
            SecretPatternScanner(),
            EncodingScanner(),
            HoneytokenDetector(self.registry),
            ToolCallArgumentScanner(self.registry),
            PartialLeakDetector(),
        ]
        self.nimbus = NimbusLedger(
            warn_threshold=self.settings.warn_threshold,
            block_threshold=self.settings.block_threshold,
        )

        # Optional ML risk probe — one auxiliary signal, never authoritative. Loads lazily
        # and degrades to a no-op if torch / the artifact is absent.
        self.ml_probe = None
        if self.settings.enable_ml_probe:
            from aegis.detectors.ml.probe import MLRiskProbe

            self.ml_probe = MLRiskProbe(self.settings.ml_probe_path)

    # ----- guard surface -------------------------------------------------

    def guard_request(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        session_id: str = "default",
        metadata: dict[str, Any] | None = None,
    ) -> AegisDecision:
        text = _messages_to_text(messages)
        ctx = ScanContext(
            session_id=session_id,
            phase=Phase.REQUEST,
            text=text,
            trusted_boundary=TrustBoundary.MIXED,
        )
        return self._guard(ctx, metadata)

    def guard_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        session_id: str = "default",
        metadata: dict[str, Any] | None = None,
    ) -> AegisDecision:
        ctx = ScanContext(
            session_id=session_id,
            phase=Phase.TOOL_CALL,
            text=_args_to_text(arguments),
            tool_name=tool_name,
            tool_arguments=arguments,
            trusted_boundary=TrustBoundary.MIXED,
        )
        return self._guard(ctx, metadata)

    def guard_response(
        self,
        output: str,
        session_id: str = "default",
        metadata: dict[str, Any] | None = None,
    ) -> AegisDecision:
        ctx = ScanContext(
            session_id=session_id,
            phase=Phase.RESPONSE,
            text=output,
            trusted_boundary=TrustBoundary.UNTRUSTED,
        )
        return self._guard(ctx, metadata)

    # ----- pipeline ------------------------------------------------------

    def _guard(self, ctx: ScanContext, metadata: dict[str, Any] | None) -> AegisDecision:
        results = [d.scan(ctx) for d in self._content]

        # Credential broker: raw secret in model-visible context is authoritative.
        assessment = self.broker.assess_context(
            ctx.text, local_test_mode=self.settings.local_test_mode
        )
        if assessment.raw_secret_present:
            results.append(_broker_result(assessment.forced_action, assessment.leaked_handles))

        # Score: this turn's leakage feeds the cumulative session ledger.
        turn_score = max((r.score for r in results), default=0.0)
        nimbus_result = self.nimbus.record(ctx.session_id, turn_score)
        results.append(nimbus_result)

        # Optional ML probe — consumes the deterministic signals + cumulative score, adds
        # one more (non-authoritative, WARN-capped) input. Never feeds back into Nimbus.
        if self.ml_probe is not None:
            results.append(
                self.ml_probe.score(ctx, results, self.nimbus.cumulative(ctx.session_id))
            )

        # Enforce.
        decision = self.policy.decide(results)
        decision = _apply_broker_override(decision, assessment)

        event = self._build_event(ctx, results, decision, assessment, metadata)
        trace_path = self.tracer.record(event)
        decision.trace_id = event.event_id
        if not decision.allowed and trace_path is not None:
            decision.reasons.append(f"trace={trace_path.name}")
        return decision

    def _build_event(
        self,
        ctx: ScanContext,
        results: list[DetectorResult],
        decision: AegisDecision,
        assessment,
        metadata: dict[str, Any] | None,
    ) -> AegisEvent:
        summary = redact_text(ctx.text)[:_SUMMARY_LIMIT]
        meta = dict(metadata or {})
        meta["policy_mode"] = self.settings.policy_mode
        if assessment.critical:
            meta["critical"] = True
            meta["raw_secret_leaked_handles"] = assessment.leaked_handles
        return AegisEvent(
            session_id=ctx.session_id,
            phase=ctx.phase,
            trusted_boundary=ctx.trusted_boundary,
            input_summary=summary,
            tool_name=ctx.tool_name,
            tool_arguments=_redact_args(ctx.tool_arguments),
            detector_evidence=results,
            policy_decision=decision,
            metadata=meta,
        )


def _broker_result(forced: Action | None, handles: list[str]) -> DetectorResult:
    return DetectorResult(
        detector_name="credential_broker",
        score=1.0,
        confidence=1.0,
        recommended_action=forced or Action.WARN,
        evidence={"raw_secret_in_context": True, "leaked_handles": handles},
    )


def _apply_broker_override(decision: AegisDecision, assessment) -> AegisDecision:
    """Broker authority: a forced action overrides even observe mode (PRD §6.5)."""
    if assessment.forced_action is None:
        return decision
    decision.action = most_severe([decision.action, assessment.forced_action])
    decision.risk_score = max(decision.risk_score, 1.0)
    decision.reasons.append("credential_broker: raw secret in model-visible context")
    return decision


def _messages_to_text(messages: list[dict[str, Any]]) -> str:
    return "\n".join(f"{m.get('role', '?')}: {m.get('content', '')}" for m in messages)


def _args_to_text(arguments: dict[str, Any]) -> str:
    return "\n".join(f"{k}={v}" for k, v in (arguments or {}).items())


def _redact_args(arguments: dict[str, Any] | None) -> dict[str, Any] | None:
    if not arguments:
        return arguments
    return {k: redact_text(str(v)) for k, v in arguments.items()}
