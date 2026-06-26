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
    CanaryPlant,
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
from aegis.policy.engine import PolicyEngine, PolicyMode
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
        self._maybe_attach_canary_vault()
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
        policy_mode: PolicyMode | str | None = None,
    ) -> AegisDecision:
        text = _messages_to_text(messages)
        ctx = ScanContext(
            session_id=session_id,
            phase=Phase.REQUEST,
            text=text,
            trusted_boundary=TrustBoundary.MIXED,
        )
        return self._guard(ctx, metadata, policy_mode)

    def guard_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        session_id: str = "default",
        metadata: dict[str, Any] | None = None,
        policy_mode: PolicyMode | str | None = None,
    ) -> AegisDecision:
        ctx = ScanContext(
            session_id=session_id,
            phase=Phase.TOOL_CALL,
            text=_args_to_text(arguments),
            tool_name=tool_name,
            tool_arguments=arguments,
            trusted_boundary=TrustBoundary.MIXED,
        )
        return self._guard(ctx, metadata, policy_mode)

    def guard_response(
        self,
        output: str,
        session_id: str = "default",
        metadata: dict[str, Any] | None = None,
        policy_mode: PolicyMode | str | None = None,
    ) -> AegisDecision:
        ctx = ScanContext(
            session_id=session_id,
            phase=Phase.RESPONSE,
            text=output,
            trusted_boundary=TrustBoundary.UNTRUSTED,
        )
        return self._guard(ctx, metadata, policy_mode)

    def plant_canary(
        self,
        service: str,
        session_id: str = "default",
        location: str = "model_context",
        format_slug: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CanaryPlant:
        """Create a honeytoken and trace its placement into model-visible context.

        The raw token is returned to the caller so it can be inserted into retrieved
        context or a prompt. Traces store only canary id and placement metadata.
        """
        token = self.registry.register(
            service, session_id, plant_location=location, format_slug=format_slug
        )
        ht = self.registry.get(token)
        if ht is None:  # defensive; register/get share the same in-memory registry.
            raise RuntimeError("registered canary was not retrievable")

        decision = AegisDecision(
            action=Action.ALLOW,
            risk_score=0.0,
            reasons=["canary planted into model-visible context"],
        )
        meta = dict(metadata or {})
        meta.update(
            {
                "event_type": "canary_planted",
                "canary_id": ht.canary_id,
                "service": ht.service,
                "plant_location": ht.plant_location,
                "format_slug": ht.format_slug,
                "provider_valid": ht.provider_valid,
                "safety_note": ht.safety_note,
                "spec_hash": ht.spec_hash,
                "token_logged": False,
            }
        )
        event = AegisEvent(
            session_id=session_id,
            phase=Phase.CANARY_PLANT,
            trusted_boundary=TrustBoundary.UNTRUSTED,
            input_summary=f"canary planted for {service} into {location}",
            detector_evidence=[],
            policy_decision=decision,
            metadata=meta,
        )
        self.tracer.record(event)
        return CanaryPlant(
            token=token,
            canary_id=ht.canary_id,
            service=ht.service,
            session_id=ht.session_id,
            location=ht.plant_location,
            format_slug=ht.format_slug,
            provider_valid=ht.provider_valid,
            safety_note=ht.safety_note,
            trace_id=event.event_id,
        )

    # ----- pipeline ------------------------------------------------------

    def _guard(
        self,
        ctx: ScanContext,
        metadata: dict[str, Any] | None,
        policy_mode: PolicyMode | str | None = None,
    ) -> AegisDecision:
        policy = self.policy if policy_mode is None else PolicyEngine(policy_mode)
        scan_ctx = self._scanner_context(ctx)
        results = [d.scan(scan_ctx) for d in self._content]

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
                self.ml_probe.score(scan_ctx, results, self.nimbus.cumulative(ctx.session_id))
            )

        # Enforce.
        decision = policy.decide(results)
        decision = _apply_broker_override(decision, assessment)
        self._mark_detected_canaries(results)

        event = self._build_event(ctx, results, decision, assessment, metadata, policy.mode)
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
        policy_mode: PolicyMode,
    ) -> AegisEvent:
        summary = self.registry.redact_text(redact_text(ctx.text))[:_SUMMARY_LIMIT]
        meta = dict(metadata or {})
        meta["policy_mode"] = str(policy_mode)
        if assessment.critical:
            meta["critical"] = True
            meta["raw_secret_leaked_handles"] = assessment.leaked_handles
        return AegisEvent(
            session_id=ctx.session_id,
            phase=ctx.phase,
            trusted_boundary=ctx.trusted_boundary,
            input_summary=summary,
            tool_name=ctx.tool_name,
            tool_arguments=_redact_args(ctx.tool_arguments, self.registry),
            detector_evidence=results,
            policy_decision=decision,
            metadata=meta,
        )

    def _scanner_context(self, ctx: ScanContext) -> ScanContext:
        if ctx.phase is not Phase.REQUEST:
            return ctx
        # Known canaries are allowed at their planting site, even when they imitate
        # provider credential shapes. Unknown/raw credentials in the same request still scan.
        return ScanContext(
            session_id=ctx.session_id,
            phase=ctx.phase,
            text=self.registry.redact_text(ctx.text),
            tool_name=ctx.tool_name,
            tool_arguments=ctx.tool_arguments,
            trusted_boundary=ctx.trusted_boundary,
        )

    def _maybe_attach_canary_vault(self) -> None:
        """Attach a durable canary vault when a key is configured or a vault already exists.

        With no key and no existing vault, the registry stays purely in-memory (current
        behaviour) — durability is opt-in via ``AEGIS_CANARY_VAULT_KEY`` (KTD13). The vault
        is imported lazily so the SDK has no hard dependency on the platform layer at import.
        """
        key = self.settings.canary_vault_key
        path = self.settings.canary_vault_path
        if key is None and not path.exists():
            return
        try:
            from aegis.platform.canaries import CanaryVault

            self.registry.attach_vault(CanaryVault(path, key))
            self.registry.restore_from_vault()
        except Exception:  # noqa: BLE001 - durable-canary setup must never break the guard path
            pass

    def _mark_detected_canaries(self, results: list[DetectorResult]) -> None:
        """Advance a planted canary to the ``detected`` lifecycle state when it leaks."""
        for result in results:
            if (
                result.detector_name == "honeytoken_detector"
                and result.recommended_action is not Action.ALLOW
            ):
                canary_id = result.evidence.get("canary_id")
                if canary_id:
                    self.registry.mark_detected(str(canary_id))


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


def _redact_args(
    arguments: dict[str, Any] | None, registry: HoneytokenRegistry
) -> dict[str, Any] | None:
    if not arguments:
        return arguments
    return {k: registry.redact_text(redact_text(str(v))) for k, v in arguments.items()}
