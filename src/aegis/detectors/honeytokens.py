"""Honeytoken (canary) registry + detector (C3 / FR-6).

Canaries are planted only in untrusted/model-visible context. Any later appearance in
output or tool arguments is a high-confidence exfiltration signal.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field

from aegis.contracts import Action, DetectorResult, Phase
from aegis.detectors.base import ScanContext, timed
from aegis.secrets.honeytoken_generator import (
    default_format_for_service,
    generate_honeytoken,
)


def _normalize(s: str) -> str:
    """Collapse whitespace so a smeared canary still matches."""
    return re.sub(r"\s+", "", s)


@dataclass
class Honeytoken:
    token: str
    service: str
    session_id: str
    canary_id: str
    plant_location: str = "registry"
    planted_at: float = field(default_factory=time.time)
    format_slug: str = "generic-sk"
    provider_valid: bool = False
    safety_note: str = ""
    spec_hash: str = ""
    normalized: str = field(default="")


class HoneytokenRegistry:
    """Deterministic registration + matching for a small set of credential families."""

    def __init__(self) -> None:
        self._tokens: dict[str, Honeytoken] = {}

    def register(
        self,
        service: str,
        session_id: str,
        plant_location: str = "registry",
        format_slug: str | None = None,
    ) -> str:
        canary_id = f"ht_{uuid.uuid4().hex[:8]}"
        generated = generate_honeytoken(format_slug or default_format_for_service(service))
        self._tokens[generated.token] = Honeytoken(
            token=generated.token,
            service=service,
            session_id=session_id,
            canary_id=canary_id,
            plant_location=plant_location,
            format_slug=generated.format_slug,
            provider_valid=generated.provider_valid,
            safety_note=generated.safety_note,
            spec_hash=generated.spec_hash,
            normalized=_normalize(generated.token),
        )
        return generated.token

    def get(self, token: str) -> Honeytoken | None:
        return self._tokens.get(token)

    def is_canary(self, token: str) -> bool:
        return token in self._tokens

    def all(self) -> list[Honeytoken]:
        return list(self._tokens.values())

    def safe_records(self, session_id: str | None = None) -> list[dict[str, object]]:
        records = self.all()
        if session_id is not None:
            records = [ht for ht in records if ht.session_id == session_id]
        return [
            {
                "canary_id": ht.canary_id,
                "service": ht.service,
                "session_id": ht.session_id,
                "plant_location": ht.plant_location,
                "planted_at": ht.planted_at,
                "format_slug": ht.format_slug,
                "provider_valid": ht.provider_valid,
                "safety_note": ht.safety_note,
                "spec_hash": ht.spec_hash,
            }
            for ht in records
        ]

    def redact_text(self, value: str) -> str:
        text = value
        for ht in self.all():
            marker = f"[REDACTED:canary:{ht.canary_id}]"
            text = text.replace(ht.token, marker)
            spaced_pattern = r"\s*".join(re.escape(ch) for ch in ht.token)
            text = re.sub(spaced_pattern, marker, text)
        return text


def _phase_location(phase: Phase) -> str:
    return {Phase.REQUEST: "request", Phase.RESPONSE: "response"}.get(phase, "text")


class HoneytokenDetector:
    name = "honeytoken_detector"

    def __init__(self, registry: HoneytokenRegistry) -> None:
        self.registry = registry

    def scan(self, ctx: ScanContext) -> DetectorResult:
        with timed() as elapsed:
            hit = self._find(ctx)
            ms = elapsed()
        if hit is None:
            return DetectorResult(
                detector_name=self.name,
                score=0.0,
                confidence=1.0,
                recommended_action=Action.ALLOW,
                evidence={},
                latency_ms=ms,
            )
        ht, location = hit
        return DetectorResult(
            detector_name=self.name,
            score=1.0,
            confidence=1.0,
            recommended_action=Action.BLOCK,
            evidence={
                "canary_id": ht.canary_id,
                "service": ht.service,
                "location": location,
                "session_id": ht.session_id,
            },
            latency_ms=ms,
        )

    def _find(self, ctx: ScanContext) -> tuple[Honeytoken, str] | None:
        # Canaries are planted in REQUEST/ingress context; they are an alarm only when they
        # *leak out* in a response or tool call (FR-6). Skip ingress text to avoid firing on
        # the planting site itself.
        if ctx.phase is not Phase.REQUEST:
            text_norm = _normalize(ctx.text or "")
            for ht in self.registry.all():
                if ht.token in (ctx.text or "") or ht.normalized in text_norm:
                    return ht, _phase_location(ctx.phase)
        # Tool-call arguments, located per argument.
        for arg_name, value in (ctx.tool_arguments or {}).items():
            sval = str(value)
            sval_norm = _normalize(sval)
            for ht in self.registry.all():
                if ht.token in sval or ht.normalized in sval_norm:
                    return ht, f"tool_arguments:{arg_name}"
        return None
