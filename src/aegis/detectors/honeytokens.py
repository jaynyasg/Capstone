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
    normalized: str = field(default="")


class HoneytokenRegistry:
    """Deterministic registration + matching for a small set of credential families."""

    def __init__(self) -> None:
        self._tokens: dict[str, Honeytoken] = {}

    def register(self, service: str, session_id: str, plant_location: str = "registry") -> str:
        canary_id = f"ht_{uuid.uuid4().hex[:8]}"
        token = f"aegis_canary_{service}_{uuid.uuid4().hex[:12]}"
        self._tokens[token] = Honeytoken(
            token=token,
            service=service,
            session_id=session_id,
            canary_id=canary_id,
            plant_location=plant_location,
            normalized=_normalize(token),
        )
        return token

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
