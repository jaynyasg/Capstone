"""Honeytoken (canary) registry + detector (C3 / FR-6).

Canaries are planted only in untrusted/model-visible context. Any later appearance in
output or tool arguments is a high-confidence exfiltration signal.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from aegis.contracts import Action, DetectorResult, Phase
from aegis.detectors.base import ScanContext, timed
from aegis.secrets.honeytoken_generator import (
    default_format_for_service,
    generate_honeytoken,
)


def _normalize(s: str) -> str:
    """Collapse whitespace so a smeared canary still matches."""
    return re.sub(r"\s+", "", s)


class CanaryPersistence(Protocol):
    """What the registry needs from a durable vault (implemented by platform.CanaryVault).

    Declared here so the detector layer never imports the platform layer — the dependency
    points one way (platform reads detector output, not the reverse). The concrete vault is
    injected by :class:`aegis.client.AegisClient`, the layer that already bridges both.
    """

    def store(
        self,
        *,
        canary_id: str,
        token: str,
        service: str,
        session_id: str,
        plant_location: str,
        planted_at: float,
        format_slug: str,
        provider_valid: bool,
        safety_note: str,
        spec_hash: str,
    ) -> None: ...

    def restore(self) -> list[dict[str, Any]]: ...

    def safe_records(self, session_id: str | None = None) -> list[dict[str, Any]]: ...

    def mark_detected(self, canary_id: str) -> None: ...

    def health_warnings(self) -> list[Any]: ...


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
    """Deterministic registration + matching for a small set of credential families.

    Optionally backed by a durable vault (:class:`CanaryPersistence`): planting persists the
    encrypted token, and :meth:`restore_from_vault` reloads decryptable canaries into memory
    so detection survives a process restart.
    """

    def __init__(self, vault: CanaryPersistence | None = None) -> None:
        self._tokens: dict[str, Honeytoken] = {}
        self._vault = vault

    def attach_vault(self, vault: CanaryPersistence) -> None:
        self._vault = vault

    def register(
        self,
        service: str,
        session_id: str,
        plant_location: str = "registry",
        format_slug: str | None = None,
    ) -> str:
        canary_id = f"ht_{uuid.uuid4().hex[:8]}"
        generated = generate_honeytoken(format_slug or default_format_for_service(service))
        ht = Honeytoken(
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
        self._tokens[ht.token] = ht
        if self._vault is not None:
            try:
                self._vault.store(
                    canary_id=ht.canary_id,
                    token=ht.token,
                    service=ht.service,
                    session_id=ht.session_id,
                    plant_location=ht.plant_location,
                    planted_at=ht.planted_at,
                    format_slug=ht.format_slug,
                    provider_valid=ht.provider_valid,
                    safety_note=ht.safety_note,
                    spec_hash=ht.spec_hash,
                )
            except Exception:  # noqa: BLE001 - durable persistence must not break planting
                pass
        return generated.token

    def restore_from_vault(self) -> None:
        """Reload decryptable canaries from the vault into memory (idempotent)."""
        if self._vault is None:
            return
        for rec in self._vault.restore():
            token = rec.get("token")
            if not token or token in self._tokens:
                continue
            self._tokens[token] = Honeytoken(
                token=token,
                service=str(rec.get("service", "unknown")),
                session_id=str(rec.get("session_id", "unknown")),
                canary_id=str(rec.get("canary_id", "unknown")),
                plant_location=str(rec.get("plant_location", "registry")),
                planted_at=float(rec.get("planted_at", 0.0) or 0.0),
                format_slug=str(rec.get("format_slug", "generic-sk")),
                provider_valid=bool(rec.get("provider_valid", False)),
                safety_note=str(rec.get("safety_note", "") or ""),
                spec_hash=str(rec.get("spec_hash", "") or ""),
                normalized=_normalize(token),
            )

    def mark_detected(self, canary_id: str) -> None:
        if self._vault is not None:
            try:
                self._vault.mark_detected(canary_id)
            except Exception:  # noqa: BLE001 - lifecycle bookkeeping must not break the guard path
                pass

    def health_warnings(self) -> list[Any]:
        """Durable-detection health (degraded key, corrupt vault rows). Empty without a vault."""
        if self._vault is None:
            return []
        try:
            return list(self._vault.health_warnings())
        except Exception:  # noqa: BLE001 - health must never raise into callers
            return []

    def get(self, token: str) -> Honeytoken | None:
        return self._tokens.get(token)

    def is_canary(self, token: str) -> bool:
        return token in self._tokens

    def all(self) -> list[Honeytoken]:
        return list(self._tokens.values())

    def safe_records(self, session_id: str | None = None) -> list[dict[str, object]]:
        """Safe canary metadata (never the token), merging in-memory and vault records.

        The merge matters after a key-loss restart: the in-memory set is empty, but the
        vault's plaintext safe metadata keeps planted canaries visible to operators.
        """
        records: dict[str, dict[str, object]] = {}
        for ht in self.all():
            if session_id is not None and ht.session_id != session_id:
                continue
            records[ht.canary_id] = {
                "canary_id": ht.canary_id,
                "service": ht.service,
                "session_id": ht.session_id,
                "plant_location": ht.plant_location,
                "planted_at": ht.planted_at,
                "format_slug": ht.format_slug,
                "provider_valid": ht.provider_valid,
                "safety_note": ht.safety_note,
                "spec_hash": ht.spec_hash,
                "lifecycle_state": "planted",
            }
        if self._vault is not None:
            try:
                for rec in self._vault.safe_records(session_id):
                    canary_id = str(rec.get("canary_id"))
                    if canary_id in records:
                        records[canary_id]["lifecycle_state"] = rec.get(
                            "lifecycle_state", records[canary_id]["lifecycle_state"]
                        )
                    else:
                        records[canary_id] = rec
            except Exception:  # noqa: BLE001 - vault read must not break the evidence view
                pass
        return list(records.values())

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
