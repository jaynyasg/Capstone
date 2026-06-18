"""Tool-call argument scanner (C4 / FR-5) — the capstone differentiator.

Inspects structured arguments of the three supported high-risk tools *before dispatch*,
closing the "tool-call args bypass response guard" failure mode (PRD §9).
"""

from __future__ import annotations

from typing import Any

from aegis.contracts import Action, DetectorResult, Phase, TrustBoundary
from aegis.detectors._credutil import find_credentials, redact
from aegis.detectors.base import ScanContext, timed
from aegis.detectors.honeytokens import HoneytokenRegistry

SUPPORTED_TOOLS = {"send_email", "http_request", "query_database"}


class ToolCallArgumentScanner:
    name = "tool_call_argument_scanner"

    def __init__(self, registry: HoneytokenRegistry | None = None) -> None:
        self.registry = registry

    def scan(self, ctx: ScanContext) -> DetectorResult:
        with timed() as elapsed:
            if ctx.phase is not Phase.TOOL_CALL or not ctx.tool_name:
                return self._allow(elapsed(), {"supported": False, "reason": "not a tool call"})
            if ctx.tool_name not in SUPPORTED_TOOLS:
                return self._allow(elapsed(), {"supported": False, "tool_name": ctx.tool_name})

            flags = self._scan_args(ctx)
            ms = elapsed()

        if flags:
            return DetectorResult(
                detector_name=self.name,
                score=0.95,
                confidence=0.95,
                recommended_action=Action.BLOCK,
                evidence={"supported": True, "tool_name": ctx.tool_name, "flags": flags},
                latency_ms=ms,
            )
        return self._allow(ms, {"supported": True, "tool_name": ctx.tool_name, "flags": []})

    def _scan_args(self, ctx: ScanContext) -> list[dict[str, Any]]:
        in_trusted = ctx.trusted_boundary is TrustBoundary.TRUSTED
        flags: list[dict[str, Any]] = []
        for arg_name, value in (ctx.tool_arguments or {}).items():
            sval = str(value)
            creds = find_credentials(sval)
            canary_id = self._match_canary(sval)
            if not creds and not canary_id:
                continue
            reason = "matched_canary" if canary_id else creds[0]["kind"]
            flags.append(
                {
                    "tool_name": ctx.tool_name,
                    "argument_name": arg_name,
                    "value_preview": redact(sval),
                    "risk_reason": reason,
                    "matched_credential_pattern": bool(creds),
                    "appeared_in_trusted": in_trusted,
                    "matched_canary": canary_id,
                }
            )
        return flags

    def _match_canary(self, value: str) -> str | None:
        if self.registry is None:
            return None
        for ht in self.registry.all():
            if ht.token in value:
                return ht.canary_id
        return None

    def _allow(self, ms: float, evidence: dict[str, Any]) -> DetectorResult:
        return DetectorResult(
            detector_name=self.name,
            score=0.0,
            confidence=0.9,
            recommended_action=Action.ALLOW,
            evidence=evidence,
            latency_ms=ms,
        )
