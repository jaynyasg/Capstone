"""The boundary contract — the single typed seam every layer mirrors.

Detectors, the policy engine, guards, the credential broker, tracing, the gateway, and
the dashboard all speak these types and nothing else. Per PRD §4.3 (events/decision) and
§6.1 (detector result). Validate every external / LLM payload against these *at the seam*.
"""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Action(StrEnum):
    """Policy outcome, ordered least→most severe. The engine picks the most severe."""

    ALLOW = "ALLOW"
    WARN = "WARN"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"

    @property
    def severity(self) -> int:
        return _ACTION_SEVERITY[self]

    def is_non_allow(self) -> bool:
        return self is not Action.ALLOW


_ACTION_SEVERITY: dict[Action, int] = {
    Action.ALLOW: 0,
    Action.WARN: 1,
    Action.SANITIZE: 2,
    Action.BLOCK: 3,
    Action.ESCALATE: 4,
}


def most_severe(actions: list[Action]) -> Action:
    """The MVP policy combinator: independent rules, take the most severe action."""
    return max(actions, key=lambda a: a.severity) if actions else Action.ALLOW


class Phase(StrEnum):
    REQUEST = "request"
    TOOL_CALL = "tool_call"
    RESPONSE = "response"
    CANARY_PLANT = "canary_plant"


class TrustBoundary(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    MIXED = "mixed"


class DetectorResult(BaseModel):
    """Common shape every detector returns (PRD §6.1). `evidence` is detector-specific."""

    detector_name: str
    score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    recommended_action: Action
    evidence: dict[str, Any] = Field(default_factory=dict)
    latency_ms: float = 0.0


class AegisDecision(BaseModel):
    """Final policy decision returned by every guard (PRD §4.3)."""

    action: Action
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)
    detector_hits: list[DetectorResult] = Field(default_factory=list)
    sanitized_payload: Any | None = None
    trace_id: str | None = None

    @property
    def allowed(self) -> bool:
        return self.action is Action.ALLOW


class CanaryPlant(BaseModel):
    """Audit record returned when Aegis plants a honeytoken into model-visible context."""

    token: str
    canary_id: str
    service: str
    session_id: str
    location: str
    format_slug: str
    provider_valid: bool = False
    safety_note: str = ""
    trace_id: str | None = None


class AegisEvent(BaseModel):
    """Normalized representation of one guarded turn (PRD §4.3).

    `input_summary` is always redacted/log-safe. `raw_content_ref` points at raw content
    only when the run is explicitly local test mode.
    """

    event_id: str = Field(default_factory=lambda: _new_id("evt"))
    created_at: float = Field(default_factory=time.time)
    session_id: str
    phase: Phase
    trusted_boundary: TrustBoundary = TrustBoundary.MIXED
    input_summary: str = ""
    raw_content_ref: str | None = None
    tool_name: str | None = None
    tool_arguments: dict[str, Any] | None = None
    secret_handles_seen: list[str] = Field(default_factory=list)
    detector_evidence: list[DetectorResult] = Field(default_factory=list)
    policy_decision: AegisDecision | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
