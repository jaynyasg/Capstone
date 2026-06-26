"""Gateway request bodies — validated at the seam (pydantic). Aegis exposes its own
normalized contracts rather than mimicking any single provider's wire format."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from aegis.policy.engine import PolicyMode


class ChatRequest(BaseModel):
    session_id: str = "gateway"
    messages: list[dict[str, Any]]
    tools: list[dict[str, Any]] | None = None
    model: str | None = None
    policy_mode: PolicyMode | None = None


class GuardRequestBody(BaseModel):
    session_id: str = "gateway"
    messages: list[dict[str, Any]]
    tools: list[dict[str, Any]] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    policy_mode: PolicyMode | None = None


class GuardToolBody(BaseModel):
    session_id: str = "gateway"
    tool_name: str
    arguments: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)
    policy_mode: PolicyMode | None = None


class GuardResponseBody(BaseModel):
    session_id: str = "gateway"
    output: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    policy_mode: PolicyMode | None = None


class PlantCanaryBody(BaseModel):
    session_id: str = "gateway"
    service: str
    location: str = "model_context"
    format_slug: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CiftCalibrationBody(BaseModel):
    model_id: str
    provider_url: str = "local"
    supports_activations: bool = False
    activation_endpoint: str | None = None
    activation_sample_count: int = Field(default=0, ge=0)
    activation_separation_score: float | None = Field(default=None, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)
