"""Typed contracts for model-specific CIFT calibration.

CIFT is model-specific: a certificate belongs to one hosted model endpoint and one observed
capability profile. Gateway-only models can be calibrated, but they are not CIFT-certified
unless activation evidence is available and passes the calibration thresholds.
"""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CertificationLevel(StrEnum):
    NONE = "none"
    GATEWAY_CALIBRATED = "gateway_calibrated"
    ACTIVATION_READY = "activation_ready"
    CIFT_CERTIFIED = "cift_certified"


class CertificationStatus(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


class CiftCalibrationRequest(BaseModel):
    model_id: str
    provider_url: str = "local"
    supports_activations: bool = False
    activation_endpoint: str | None = None
    activation_sample_count: int = Field(default=0, ge=0)
    activation_separation_score: float | None = Field(default=None, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CiftCertification(BaseModel):
    certification_id: str = Field(default_factory=lambda: f"cift_{uuid.uuid4().hex[:12]}")
    created_at: float = Field(default_factory=time.time)
    model_id: str
    provider_url: str
    model_fingerprint: str
    level: CertificationLevel
    status: CertificationStatus
    reasons: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
