"""Aegis — runtime credential defense for LLM agents."""

from aegis.cift import CiftCalibrationRequest, CiftCertification, calibrate_model
from aegis.client import AegisClient
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
from aegis.policy.engine import PolicyMode

__all__ = [
    "AegisClient",
    "CiftCalibrationRequest",
    "CiftCertification",
    "Settings",
    "PolicyMode",
    "Action",
    "AegisDecision",
    "AegisEvent",
    "CanaryPlant",
    "DetectorResult",
    "Phase",
    "TrustBoundary",
    "most_severe",
    "calibrate_model",
]

__version__ = "0.1.0"
