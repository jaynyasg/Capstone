"""Aegis — runtime credential defense for LLM agents."""

from aegis.client import AegisClient
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
from aegis.policy.engine import PolicyMode

__all__ = [
    "AegisClient",
    "Settings",
    "PolicyMode",
    "Action",
    "AegisDecision",
    "AegisEvent",
    "DetectorResult",
    "Phase",
    "TrustBoundary",
    "most_severe",
]

__version__ = "0.1.0"
