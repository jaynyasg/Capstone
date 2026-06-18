"""Detector interface and the raw-content scan context.

`AegisEvent` is the log-safe artifact (redacted). Detectors instead receive a `ScanContext`
carrying the *raw* content to inspect — kept out of the event so secrets never reach logs
by default. Every detector returns the common `DetectorResult` shape (contracts.py).
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from aegis.contracts import DetectorResult, Phase, TrustBoundary


class ScanContext(BaseModel):
    """Raw inputs handed to a detector for one turn."""

    session_id: str
    phase: Phase
    text: str = ""
    tool_name: str | None = None
    tool_arguments: dict[str, Any] | None = None
    trusted_boundary: TrustBoundary = TrustBoundary.MIXED
    secret_handles: list[str] = Field(default_factory=list)


@runtime_checkable
class Detector(Protocol):
    """A stateless content detector. Stateful signals (Nimbus) have their own surface."""

    name: str

    def scan(self, ctx: ScanContext) -> DetectorResult: ...


@contextmanager
def timed():
    """Yield a callable returning elapsed ms — for the DetectorResult.latency_ms field."""
    start = time.perf_counter()
    yield lambda: (time.perf_counter() - start) * 1000.0
