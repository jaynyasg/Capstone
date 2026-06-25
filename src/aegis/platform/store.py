"""Platform evidence contract: query, windowing, health, and freshness vocabulary.

This module defines the *vocabulary* every platform consumer (gateway API, dashboard,
exports, reports) speaks, plus the :class:`EvidenceStore` protocol the SQLite adapter
implements. It deliberately imports nothing from :mod:`aegis.platform.evidence` so the
contract can be imported anywhere without a cycle — the dependency arrow points one way
(evidence → store), and the protocol's overview return type is a ``TYPE_CHECKING`` forward
reference.

Count semantics are fixed here and mirrored everywhere:

* ``total`` always means *all matching records*.
* ``latest`` / ``recent`` always means *the bounded window actually returned*.

Reads are bounded by default. :class:`EvidenceQuery` clamps unsafe windows (negative, zero,
or excessive limits) on construction, so a single contract value can never trigger an
unbounded or degenerate read regardless of where it came from (CLI flag, API query string,
or test).
"""

from __future__ import annotations

import time
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field, field_validator

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    from aegis.platform.evidence import PlatformOverview

# Platform API/response schema version. Bumped when the response contract changes shape.
SCHEMA_VERSION = "1.0"

# Default read window and the hard ceiling an excessive limit is clamped to.
DEFAULT_LIMIT = 25
MAX_LIMIT = 500


class HealthSeverity(StrEnum):
    """How loud a health warning is. INFO never degrades overall status."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class HealthStatus(StrEnum):
    """Operator-facing rollup of evidence integrity."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"


class WarningType(StrEnum):
    """Why a source is not fully trustworthy. Drives operator copy near the evidence."""

    MISSING = "missing"  # source not present (often a healthy fresh-start, hence INFO)
    UNREADABLE = "unreadable"  # exists but cannot be read (permissions, encoding)
    CORRUPT_ROW = "corrupt_row"  # readable but some rows did not parse
    PARTIAL_IMPORT = "partial_import"  # import stopped before consuming the whole source
    DEGRADED = "degraded"  # backing store/key unavailable or incompatible


class FreshnessState(StrEnum):
    """Whether an overview is live, served from cache, gone stale, or a static snapshot."""

    LIVE = "live"
    CACHED = "cached"
    STALE = "stale"
    STATIC = "static"


class EvidenceQuery(BaseModel):
    """A bounded, validated read window. Construction clamps unsafe values.

    The store and the API both build one of these, so clamping in one place guarantees
    consistent behaviour everywhere: negative/zero limits fall back to the default and
    excessive limits clamp to :data:`MAX_LIMIT`.
    """

    limit: int = DEFAULT_LIMIT
    offset: int = 0
    session_id: str | None = None
    action: str | None = None
    phase: str | None = None
    detector: str | None = None
    model_id: str | None = None
    since: float | None = None
    until: float | None = None

    @field_validator("limit")
    @classmethod
    def _clamp_limit(cls, value: int) -> int:
        if value < 1:
            return DEFAULT_LIMIT
        return min(value, MAX_LIMIT)

    @field_validator("offset")
    @classmethod
    def _clamp_offset(cls, value: int) -> int:
        return max(0, value)


class HealthWarning(BaseModel):
    """One reason a source is degraded. ``detail`` is always display-safe (redacted)."""

    source_kind: str
    warning_type: WarningType
    severity: HealthSeverity = HealthSeverity.WARNING
    detail: str = ""
    source_path: str | None = None
    count: int = 1


class EvidenceHealth(BaseModel):
    """Integrity rollup: a status plus the warnings that produced it."""

    status: HealthStatus = HealthStatus.HEALTHY
    warnings: list[HealthWarning] = Field(default_factory=list)

    @classmethod
    def from_warnings(cls, warnings: list[HealthWarning]) -> EvidenceHealth:
        """Derive overall status: any WARNING/ERROR degrades; INFO-only stays healthy."""
        degraded = any(w.severity is not HealthSeverity.INFO for w in warnings)
        status = HealthStatus.DEGRADED if degraded else HealthStatus.HEALTHY
        return cls(status=status, warnings=list(warnings))


class SnapshotMeta(BaseModel):
    """Freshness/provenance metadata attached to an overview response.

    In live mode this is ``LIVE`` with zero cache age; the snapshot cache (U6) populates
    ``CACHED``/``STALE`` and static dashboard generation uses ``STATIC``.
    """

    schema_version: str = SCHEMA_VERSION
    generated_at: float = Field(default_factory=time.time)
    freshness: FreshnessState = FreshnessState.LIVE
    cache_age_seconds: float = 0.0
    refresh_source: str = "live"
    stale_after_seconds: float | None = None


class RecordWindow(BaseModel):
    """A bounded slice of records plus the true total and the query that produced it.

    The reusable drilldown shape: ``total`` answers "how many match" and ``latest`` is the
    window actually returned for ``query``.
    """

    total: int = 0
    latest: list[dict[str, Any]] = Field(default_factory=list)
    query: EvidenceQuery = Field(default_factory=EvidenceQuery)


@runtime_checkable
class EvidenceStore(Protocol):
    """The read boundary the gateway, dashboard, and exports consume.

    The JSONL-backed default (U1) and the SQLite adapter (U2) both satisfy this shape, so
    consumers never parse raw artifacts themselves.
    """

    def overview(self, query: EvidenceQuery | None = None) -> PlatformOverview: ...

    def decisions(self, query: EvidenceQuery | None = None) -> RecordWindow: ...

    def sessions(self, query: EvidenceQuery | None = None) -> RecordWindow: ...

    def detectors(self, query: EvidenceQuery | None = None) -> RecordWindow: ...

    def canaries(self, query: EvidenceQuery | None = None) -> RecordWindow: ...

    def cift(self, query: EvidenceQuery | None = None) -> RecordWindow: ...

    def health(self) -> EvidenceHealth: ...
