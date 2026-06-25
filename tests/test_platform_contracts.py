"""U1 — platform contract vocabulary: bounded queries, health, windowing, freshness.

These exercise the *types* every platform consumer (API, dashboard, exports) speaks,
independent of any backing store. Count semantics are fixed here: ``total`` = all matching
records, ``latest`` = the bounded window actually returned.
"""

from __future__ import annotations

from aegis.platform.store import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    SCHEMA_VERSION,
    EvidenceHealth,
    EvidenceQuery,
    FreshnessState,
    HealthSeverity,
    HealthStatus,
    HealthWarning,
    RecordWindow,
    SnapshotMeta,
    WarningType,
)


def test_schema_version_is_stable_nonempty() -> None:
    assert isinstance(SCHEMA_VERSION, str)
    assert SCHEMA_VERSION


def test_query_defaults_are_bounded() -> None:
    q = EvidenceQuery()
    assert q.limit == DEFAULT_LIMIT
    assert q.offset == 0


def test_query_clamps_unsafe_limits_consistently() -> None:
    # Negative, zero, and excessive limits are all coerced to a safe value so no single
    # contract value can ever trigger an unbounded or degenerate read.
    assert EvidenceQuery(limit=-5).limit == DEFAULT_LIMIT
    assert EvidenceQuery(limit=0).limit == DEFAULT_LIMIT
    assert EvidenceQuery(limit=10_000).limit == MAX_LIMIT
    assert EvidenceQuery(limit=50).limit == 50  # valid window passes through


def test_query_clamps_negative_offset() -> None:
    assert EvidenceQuery(offset=-3).offset == 0
    assert EvidenceQuery(offset=7).offset == 7


def test_query_carries_filter_dimensions() -> None:
    q = EvidenceQuery(session_id="s1", action="BLOCK", phase="tool_call", detector="x", since=1.0)
    assert q.session_id == "s1"
    assert q.action == "BLOCK"
    assert q.phase == "tool_call"
    assert q.detector == "x"
    assert q.since == 1.0


def test_health_with_no_warnings_is_healthy() -> None:
    assert EvidenceHealth.from_warnings([]).status is HealthStatus.HEALTHY


def test_health_degrades_on_warning_or_error() -> None:
    corrupt = HealthWarning(
        source_kind="traces",
        warning_type=WarningType.CORRUPT_ROW,
        severity=HealthSeverity.WARNING,
        detail="2 malformed lines",
    )
    unreadable = HealthWarning(
        source_kind="evals",
        warning_type=WarningType.UNREADABLE,
        severity=HealthSeverity.ERROR,
    )
    assert EvidenceHealth.from_warnings([corrupt]).status is HealthStatus.DEGRADED
    assert EvidenceHealth.from_warnings([unreadable]).status is HealthStatus.DEGRADED
    both = EvidenceHealth.from_warnings([corrupt, unreadable])
    assert both.status is HealthStatus.DEGRADED
    assert len(both.warnings) == 2


def test_health_stays_healthy_on_info_only() -> None:
    # A missing-but-expected source before any traffic is informational, not a defect.
    info = HealthWarning(
        source_kind="traces",
        warning_type=WarningType.MISSING,
        severity=HealthSeverity.INFO,
    )
    assert EvidenceHealth.from_warnings([info]).status is HealthStatus.HEALTHY


def test_record_window_defaults_are_empty_and_truthful() -> None:
    window = RecordWindow()
    assert window.total == 0
    assert window.latest == []
    assert window.query.limit == DEFAULT_LIMIT


def test_snapshot_meta_defaults_to_live_current_schema() -> None:
    meta = SnapshotMeta(generated_at=10.0)
    assert meta.schema_version == SCHEMA_VERSION
    assert meta.freshness is FreshnessState.LIVE
    assert meta.cache_age_seconds == 0.0
