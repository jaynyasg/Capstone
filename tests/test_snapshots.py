"""U6 — overview snapshot cache: bounded reads with explicit live/cached/stale freshness.

A controllable clock and a counting builder make the freshness state machine deterministic:
within the refresh window the same snapshot is reused; past it the overview rebuilds; past
the stale threshold a cached read is labelled stale; and a cached read never drops health.
"""

from __future__ import annotations

from aegis.platform.evidence import (
    CanaryOverview,
    CiftOverview,
    DecisionOverview,
    PlatformOverview,
    PlatformStatus,
)
from aegis.platform.snapshots import SnapshotCache
from aegis.platform.store import (
    EvidenceHealth,
    FreshnessState,
    HealthSeverity,
    HealthWarning,
    WarningType,
)


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _overview(total: int, warnings: list[HealthWarning] | None = None) -> PlatformOverview:
    return PlatformOverview(
        status=PlatformStatus(
            provider="mock",
            policy_mode="balanced",
            braintrust=False,
            ml_probe=False,
            traces_dir="t",
            reports_dir="r",
        ),
        decisions=DecisionOverview(total=total),
        cift=CiftOverview(),
        canaries=CanaryOverview(),
        health=EvidenceHealth.from_warnings(warnings or []),
    )


def _counting_builder():
    state = {"calls": 0}

    def builder() -> PlatformOverview:
        state["calls"] += 1
        return _overview(state["calls"])

    return builder, state


def test_snapshot_reused_within_refresh_window() -> None:
    clock = _Clock()
    builder, state = _counting_builder()
    cache = SnapshotCache(builder, refresh_interval=5.0, stale_after=60.0, clock=clock)

    first = cache.get()  # builds at t=0
    clock.now = 2.0
    second = cache.get()  # within window -> reuse

    assert state["calls"] == 1
    assert first.snapshot.freshness is FreshnessState.LIVE
    assert second.decisions.total == 1  # reused counts
    assert second.snapshot.freshness is FreshnessState.CACHED
    assert second.snapshot.generated_at == 0.0
    assert second.snapshot.cache_age_seconds == 2.0


def test_snapshot_refreshes_after_interval() -> None:
    clock = _Clock()
    builder, state = _counting_builder()
    cache = SnapshotCache(builder, refresh_interval=5.0, stale_after=60.0, clock=clock)

    cache.get()  # t=0 -> total 1
    clock.now = 6.0
    refreshed = cache.get()  # past refresh interval -> rebuild

    assert state["calls"] == 2
    assert refreshed.decisions.total == 2  # fresh counts
    assert refreshed.snapshot.freshness is FreshnessState.LIVE


def test_snapshot_marked_stale_past_threshold() -> None:
    clock = _Clock()
    builder, state = _counting_builder()
    # Refresh slower than stale: the snapshot ages into the stale band before a rebuild.
    cache = SnapshotCache(builder, refresh_interval=1000.0, stale_after=60.0, clock=clock)

    cache.get()  # t=0
    clock.now = 70.0
    stale = cache.get()

    assert state["calls"] == 1  # not rebuilt yet
    assert stale.snapshot.freshness is FreshnessState.STALE
    assert stale.snapshot.cache_age_seconds == 70.0


def test_cached_read_keeps_health_warnings() -> None:
    clock = _Clock()
    warning = HealthWarning(
        source_kind="traces",
        warning_type=WarningType.CORRUPT_ROW,
        severity=HealthSeverity.WARNING,
    )

    def builder() -> PlatformOverview:
        return _overview(1, warnings=[warning])

    cache = SnapshotCache(builder, refresh_interval=5.0, stale_after=60.0, clock=clock)
    cache.get()
    clock.now = 2.0
    cached = cache.get()

    assert cached.snapshot.freshness is FreshnessState.CACHED
    assert cached.health.status.value == "degraded"  # warning survives the cache
    assert len(cached.health.warnings) == 1


def test_disabled_cache_rebuilds_every_read() -> None:
    clock = _Clock()
    builder, state = _counting_builder()
    cache = SnapshotCache(builder, refresh_interval=0.0, stale_after=60.0, clock=clock)

    first = cache.get()
    second = cache.get()

    assert state["calls"] == 2  # deterministic: every read rebuilds
    assert first.snapshot.freshness is FreshnessState.LIVE
    assert second.snapshot.freshness is FreshnessState.LIVE
