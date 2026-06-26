"""U6 — overview snapshot cache: bounded reads with explicit live/cached/stale freshness.

A controllable clock and a counting builder make the freshness state machine deterministic:
within the refresh window the same snapshot is reused; past it the overview rebuilds; past
the stale threshold a cached read is labelled stale; and a cached read never drops health.
"""

from __future__ import annotations

import pytest

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


def _toggle_builder():
    """A builder whose ``state['fail']`` flag makes the next build raise."""
    state = {"calls": 0, "fail": False}

    def builder() -> PlatformOverview:
        state["calls"] += 1
        if state["fail"]:
            raise RuntimeError("builder boom (e.g. transient SQLite lock)")
        return _overview(state["calls"])

    return builder, state


def test_snapshot_reused_within_refresh_window() -> None:
    clock = _Clock()
    builder, state = _counting_builder()
    # One controllable clock for both roles keeps the displayed generated_at deterministic.
    cache = SnapshotCache(
        builder, refresh_interval=5.0, stale_after=60.0, clock=clock, wall_clock=clock
    )

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


def test_invalidate_forces_next_read_to_rebuild() -> None:
    clock = _Clock()
    builder, state = _counting_builder()
    # Huge refresh window so a rebuild can only come from invalidate(), not from ageing out.
    cache = SnapshotCache(
        builder, refresh_interval=1000.0, stale_after=60.0, clock=clock, wall_clock=clock
    )
    cache.get()  # build 1
    cache.get()  # within window -> cached, no rebuild
    assert state["calls"] == 1

    cache.invalidate()
    cache.get()  # cache cleared -> rebuild
    assert state["calls"] == 2


def test_negative_refresh_interval_normalises_to_zero() -> None:
    clock = _Clock()
    builder, state = _counting_builder()
    cache = SnapshotCache(
        builder, refresh_interval=-5.0, stale_after=60.0, clock=clock, wall_clock=clock
    )
    cache.get()
    cache.get()
    assert state["calls"] == 2  # clamped to 0 -> every read rebuilds (deterministic)


def test_disabled_cache_rebuilds_every_read() -> None:
    clock = _Clock()
    builder, state = _counting_builder()
    cache = SnapshotCache(builder, refresh_interval=0.0, stale_after=60.0, clock=clock)

    first = cache.get()
    second = cache.get()

    assert state["calls"] == 2  # deterministic: every read rebuilds
    assert first.snapshot.freshness is FreshnessState.LIVE
    assert second.snapshot.freshness is FreshnessState.LIVE


def test_builder_failure_serves_last_good_snapshot_as_stale() -> None:
    # A transient builder failure (e.g. a locked SQLite store) must not 500 the dashboard: the
    # last good snapshot is served, labelled STALE so the operator sees it is not fresh.
    clock = _Clock()
    builder, state = _toggle_builder()
    cache = SnapshotCache(
        builder, refresh_interval=5.0, stale_after=60.0, clock=clock, wall_clock=clock
    )
    first = cache.get()  # t=0 -> LIVE, total 1
    assert first.snapshot.freshness is FreshnessState.LIVE

    state["fail"] = True
    clock.now = 6.0  # past refresh interval -> attempts a rebuild, which fails
    served = cache.get()

    assert state["calls"] == 2  # the rebuild was attempted
    assert served.snapshot.freshness is FreshnessState.STALE  # last good, labelled stale
    assert served.decisions.total == 1  # the last good snapshot's counts, not an error
    assert served.snapshot.cache_age_seconds == 6.0


def test_builder_failure_with_no_cache_propagates() -> None:
    # With nothing cached to fall back to, a builder failure has no safe answer — it must raise
    # rather than fabricate an empty snapshot.
    clock = _Clock()
    builder, state = _toggle_builder()
    state["fail"] = True
    cache = SnapshotCache(
        builder, refresh_interval=5.0, stale_after=60.0, clock=clock, wall_clock=clock
    )
    with pytest.raises(RuntimeError):
        cache.get()


def test_builder_failure_backs_off_during_cooldown_then_retries() -> None:
    # After a failure the builder is not retried every request (a short cooldown serves stale),
    # then a later request retries and recovers to LIVE.
    clock = _Clock()
    builder, state = _toggle_builder()
    cache = SnapshotCache(
        builder, refresh_interval=5.0, stale_after=60.0, clock=clock, wall_clock=clock
    )
    cache.get()  # t=0 -> LIVE (calls 1)

    state["fail"] = True
    clock.now = 6.0
    cache.get()  # rebuild attempt fails (calls 2), serves stale, enters cooldown
    clock.now = 9.0  # within the cooldown window (failed at 6, cooldown = refresh_interval 5)
    cache.get()  # must NOT retry the builder while cooling
    assert state["calls"] == 2

    state["fail"] = False
    clock.now = 12.0  # past the cooldown -> retries and recovers
    recovered = cache.get()
    assert state["calls"] == 3
    assert recovered.snapshot.freshness is FreshnessState.LIVE


def test_age_uses_monotonic_clock_and_never_negative_on_wall_clock_step_back() -> None:
    # Age/refresh must key off a monotonic clock; a backward wall-clock step (e.g. NTP
    # correction) must not yield a negative displayed age or a frozen cache.
    mono = _Clock()
    wall = _Clock()
    wall.now = 100.0
    builder, state = _counting_builder()
    cache = SnapshotCache(
        builder, refresh_interval=5.0, stale_after=60.0, clock=mono, wall_clock=wall
    )

    first = cache.get()  # mono=0, wall=100 -> LIVE
    assert first.snapshot.generated_at == 100.0  # display timestamp is the wall clock

    wall.now = 90.0  # wall clock steps backward 10s
    mono.now = 2.0  # only 2s of real elapsed time
    cached = cache.get()

    assert state["calls"] == 1  # still within the refresh window
    assert cached.snapshot.freshness is FreshnessState.CACHED
    assert cached.snapshot.cache_age_seconds == 2.0  # from monotonic, not wall (-10 would be wrong)
    assert cached.snapshot.cache_age_seconds >= 0.0  # never negative
    assert cached.snapshot.generated_at == 100.0  # build timestamp unaffected by the step


def test_refresh_keyed_on_monotonic_survives_wall_clock_step_back() -> None:
    # Even if the wall clock jumps backward, once the monotonic age crosses the refresh
    # interval the snapshot rebuilds (the old single-clock code would freeze forever).
    mono = _Clock()
    wall = _Clock()
    wall.now = 100.0
    builder, state = _counting_builder()
    cache = SnapshotCache(
        builder, refresh_interval=5.0, stale_after=60.0, clock=mono, wall_clock=wall
    )

    cache.get()  # mono=0 -> total 1
    wall.now = 50.0  # wall clock steps far backward
    mono.now = 6.0  # monotonic crosses the refresh interval
    refreshed = cache.get()

    assert state["calls"] == 2  # rebuilt despite the backward wall step
    assert refreshed.snapshot.freshness is FreshnessState.LIVE
