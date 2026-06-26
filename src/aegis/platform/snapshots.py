"""Overview snapshot cache and freshness semantics (U6).

The platform overview is the heaviest read — it imports artifacts and aggregates them. Under
a dashboard that auto-refreshes every few seconds, recomputing it on every request is
wasteful. :class:`SnapshotCache` memoizes the default overview for a short window and labels
every served overview with explicit freshness (live / cached / stale), so an operator can
always tell whether they are looking at a just-built read or a reused one.

Two thresholds, deliberately independent (see KTD9):

* ``refresh_interval`` — rebuild once the cached snapshot is older than this (default 5s, the
  dashboard's refresh cadence). ``0`` disables caching entirely (every read rebuilds), which
  keeps tests deterministic.
* ``stale_after`` — label a served snapshot ``stale`` past this age (default 60s).

A cached read **never drops the health** the snapshot carried (R5/R18): warnings stay visible
even when counts are reused, so a stale or cached view can never hide a degraded source.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from aegis.platform.evidence import PlatformOverview
from aegis.platform.store import FreshnessState, SnapshotMeta


class SnapshotCache:
    """Time-boxed cache for the default platform overview with freshness labelling."""

    def __init__(
        self,
        builder: Callable[[], PlatformOverview],
        *,
        refresh_interval: float = 5.0,
        stale_after: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self._builder = builder
        self._refresh_interval = max(0.0, refresh_interval)
        self._stale_after = stale_after
        # ``clock`` drives age/refresh and must be monotonic, so a backward wall-clock step
        # (NTP correction) can neither freeze the cache nor show a negative age. ``wall_clock``
        # supplies only the human-readable ``generated_at`` instant.
        self._clock = clock
        self._wall_clock = wall_clock
        self._cached: PlatformOverview | None = None
        self._generated_at = 0.0  # monotonic reading at last build (for age/refresh)
        self._generated_wall = 0.0  # wall-clock instant at last build (for display)

    def get(self) -> PlatformOverview:
        """Return the overview, rebuilding when the cache is empty or past its refresh window."""
        now = self._clock()
        age = max(0.0, now - self._generated_at)  # clamp: monotonic should never regress
        if self._cached is None or age >= self._refresh_interval:
            overview = self._builder()
            self._cached = overview
            self._generated_at = now
            self._generated_wall = self._wall_clock()
            return overview.model_copy(
                update={"snapshot": self._meta(self._generated_wall, FreshnessState.LIVE, 0.0)}
            )
        freshness = FreshnessState.STALE if age >= self._stale_after else FreshnessState.CACHED
        # Reuse cached counts/windows but refresh only the freshness metadata. The cached
        # overview keeps its health, so warnings remain visible on a cached/stale read.
        return self._cached.model_copy(
            update={"snapshot": self._meta(self._generated_wall, freshness, age)}
        )

    def invalidate(self) -> None:
        self._cached = None

    def _meta(self, generated_at: float, freshness: FreshnessState, age: float) -> SnapshotMeta:
        return SnapshotMeta(
            generated_at=generated_at,
            freshness=freshness,
            cache_age_seconds=age,
            refresh_source="live" if freshness is FreshnessState.LIVE else "cache",
            stale_after_seconds=self._stale_after,
        )
