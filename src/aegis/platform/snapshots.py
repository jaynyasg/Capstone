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
from aegis.platform.store import SCHEMA_VERSION, FreshnessState, SnapshotMeta


class SnapshotCache:
    """Time-boxed cache for the default platform overview with freshness labelling."""

    def __init__(
        self,
        builder: Callable[[], PlatformOverview],
        *,
        refresh_interval: float = 5.0,
        stale_after: float = 60.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._builder = builder
        self._refresh_interval = max(0.0, refresh_interval)
        self._stale_after = stale_after
        self._clock = clock
        self._cached: PlatformOverview | None = None
        self._generated_at = 0.0

    def get(self) -> PlatformOverview:
        """Return the overview, rebuilding when the cache is empty or past its refresh window."""
        now = self._clock()
        if self._cached is None or (now - self._generated_at) >= self._refresh_interval:
            overview = self._builder()
            self._cached = overview
            self._generated_at = now
            return overview.model_copy(
                update={"snapshot": self._meta(now, FreshnessState.LIVE, 0.0, "live")}
            )
        age = now - self._generated_at
        freshness = FreshnessState.STALE if age >= self._stale_after else FreshnessState.CACHED
        # Reuse cached counts/windows but refresh only the freshness metadata. The cached
        # overview keeps its health, so warnings remain visible on a cached/stale read.
        return self._cached.model_copy(
            update={"snapshot": self._meta(self._generated_at, freshness, age, "cache")}
        )

    def invalidate(self) -> None:
        self._cached = None

    def _meta(
        self, generated_at: float, freshness: FreshnessState, age: float, source: str
    ) -> SnapshotMeta:
        return SnapshotMeta(
            schema_version=SCHEMA_VERSION,
            generated_at=generated_at,
            freshness=freshness,
            cache_age_seconds=age,
            refresh_source=source,
            stale_after_seconds=self._stale_after,
        )
