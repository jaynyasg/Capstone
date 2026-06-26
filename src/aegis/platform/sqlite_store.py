"""Local SQLite adapter for the platform evidence read model (U2).

Why SQLite: it is in the Python standard library (no hosted-database dependency, so the
offline verify gate stays deterministic — KTD3), supports bounded ``LIMIT`` windows and
``COUNT(*)`` totals over indexed columns, and gives the platform one local file to back up
alongside traces, CIFT records, and the canary vault (KTD13).

The store is a *read model*: raw JSONL artifacts remain the source of truth and replayable
fallback (KTD4); importers (``importers.py``) project validated, redacted rows into here.
Every public read returns truthful totals (``COUNT(*)``) with a bounded window (``LIMIT``),
so memory stays flat as evidence grows.

A connection is opened per operation (``check_same_thread`` is therefore a non-issue under
FastAPI's threadpool) and WAL is enabled best-effort for local read/write concurrency,
degrading gracefully where the journal mode cannot be switched.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aegis.platform.evidence import (
    CanaryOverview,
    CiftOverview,
    DecisionOverview,
    PlatformOverview,
    PlatformStatus,
    SessionRiskOverview,
    load_eval_metrics_with_health,
)
from aegis.platform.store import (
    SCHEMA_VERSION,
    EvidenceHealth,
    EvidenceQuery,
    FreshnessState,
    HealthSeverity,
    HealthWarning,
    RecordWindow,
    SnapshotMeta,
    WarningType,
)

if TYPE_CHECKING:
    from aegis.config import Settings

# Local persistent-state schema version, tracked separately from the API SCHEMA_VERSION so
# durable state can migrate independently of the response contract (KTD12).
LOCAL_SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_events (
    event_id    TEXT PRIMARY KEY,
    created_at  REAL NOT NULL DEFAULT 0,
    session_id  TEXT NOT NULL DEFAULT 'unknown',
    phase       TEXT NOT NULL DEFAULT '?',
    action      TEXT NOT NULL DEFAULT 'ALLOW',
    tool_name   TEXT,
    risk_score  REAL NOT NULL DEFAULT 0,
    nimbus_score REAL NOT NULL DEFAULT 0,
    summary     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_created ON evidence_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_session ON evidence_events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_action ON evidence_events(action);
CREATE INDEX IF NOT EXISTS idx_events_phase ON evidence_events(phase);

CREATE TABLE IF NOT EXISTS detector_hits (
    event_id          TEXT NOT NULL,
    detector_name     TEXT NOT NULL,
    recommended_action TEXT,
    score             REAL NOT NULL DEFAULT 0,
    fired             INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (event_id, detector_name)
);
CREATE INDEX IF NOT EXISTS idx_hits_detector ON detector_hits(detector_name);
CREATE INDEX IF NOT EXISTS idx_hits_fired ON detector_hits(fired);

CREATE TABLE IF NOT EXISTS canary_records (
    canary_id       TEXT PRIMARY KEY,
    lifecycle_state TEXT NOT NULL DEFAULT 'planted',
    service         TEXT NOT NULL DEFAULT 'unknown',
    format_slug     TEXT NOT NULL DEFAULT 'unknown',
    session_id      TEXT,
    plant_location  TEXT,
    planted_at      REAL NOT NULL DEFAULT 0,
    provider_valid  INTEGER NOT NULL DEFAULT 0,
    safety_note     TEXT,
    spec_hash       TEXT
);
CREATE INDEX IF NOT EXISTS idx_canary_planted ON canary_records(planted_at DESC);

CREATE TABLE IF NOT EXISTS cift_certifications (
    certification_id TEXT PRIMARY KEY,
    created_at       REAL NOT NULL DEFAULT 0,
    model_id         TEXT NOT NULL DEFAULT 'unknown',
    level            TEXT NOT NULL DEFAULT 'unknown',
    status           TEXT NOT NULL DEFAULT 'unknown',
    record_json      TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_cift_created ON cift_certifications(created_at DESC);

CREATE TABLE IF NOT EXISTS import_checkpoints (
    source_kind      TEXT NOT NULL,
    source_path      TEXT NOT NULL,
    last_imported_at REAL NOT NULL DEFAULT 0,
    row_count        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (source_kind, source_path)
);

CREATE TABLE IF NOT EXISTS health_warnings (
    source_kind  TEXT NOT NULL,
    source_path  TEXT,
    warning_type TEXT NOT NULL,
    severity     TEXT NOT NULL DEFAULT 'warning',
    detail       TEXT NOT NULL DEFAULT '',
    count        INTEGER NOT NULL DEFAULT 1
);
"""


class SqliteEvidenceStore:
    """Bounded SQLite read model satisfying the :class:`EvidenceStore` protocol."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # In-process import gate: source_path -> signature at its last import. Lets importers
        # skip re-reading an unchanged corpus within a running process. It is a memoisation
        # cache, not durable state — a restart re-imports once (cheap, idempotent upserts).
        self._import_signatures: dict[str, str] = {}
        try:
            self._init_schema()
        except sqlite3.DatabaseError:
            # evidence.db is a rebuildable cache (re-imported from JSONL); a corrupt file must
            # not brick the gateway — recreate it once rather than propagating the error.
            self.path.unlink(missing_ok=True)
            self._init_schema()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            if conn.execute("PRAGMA user_version").fetchone()[0] < LOCAL_SCHEMA_VERSION:
                conn.execute(f"PRAGMA user_version = {LOCAL_SCHEMA_VERSION}")

    # ----- connection ----------------------------------------------------

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.Error:
            pass  # WAL is an optimisation; default journal mode is fine for correctness.
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ----- writes (idempotent) -------------------------------------------

    def upsert_events(self, events: list[dict[str, Any]]) -> None:
        """Insert shaped, redacted event rows. Idempotent on ``event_id``."""
        if not events:
            return
        with self._connect() as conn:
            for ev in events:
                conn.execute(
                    """INSERT OR IGNORE INTO evidence_events
                       (event_id, created_at, session_id, phase, action, tool_name,
                        risk_score, nimbus_score, summary)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        ev["event_id"],
                        float(ev.get("created_at", 0.0) or 0.0),
                        ev.get("session_id", "unknown"),
                        ev.get("phase", "?"),
                        ev.get("action", "ALLOW"),
                        ev.get("tool_name"),
                        float(ev.get("risk_score", 0.0) or 0.0),
                        float(ev.get("nimbus_score", 0.0) or 0.0),
                        ev.get("summary", ""),
                    ),
                )
                for hit in ev.get("detectors", []):
                    conn.execute(
                        """INSERT OR IGNORE INTO detector_hits
                           (event_id, detector_name, recommended_action, score, fired)
                           VALUES (?,?,?,?,?)""",
                        (
                            ev["event_id"],
                            hit.get("detector_name", "unknown"),
                            hit.get("recommended_action"),
                            float(hit.get("score", 0.0) or 0.0),
                            1 if hit.get("fired") else 0,
                        ),
                    )

    def upsert_cift(self, records: list[dict[str, Any]]) -> None:
        if not records:
            return
        with self._connect() as conn:
            for rec in records:
                conn.execute(
                    """INSERT OR IGNORE INTO cift_certifications
                       (certification_id, created_at, model_id, level, status, record_json)
                       VALUES (?,?,?,?,?,?)""",
                    (
                        rec["certification_id"],
                        float(rec.get("created_at", 0.0) or 0.0),
                        rec.get("model_id", "unknown"),
                        rec.get("level", "unknown"),
                        rec.get("status", "unknown"),
                        rec.get("record_json", "{}"),
                    ),
                )

    def upsert_canaries(self, records: list[dict[str, Any]]) -> None:
        if not records:
            return
        with self._connect() as conn:
            for rec in records:
                # Newer lifecycle state should win (planted -> detected/expired), so replace.
                conn.execute(
                    """INSERT INTO canary_records
                       (canary_id, lifecycle_state, service, format_slug, session_id,
                        plant_location, planted_at, provider_valid, safety_note, spec_hash)
                       VALUES (?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(canary_id) DO UPDATE SET
                         lifecycle_state=excluded.lifecycle_state,
                         service=excluded.service,
                         format_slug=excluded.format_slug,
                         session_id=excluded.session_id,
                         plant_location=excluded.plant_location,
                         planted_at=excluded.planted_at,
                         provider_valid=excluded.provider_valid,
                         safety_note=excluded.safety_note,
                         spec_hash=excluded.spec_hash""",
                    (
                        rec["canary_id"],
                        rec.get("lifecycle_state", "planted"),
                        rec.get("service", "unknown"),
                        rec.get("format_slug", "unknown"),
                        rec.get("session_id"),
                        rec.get("plant_location"),
                        float(rec.get("planted_at", 0.0) or 0.0),
                        1 if rec.get("provider_valid") else 0,
                        rec.get("safety_note", ""),
                        rec.get("spec_hash", ""),
                    ),
                )

    def set_warnings(self, source_kind: str, warnings: list[HealthWarning]) -> None:
        """Replace all warnings for a source kind so fixed sources stop warning on re-import."""
        with self._connect() as conn:
            conn.execute("DELETE FROM health_warnings WHERE source_kind=?", (source_kind,))
            for w in warnings:
                conn.execute(
                    """INSERT INTO health_warnings
                       (source_kind, source_path, warning_type, severity, detail, count)
                       VALUES (?,?,?,?,?,?)""",
                    (
                        w.source_kind,
                        w.source_path,
                        w.warning_type.value,
                        w.severity.value,
                        w.detail,
                        w.count,
                    ),
                )

    def record_checkpoint(self, source_kind: str, source_path: str, *, row_count: int) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO import_checkpoints
                       (source_kind, source_path, last_imported_at, row_count)
                   VALUES (?,?,?,?)
                   ON CONFLICT(source_kind, source_path) DO UPDATE SET
                     last_imported_at=excluded.last_imported_at,
                     row_count=excluded.row_count""",
                (source_kind, source_path, time.time(), row_count),
            )

    def import_signature(self, source_path: str) -> str | None:
        """The source's change-signature at its last in-process import, or None if never seen."""
        return self._import_signatures.get(source_path)

    def set_import_signature(self, source_path: str, signature: str) -> None:
        self._import_signatures[source_path] = signature

    # ----- bounded reads -------------------------------------------------

    def decisions(self, query: EvidenceQuery | None = None) -> RecordWindow:
        query = query or EvidenceQuery()
        where, params = _event_where(query)
        with self._connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM evidence_events{where}", params
            ).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM evidence_events{where} "
                "ORDER BY created_at DESC, event_id DESC LIMIT ? OFFSET ?",
                (*params, query.limit, query.offset),
            ).fetchall()
            fired = self._fired_detectors_for(conn, [row["event_id"] for row in rows])
            latest = [_decision_row(row, fired.get(row["event_id"], [])) for row in rows]
        return RecordWindow(total=total, latest=latest, query=query)

    def sessions(self, query: EvidenceQuery | None = None) -> RecordWindow:
        query = query or EvidenceQuery()
        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(DISTINCT session_id) FROM evidence_events"
            ).fetchone()[0]
            rows = conn.execute(
                """SELECT session_id, events, last_seen, latest_action, nimbus_cumulative_score
                   FROM (
                     SELECT session_id,
                            COUNT(*) OVER (PARTITION BY session_id) AS events,
                            MAX(created_at) OVER (PARTITION BY session_id) AS last_seen,
                            action AS latest_action,
                            -- The nimbus ledger is monotonic, so a session's risk is its peak.
                            -- Taking MAX (not the latest row) stops a trailing nimbus-0 event
                            -- (e.g. a benign canary plant) from zeroing the session score.
                            MAX(nimbus_score) OVER (PARTITION BY session_id)
                              AS nimbus_cumulative_score,
                            ROW_NUMBER() OVER (
                              PARTITION BY session_id ORDER BY created_at DESC, event_id DESC
                            ) AS rn
                     FROM evidence_events
                   ) WHERE rn = 1
                   ORDER BY last_seen DESC LIMIT ? OFFSET ?""",
                (query.limit, query.offset),
            ).fetchall()
            latest = [dict(row) for row in rows]
        return RecordWindow(total=total, latest=latest, query=query)

    def detectors(self, query: EvidenceQuery | None = None) -> RecordWindow:
        query = query or EvidenceQuery()
        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(DISTINCT detector_name) FROM detector_hits WHERE fired=1"
            ).fetchone()[0]
            rows = conn.execute(
                """SELECT detector_name, COUNT(*) AS count FROM detector_hits
                   WHERE fired=1 GROUP BY detector_name
                   ORDER BY count DESC, detector_name ASC LIMIT ? OFFSET ?""",
                (query.limit, query.offset),
            ).fetchall()
            latest = [dict(row) for row in rows]
        return RecordWindow(total=total, latest=latest, query=query)

    def canaries(self, query: EvidenceQuery | None = None) -> RecordWindow:
        query = query or EvidenceQuery()
        clause = " WHERE session_id=?" if query.session_id else ""
        params: tuple[Any, ...] = (query.session_id,) if query.session_id else ()
        with self._connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM canary_records{clause}", params
            ).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM canary_records{clause} "
                "ORDER BY planted_at DESC, canary_id DESC LIMIT ? OFFSET ?",
                (*params, query.limit, query.offset),
            ).fetchall()
            latest = [_canary_dict(row) for row in rows]
        return RecordWindow(total=total, latest=latest, query=query)

    def cift(self, query: EvidenceQuery | None = None) -> RecordWindow:
        query = query or EvidenceQuery()
        clause = ""
        params: tuple[Any, ...] = ()
        if query.model_id:
            clause = " WHERE model_id=?"
            params = (query.model_id,)
        with self._connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM cift_certifications{clause}", params
            ).fetchone()[0]
            rows = conn.execute(
                f"SELECT record_json FROM cift_certifications{clause} "
                "ORDER BY created_at DESC, certification_id DESC LIMIT ? OFFSET ?",
                (*params, query.limit, query.offset),
            ).fetchall()
            latest = [_json_or_empty(row["record_json"]) for row in rows]
        return RecordWindow(total=total, latest=latest, query=query)

    def health(self) -> EvidenceHealth:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT source_kind, source_path, warning_type, severity, detail, count "
                "FROM health_warnings"
            ).fetchall()
        warnings = [
            HealthWarning(
                source_kind=row["source_kind"],
                source_path=row["source_path"],
                warning_type=WarningType(row["warning_type"]),
                severity=HealthSeverity(row["severity"]),
                detail=row["detail"],
                count=row["count"],
            )
            for row in rows
        ]
        return EvidenceHealth.from_warnings(warnings)

    # ----- typed sub-overviews (feed the assembler) ----------------------

    def decision_overview(self, query: EvidenceQuery | None = None) -> DecisionOverview:
        query = query or EvidenceQuery()
        window = self.decisions(query)
        with self._connect() as conn:
            by_action = _counts(
                conn, "SELECT action, COUNT(*) FROM evidence_events GROUP BY action"
            )
            by_phase = _counts(
                conn, "SELECT phase, COUNT(*) FROM evidence_events GROUP BY phase"
            )
            detector_hits = _counts(
                conn,
                "SELECT detector_name, COUNT(*) FROM detector_hits WHERE fired=1 "
                "GROUP BY detector_name",
            )
        return DecisionOverview(
            total=window.total,
            by_action=by_action,
            by_phase=by_phase,
            detector_hits=detector_hits,
            recent=window.latest,
        )

    def cift_overview(self, query: EvidenceQuery | None = None) -> CiftOverview:
        query = query or EvidenceQuery()
        window = self.cift(query)
        with self._connect() as conn:
            by_level = _counts(
                conn, "SELECT level, COUNT(*) FROM cift_certifications GROUP BY level"
            )
            by_status = _counts(
                conn, "SELECT status, COUNT(*) FROM cift_certifications GROUP BY status"
            )
        return CiftOverview(
            total=window.total, by_level=by_level, by_status=by_status, latest=window.latest
        )

    def canary_overview(self, query: EvidenceQuery | None = None) -> CanaryOverview:
        query = query or EvidenceQuery()
        window = self.canaries(query)
        with self._connect() as conn:
            by_service = _counts(
                conn, "SELECT service, COUNT(*) FROM canary_records GROUP BY service"
            )
            by_format = _counts(
                conn, "SELECT format_slug, COUNT(*) FROM canary_records GROUP BY format_slug"
            )
        return CanaryOverview(
            total=window.total, by_service=by_service, by_format=by_format, latest=window.latest
        )

    def session_overviews(self, query: EvidenceQuery | None = None) -> list[SessionRiskOverview]:
        window = self.sessions(query)
        return [
            SessionRiskOverview(
                session_id=str(row.get("session_id", "unknown")),
                events=int(row.get("events", 0)),
                last_seen=float(row.get("last_seen", 0.0) or 0.0),
                nimbus_cumulative_score=float(row.get("nimbus_cumulative_score", 0.0) or 0.0),
                latest_action=str(row.get("latest_action", "ALLOW")),
            )
            for row in window.latest
        ]

    # ----- helpers -------------------------------------------------------

    def _fired_detectors_for(
        self, conn: sqlite3.Connection, event_ids: list[str]
    ) -> dict[str, list[str]]:
        """Fired detector names grouped per event, fetched in one query (avoids an N+1 read)."""
        if not event_ids:
            return {}
        placeholders = ",".join("?" * len(event_ids))
        grouped: dict[str, list[str]] = {}
        for row in conn.execute(
            f"SELECT event_id, detector_name FROM detector_hits "
            f"WHERE fired=1 AND event_id IN ({placeholders}) ORDER BY detector_name",
            event_ids,
        ).fetchall():
            grouped.setdefault(row["event_id"], []).append(row["detector_name"])
        return grouped


def _decision_row(row: sqlite3.Row, fired: list[str]) -> dict[str, Any]:
    """Shape one evidence_events row + its pre-fetched fired detectors into a display dict."""
    return {
        "event_id": row["event_id"],
        "created_at": row["created_at"],
        "session_id": row["session_id"],
        "phase": row["phase"],
        "tool_name": row["tool_name"],
        "action": row["action"],
        "risk_score": row["risk_score"],
        "detectors": fired,
        "summary": row["summary"],
    }


def _event_where(query: EvidenceQuery) -> tuple[str, tuple[Any, ...]]:
    """Build a parameterised WHERE clause for evidence_events from active filters."""
    clauses: list[str] = []
    params: list[Any] = []
    if query.session_id:
        clauses.append("session_id=?")
        params.append(query.session_id)
    if query.action:
        clauses.append("action=?")
        params.append(query.action)
    if query.phase:
        clauses.append("phase=?")
        params.append(query.phase)
    if query.since is not None:
        clauses.append("created_at>=?")
        params.append(query.since)
    if query.until is not None:
        clauses.append("created_at<=?")
        params.append(query.until)
    if query.detector:
        clauses.append(
            "event_id IN (SELECT event_id FROM detector_hits WHERE detector_name=? AND fired=1)"
        )
        params.append(query.detector)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, tuple(params)


def _counts(conn: sqlite3.Connection, sql: str) -> dict[str, int]:
    return {str(k): int(v) for k, v in conn.execute(sql).fetchall()}


def _canary_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["provider_valid"] = bool(data.get("provider_valid"))
    return data


def _json_or_empty(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def sync_store(
    store: SqliteEvidenceStore,
    settings: Settings,
    *,
    certifications: list[Any] | None = None,
    canaries: list[Any] | None = None,
) -> None:
    """Idempotently import local artifacts into ``store`` (traces, CIFT, canaries).

    Shared by the overview builder and the drilldown endpoints so reads always see the same
    imported state. Raw JSONL remains the source of truth; re-importing is a cheap no-op.
    """
    from aegis.platform.importers import (
        import_canary_records,
        import_cift_jsonl,
        import_cift_records,
        import_trace_events,
    )

    import_trace_events(store, settings.traces_dir)
    if certifications is not None:
        import_cift_records(store, certifications)
    else:
        import_cift_jsonl(store, settings.cift_path)
    if canaries is not None:
        import_canary_records(store, canaries)


def build_overview_from_store(
    *,
    store: SqliteEvidenceStore,
    settings: Settings,
    provider_name: str,
    braintrust_enabled: bool,
    ml_probe_available: bool,
    reports_dir: Path | str,
    canaries: list[Any] | None = None,
    certifications: list[Any] | None = None,
    metrics: dict[str, Any] | None = None,
    extra_warnings: list[HealthWarning] | None = None,
    query: EvidenceQuery | None = None,
) -> PlatformOverview:
    """Import local artifacts into ``store`` (idempotently) and assemble a PlatformOverview.

    Mirrors :func:`aegis.platform.evidence.collect_platform_overview` but serves the bounded
    read model instead of eager in-memory aggregation. The store owns row evidence (decisions,
    CIFT, canaries, sessions, import health); this assembler adds runtime status, eval metrics,
    and ``extra_warnings`` (e.g. durable-canary key-loss health), which the store does not own.
    """
    if query is None:
        query = EvidenceQuery()
    reports_path = Path(reports_dir)
    cift_path = settings.cift_path

    sync_store(store, settings, certifications=certifications, canaries=canaries)

    if metrics is not None:
        eval_metrics: dict[str, Any] | None = metrics
        metrics_warnings: list[HealthWarning] = []
    else:
        eval_metrics, metrics_warnings = load_eval_metrics_with_health(reports_path)

    health = EvidenceHealth.from_warnings(
        store.health().warnings + metrics_warnings + list(extra_warnings or [])
    )

    return PlatformOverview(
        schema_version=SCHEMA_VERSION,
        query=query,
        snapshot=SnapshotMeta(generated_at=time.time(), freshness=FreshnessState.LIVE),
        health=health,
        status=PlatformStatus(
            provider=provider_name,
            policy_mode=str(settings.policy_mode),
            braintrust=braintrust_enabled,
            ml_probe=ml_probe_available,
            traces_dir=str(settings.traces_dir),
            reports_dir=str(reports_path),
        ),
        decisions=store.decision_overview(query),
        evals=eval_metrics or {},
        cift=store.cift_overview(query),
        canaries=store.canary_overview(query),
        sessions=store.session_overviews(query),
        evidence_paths={
            "traces": str(settings.traces_dir),
            "evals": str(reports_path),
            "cift": str(cift_path),
            "store": str(store.path),
        },
    )
