"""Project local JSONL artifacts into the SQLite evidence store (U2).

Importers parse, **redact**, and shape rows before handing them to the store, so the store
stays a dumb persistence layer and redaction lives in exactly one place. Imports are
idempotent (the store upserts on primary keys) and health-aware: a corrupt or unreadable
source produces a structured warning rather than silently dropping evidence. Raw JSONL
remains the replayable source of truth (KTD4).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aegis.detectors._credutil import redact_text
from aegis.platform.evidence import (
    SENSITIVE_CANARY_KEYS,
    _canaries_from_traces,
    _record_dict,
    _redact_jsonish,
    load_jsonl_with_health,
)
from aegis.platform.store import HealthWarning

if TYPE_CHECKING:
    from aegis.platform.sqlite_store import SqliteEvidenceStore


def import_trace_events(store: SqliteEvidenceStore, traces_dir: Path | str) -> list[HealthWarning]:
    """Import redacted decision rows (and planted canaries) from trace JSONL files."""
    rows, warnings = load_jsonl_with_health(traces_dir, source_kind="traces")
    store.upsert_events([_event_row(row) for row in rows])
    canaries = [_safe_canary(record) for record in _canaries_from_traces(rows)]
    if canaries:
        store.upsert_canaries(canaries)
    store.set_warnings("traces", warnings)
    store.record_checkpoint("traces", str(Path(traces_dir)), row_count=len(rows))
    return warnings


def import_cift_jsonl(store: SqliteEvidenceStore, cift_path: Path | str) -> list[HealthWarning]:
    """Import CIFT certificates from their JSONL store."""
    rows, warnings = load_jsonl_with_health(cift_path, source_kind="cift")
    store.upsert_cift([_cift_row(row) for row in rows])
    store.set_warnings("cift", warnings)
    store.record_checkpoint("cift", str(Path(cift_path)), row_count=len(rows))
    return warnings


def import_cift_records(store: SqliteEvidenceStore, records: list[Any]) -> None:
    """Import CIFT certificates already held in memory (e.g. from the gateway store)."""
    store.upsert_cift([_cift_row(record) for record in records])


def import_canary_records(store: SqliteEvidenceStore, records: list[Any]) -> None:
    """Import safe canary metadata (never raw token material)."""
    store.upsert_canaries([_safe_canary(record) for record in records])


# ----- row transforms (parse + redact + shape) --------------------------


def _event_row(raw: dict[str, Any]) -> dict[str, Any]:
    decision = _record_dict(raw.get("policy_decision"))
    detectors: list[dict[str, Any]] = []
    nimbus = 0.0
    for hit in decision.get("detector_hits", []):
        data = _record_dict(hit)
        name = str(data.get("detector_name", "unknown"))
        action = data.get("recommended_action")
        detectors.append(
            {
                "detector_name": name,
                "recommended_action": None if action is None else str(action),
                "score": _as_float(data.get("score")),
                "fired": action not in (None, "ALLOW"),
            }
        )
        if name == "nimbus_lite_ledger":
            nimbus = _as_float(_record_dict(data.get("evidence")).get("cumulative_score"))
    return {
        "event_id": str(raw.get("event_id") or _surrogate_id(raw)),
        "created_at": _as_float(raw.get("created_at")),
        "session_id": str(raw.get("session_id", "unknown")),
        "phase": str(raw.get("phase", "?")),
        "action": str(decision.get("action", "ALLOW")),
        "tool_name": raw.get("tool_name"),
        "risk_score": _as_float(decision.get("risk_score")),
        "nimbus_score": nimbus,
        # Traces are redacted at write time; re-redact so the durable store never holds a
        # raw secret even if an upstream artifact slipped one through.
        "summary": redact_text(str(raw.get("input_summary", ""))),
        "detectors": detectors,
    }


def _cift_row(raw: Any) -> dict[str, Any]:
    record = _record_dict(raw)
    return {
        "certification_id": str(record.get("certification_id") or _surrogate_id(record)),
        "created_at": _as_float(record.get("created_at")),
        "model_id": str(record.get("model_id", "unknown")),
        "level": str(record.get("level", "unknown")),
        "status": str(record.get("status", "unknown")),
        "record_json": json.dumps(_redact_jsonish(record), default=str),
    }


def _safe_canary(raw: Any) -> dict[str, Any]:
    record = _record_dict(raw)
    safe = _redact_jsonish(
        {key: value for key, value in record.items() if key not in SENSITIVE_CANARY_KEYS}
    )
    return {
        "canary_id": str(safe.get("canary_id", "unknown")),
        "lifecycle_state": str(safe.get("lifecycle_state", "planted")),
        "service": str(safe.get("service", "unknown")),
        "format_slug": str(safe.get("format_slug", "unknown")),
        "session_id": safe.get("session_id"),
        "plant_location": safe.get("plant_location"),
        "planted_at": _as_float(safe.get("planted_at")),
        "provider_valid": bool(safe.get("provider_valid")),
        "safety_note": safe.get("safety_note", ""),
        "spec_hash": safe.get("spec_hash", ""),
    }


def _as_float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _surrogate_id(raw: dict[str, Any]) -> str:
    """Stable surrogate key for rows missing an id, so dedup still works across imports."""
    basis = json.dumps(
        {key: raw.get(key) for key in ("created_at", "session_id", "phase", "input_summary")},
        sort_keys=True,
        default=str,
    )
    return "row_" + hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]
