"""Local-file-backed platform evidence overview.

The collector reads the artifacts Aegis already produces: local trace JSONL, eval
metrics, CIFT certificates, and safe honeytoken records. It does not introduce a
database or active actions; it turns the existing SDK/proxy evidence into one typed
platform contract for the gateway and dashboard.
"""

from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from aegis.config import Settings
from aegis.detectors._credutil import redact_text


class PlatformStatus(BaseModel):
    """Runtime status for the gateway process serving the platform view."""

    gateway: str = "ok"
    provider: str
    policy_mode: str
    braintrust: bool
    ml_probe: bool
    traces_dir: str
    reports_dir: str


class DecisionOverview(BaseModel):
    """Aggregate view of recent guarded decisions."""

    total: int = 0
    by_action: dict[str, int] = Field(default_factory=dict)
    by_phase: dict[str, int] = Field(default_factory=dict)
    detector_hits: dict[str, int] = Field(default_factory=dict)
    recent: list[dict[str, Any]] = Field(default_factory=list)


class CiftOverview(BaseModel):
    """Summary of stored model calibration/certification evidence."""

    total: int = 0
    by_level: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    latest: list[dict[str, Any]] = Field(default_factory=list)


class CanaryOverview(BaseModel):
    """Summary of planted canaries without raw honeytoken values."""

    total: int = 0
    by_service: dict[str, int] = Field(default_factory=dict)
    by_format: dict[str, int] = Field(default_factory=dict)
    latest: list[dict[str, Any]] = Field(default_factory=list)


class SessionRiskOverview(BaseModel):
    """Latest known session-level risk from trace and Nimbus evidence."""

    session_id: str
    events: int
    last_seen: float
    nimbus_cumulative_score: float = 0.0
    latest_action: str = "ALLOW"


class PlatformOverview(BaseModel):
    """Single platform contract consumed by the gateway API and dashboard."""

    generated_at: float = Field(default_factory=time.time)
    status: PlatformStatus
    decisions: DecisionOverview
    evals: dict[str, dict[str, Any]] = Field(default_factory=dict)
    cift: CiftOverview
    canaries: CanaryOverview
    sessions: list[SessionRiskOverview] = Field(default_factory=list)
    evidence_paths: dict[str, str] = Field(default_factory=dict)


def collect_platform_overview(
    *,
    settings: Settings,
    provider_name: str,
    braintrust_enabled: bool,
    ml_probe_available: bool,
    reports_dir: Path | str,
    canaries: list[Any] | None = None,
    certifications: list[Any] | None = None,
    metrics: dict[str, Any] | None = None,
    decision_limit: int = 25,
) -> PlatformOverview:
    """Collect a read-only overview from local Aegis evidence artifacts."""

    reports_path = Path(reports_dir)
    cift_path = settings.traces_dir.parent / "cift" / "certifications.jsonl"
    events = load_trace_events(settings.traces_dir, limit=None)
    eval_metrics = metrics if metrics is not None else load_eval_metrics(reports_path)
    cift_records = certifications if certifications is not None else load_jsonl_records(cift_path)
    canary_records = canaries if canaries is not None else _canaries_from_traces(events)

    return PlatformOverview(
        status=PlatformStatus(
            provider=provider_name,
            policy_mode=str(settings.policy_mode),
            braintrust=braintrust_enabled,
            ml_probe=ml_probe_available,
            traces_dir=str(settings.traces_dir),
            reports_dir=str(reports_path),
        ),
        decisions=_summarize_decisions(events, decision_limit),
        evals=eval_metrics or {},
        cift=_summarize_cift(cift_records, decision_limit),
        canaries=_summarize_canaries(canary_records, decision_limit),
        sessions=_summarize_sessions(events),
        evidence_paths={
            "traces": str(settings.traces_dir),
            "evals": str(reports_path),
            "cift": str(cift_path),
        },
    )


def load_trace_events(traces_dir: Path | str, limit: int | None = 25) -> list[dict[str, Any]]:
    """Read recent redacted trace events from local JSONL files."""

    rows = load_jsonl_records(traces_dir)
    return rows[:limit] if limit is not None else rows


def load_eval_metrics(reports_dir: Path | str) -> dict[str, Any] | None:
    """Read eval metrics JSON if present; corrupt or absent artifacts degrade to empty."""

    path = Path(reports_dir) / "metrics.json"
    if not path.exists():
        return None
    try:
        metrics = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return metrics if isinstance(metrics, dict) else None


def load_jsonl_records(path_or_dir: Path | str) -> list[dict[str, Any]]:
    """Read JSONL records from a file or directory; bad local artifacts are ignored."""

    path = Path(path_or_dir)
    if not path.exists():
        return []
    files = sorted(path.glob("*.jsonl")) if path.is_dir() else [path]
    rows: list[dict[str, Any]] = []
    for file_path in files:
        try:
            lines = file_path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    rows.sort(key=lambda r: r.get("created_at", 0.0), reverse=True)
    return rows


def _summarize_decisions(events: list[dict[str, Any]], limit: int) -> DecisionOverview:
    action_counts: Counter[str] = Counter()
    phase_counts: Counter[str] = Counter()
    detector_counts: Counter[str] = Counter()
    recent: list[dict[str, Any]] = []
    for event in events:
        decision = _record_dict(event.get("policy_decision"))
        action = str(decision.get("action", "ALLOW"))
        phase = str(event.get("phase", "?"))
        action_counts[action] += 1
        phase_counts[phase] += 1
        fired = _fired_detectors(decision)
        detector_counts.update(fired)
        recent.append(
            {
                "event_id": event.get("event_id"),
                "created_at": event.get("created_at"),
                "session_id": event.get("session_id"),
                "phase": phase,
                "tool_name": event.get("tool_name"),
                "action": action,
                "risk_score": decision.get("risk_score", 0.0),
                "detectors": fired,
                "summary": redact_text(str(event.get("input_summary", ""))),
            }
        )
    return DecisionOverview(
        total=len(events),
        by_action=dict(action_counts),
        by_phase=dict(phase_counts),
        detector_hits=dict(detector_counts),
        recent=recent[:limit],
    )


def _summarize_cift(records: list[Any], limit: int) -> CiftOverview:
    rows = [_record_dict(record) for record in records]
    by_level = Counter(str(r.get("level", "unknown")) for r in rows)
    by_status = Counter(str(r.get("status", "unknown")) for r in rows)
    latest = [
        _redact_jsonish(record)
        for record in sorted(rows, key=lambda r: r.get("created_at", 0.0), reverse=True)[:limit]
    ]
    return CiftOverview(
        total=len(rows),
        by_level=dict(by_level),
        by_status=dict(by_status),
        latest=latest,
    )


def _summarize_canaries(records: list[Any], limit: int) -> CanaryOverview:
    rows = [_record_dict(record) for record in records]
    by_service = Counter(str(r.get("service", "unknown")) for r in rows)
    by_format = Counter(str(r.get("format_slug", "unknown")) for r in rows)
    latest = [
        _safe_canary_record(record)
        for record in sorted(rows, key=lambda r: r.get("planted_at", 0.0), reverse=True)[:limit]
    ]
    return CanaryOverview(
        total=len(rows),
        by_service=dict(by_service),
        by_format=dict(by_format),
        latest=latest,
    )


def _summarize_sessions(events: list[dict[str, Any]]) -> list[SessionRiskOverview]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        grouped[str(event.get("session_id", "unknown"))].append(event)

    sessions: list[SessionRiskOverview] = []
    for session_id, rows in grouped.items():
        rows.sort(key=lambda r: r.get("created_at", 0.0), reverse=True)
        latest = rows[0]
        latest_decision = _record_dict(latest.get("policy_decision"))
        sessions.append(
            SessionRiskOverview(
                session_id=session_id,
                events=len(rows),
                last_seen=float(latest.get("created_at", 0.0) or 0.0),
                nimbus_cumulative_score=_latest_nimbus_score(rows),
                latest_action=str(latest_decision.get("action", "ALLOW")),
            )
        )
    sessions.sort(key=lambda s: s.last_seen, reverse=True)
    return sessions


def _canaries_from_traces(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for event in events:
        metadata = _record_dict(event.get("metadata"))
        event_type = metadata.get("event_type")
        if event_type != "canary_planted" and event.get("phase") != "canary_plant":
            continue
        canary_id = str(metadata.get("canary_id") or event.get("event_id") or "unknown")
        if canary_id in seen:
            continue
        seen.add(canary_id)
        records.append(
            {
                "canary_id": canary_id,
                "service": metadata.get("service", "unknown"),
                "session_id": event.get("session_id", "unknown"),
                "plant_location": metadata.get("plant_location", "unknown"),
                "planted_at": event.get("created_at", 0.0),
                "format_slug": metadata.get("format_slug", "unknown"),
                "provider_valid": metadata.get("provider_valid", False),
                "safety_note": metadata.get("safety_note", ""),
                "spec_hash": metadata.get("spec_hash", ""),
            }
        )
    records.sort(key=lambda r: r.get("planted_at", 0.0), reverse=True)
    return records


def _latest_nimbus_score(events: list[dict[str, Any]]) -> float:
    for event in events:
        decision = _record_dict(event.get("policy_decision"))
        for raw_hit in decision.get("detector_hits", []):
            hit = _record_dict(raw_hit)
            if hit.get("detector_name") == "nimbus_lite_ledger":
                evidence = _record_dict(hit.get("evidence"))
                try:
                    return float(evidence.get("cumulative_score", 0.0) or 0.0)
                except (TypeError, ValueError):
                    return 0.0
    return 0.0


def _fired_detectors(decision: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for raw_hit in decision.get("detector_hits", []):
        hit = _record_dict(raw_hit)
        action = hit.get("recommended_action")
        if action not in (None, "ALLOW"):
            names.append(str(hit.get("detector_name", "unknown")))
    return names


def _record_dict(record: Any) -> dict[str, Any]:
    if hasattr(record, "model_dump"):
        return record.model_dump()
    if isinstance(record, dict):
        return dict(record)
    return {}


def _safe_canary_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        str(key): _redact_jsonish(value)
        for key, value in record.items()
        if key not in {"token", "normalized"}
    }


def _redact_jsonish(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [_redact_jsonish(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _redact_jsonish(v) for k, v in value.items()}
    return value
