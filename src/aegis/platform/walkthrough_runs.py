"""Replayable walkthrough run artifacts for the operator dashboard.

The live dashboard already shows what happened during a walkthrough. This module makes that
finished run durable: a redacted JSON artifact that can be loaded later and replayed without
calling the guards again.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path
from typing import Any

from aegis.detectors._credutil import redact_text
from aegis.platform.store import SCHEMA_VERSION

RUN_SCHEMA_VERSION = 1
DEFAULT_RUN_LIMIT = 10
MAX_RUN_LIMIT = 50
MAX_RUN_BYTES = 500_000

_RUN_ID_RE = re.compile(r"^[0-9TZA-Fa-f-]+$")


def _utc_stamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def _iso_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _new_run_id() -> str:
    return f"{_utc_stamp()}-{uuid.uuid4().hex[:8]}"


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _redact_value(item) for key, item in value.items()}
    return value


def _safe_run_id(run_id: str) -> str:
    if not _RUN_ID_RE.match(run_id):
        raise ValueError("invalid walkthrough run id")
    return run_id


def _run_path(root: Path, run_id: str) -> Path:
    return root / f"{_safe_run_id(run_id)}.json"


def _read_run(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _metadata(run: dict[str, Any]) -> dict[str, Any]:
    steps = run.get("steps", [])
    return {
        "id": run.get("id", ""),
        "createdAt": run.get("createdAt", ""),
        "completedAt": run.get("completedAt", ""),
        "startedAt": run.get("startedAt", ""),
        "policyMode": run.get("policyMode", ""),
        "scenario": run.get("scenario", ""),
        "guardCall": run.get("guardCall", ""),
        "liveResponses": run.get("liveResponses", 0),
        "detectorHits": run.get("detectorHits", "none"),
        "steps": len(steps) if isinstance(steps, list) else 0,
        "replayable": True,
    }


def _clamp_limit(limit: int) -> int:
    if limit < 1:
        return DEFAULT_RUN_LIMIT
    return min(limit, MAX_RUN_LIMIT)


def save_walkthrough_run(root: Path | str, payload: dict[str, Any]) -> dict[str, Any]:
    """Save one redacted walkthrough run and return the replayable artifact."""
    if not isinstance(payload, dict):
        raise ValueError("walkthrough run must be a JSON object")

    run = _redact_value(payload)
    if not isinstance(run.get("steps"), list) or not run["steps"]:
        raise ValueError("walkthrough run requires at least one step")

    run_id = _new_run_id()
    run["id"] = run_id
    run["version"] = RUN_SCHEMA_VERSION
    run["createdAt"] = _iso_utc()
    run["replayable"] = True

    encoded = json.dumps(run, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    if len(encoded) > MAX_RUN_BYTES:
        raise ValueError("walkthrough run is too large to save")

    root_path = Path(root)
    root_path.mkdir(parents=True, exist_ok=True)
    tmp = root_path / f"{run_id}.tmp"
    final = _run_path(root_path, run_id)
    tmp.write_bytes(encoded)
    tmp.replace(final)
    return run


def load_walkthrough_run(root: Path | str, run_id: str) -> dict[str, Any] | None:
    """Load one replayable run by id, or ``None`` when it is absent/corrupt."""
    try:
        path = _run_path(Path(root), run_id)
    except ValueError:
        return None
    if not path.exists():
        return None
    return _read_run(path)


def list_walkthrough_runs(root: Path | str, limit: int = DEFAULT_RUN_LIMIT) -> dict[str, Any]:
    """List recent replayable run metadata, newest first."""
    root_path = Path(root)
    if not root_path.exists():
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "walkthrough_runs",
            "total": 0,
            "latest": [],
        }

    runs: list[tuple[float, dict[str, Any]]] = []
    for path in root_path.glob("*.json"):
        run = _read_run(path)
        if run is None:
            continue
        runs.append((path.stat().st_mtime, run))

    runs.sort(key=lambda item: item[0], reverse=True)
    window = [_metadata(run) for _, run in runs[: _clamp_limit(limit)]]
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "walkthrough_runs",
        "total": len(runs),
        "latest": window,
    }
