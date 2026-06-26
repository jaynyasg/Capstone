"""U2 — SQLite EvidenceStore: bounded reads, truthful totals, idempotent import, health.

The store replaces eager all-row aggregation: ``total`` comes from ``COUNT(*)`` and the
window from ``LIMIT``, so reads stay bounded as evidence grows. Import is idempotent and
records structured health rather than silently dropping corrupt rows. The store is also
state worth backing up, so it must never persist raw secrets.
"""

from __future__ import annotations

import json
from pathlib import Path

from aegis import PolicyMode, Settings
from aegis.platform import importers
from aegis.platform.evidence import collect_platform_overview
from aegis.platform.importers import import_cift_jsonl, import_trace_events
from aegis.platform.sqlite_store import SqliteEvidenceStore, build_overview_from_store
from aegis.platform.store import EvidenceQuery, HealthStatus
from tests.conftest import FAKE_GITHUB_PAT


def _count_loader(monkeypatch) -> dict:
    """Wrap importers.load_jsonl_with_health with a call counter (the per-request re-read)."""
    calls = {"n": 0}
    real = importers.load_jsonl_with_health

    def counting(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(importers, "load_jsonl_with_health", counting)
    return calls


def _event(
    i: int,
    *,
    session: str = "s1",
    phase: str = "response",
    action: str = "ALLOW",
    detectors: list | None = None,
    created: float | None = None,
) -> dict:
    return {
        "event_id": f"evt_{i}",
        "created_at": float(i if created is None else created),
        "session_id": session,
        "phase": phase,
        "input_summary": f"event {i}",
        "policy_decision": {
            "action": action,
            "risk_score": 0.0,
            "detector_hits": detectors or [],
        },
    }


def _write_trace(traces: Path, rows: list[dict], name: str = "s1.jsonl") -> None:
    traces.mkdir(parents=True, exist_ok=True)
    (traces / name).write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def test_store_initializes_without_existing_file(tmp_path) -> None:
    db = tmp_path / "platform" / "evidence.db"
    store = SqliteEvidenceStore(db)
    assert db.exists()  # created deterministically under the temp state dir
    window = store.decisions()
    assert window.total == 0
    assert window.latest == []
    assert store.health().status is HealthStatus.HEALTHY


def test_import_then_bounded_query_reports_truthful_total(tmp_path) -> None:
    traces = tmp_path / "traces"
    _write_trace(traces, [_event(i, action="BLOCK" if i % 2 else "ALLOW") for i in range(30)])
    store = SqliteEvidenceStore(tmp_path / "platform" / "evidence.db")
    import_trace_events(store, traces)

    window = store.decisions(EvidenceQuery(limit=10))
    assert window.total == 30  # all matching records
    assert len(window.latest) == 10  # bounded window only
    assert window.latest[0]["created_at"] == 29.0  # newest first


def test_repeated_import_does_not_duplicate_rows(tmp_path) -> None:
    traces = tmp_path / "traces"
    _write_trace(traces, [_event(i) for i in range(5)])
    store = SqliteEvidenceStore(tmp_path / "platform" / "evidence.db")
    import_trace_events(store, traces)
    import_trace_events(store, traces)  # same artifact, second pass
    assert store.decisions().total == 5


def test_unchanged_source_skips_reimport(tmp_path, monkeypatch) -> None:
    traces = tmp_path / "traces"
    _write_trace(traces, [_event(i) for i in range(3)])
    store = SqliteEvidenceStore(tmp_path / "platform" / "evidence.db")
    calls = _count_loader(monkeypatch)

    import_trace_events(store, traces)  # first import reads the corpus
    import_trace_events(store, traces)  # unchanged source -> must skip the re-read/parse

    assert calls["n"] == 1  # the second import did not re-read the corpus
    assert store.decisions().total == 3  # data from the first import is intact


def test_changed_source_triggers_reimport(tmp_path, monkeypatch) -> None:
    traces = tmp_path / "traces"
    _write_trace(traces, [_event(0)])
    store = SqliteEvidenceStore(tmp_path / "platform" / "evidence.db")
    calls = _count_loader(monkeypatch)

    import_trace_events(store, traces)  # reads (1)
    _write_trace(traces, [_event(1)], name="s2.jsonl")  # new file -> source changed
    import_trace_events(store, traces)  # changed source -> re-reads (2)

    assert calls["n"] == 2
    assert store.decisions().total == 2  # the appended evidence was picked up


def test_corrupt_line_warns_but_imports_valid_rows(tmp_path) -> None:
    traces = tmp_path / "traces"
    traces.mkdir(parents=True)
    (traces / "s1.jsonl").write_text(
        json.dumps(_event(1, action="BLOCK")) + "\n{bad json}\n" + json.dumps(_event(2)) + "\n",
        encoding="utf-8",
    )
    store = SqliteEvidenceStore(tmp_path / "platform" / "evidence.db")
    warnings = import_trace_events(store, traces)

    assert store.decisions().total == 2  # the two valid rows survived
    kinds = {(w.source_kind, w.warning_type.value) for w in warnings}
    assert ("traces", "corrupt_row") in kinds
    assert store.health().status is HealthStatus.DEGRADED


def test_cift_total_exceeds_visible_window(tmp_path) -> None:
    cift = tmp_path / "cift" / "certifications.jsonl"
    cift.parent.mkdir(parents=True)
    rows = [
        {
            "certification_id": f"c{i}",
            "created_at": float(i),
            "model_id": "llama-local",
            "level": "gateway_calibrated",
            "status": "WARN",
        }
        for i in range(8)
    ]
    cift.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    store = SqliteEvidenceStore(tmp_path / "platform" / "evidence.db")
    import_cift_jsonl(store, cift)

    window = store.cift(EvidenceQuery(limit=3))
    assert window.total == 8
    assert len(window.latest) == 3
    assert window.latest[0]["certification_id"] == "c7"  # newest first


def test_store_window_never_persists_raw_secret(tmp_path) -> None:
    # Traces are redacted at write time, but the store is durable state worth backing up —
    # it must re-redact on import so a raw secret never lands on disk in the db file.
    traces = tmp_path / "traces"
    _write_trace(
        traces,
        [
            {
                "event_id": "evt_secret",
                "created_at": 1.0,
                "session_id": "s1",
                "phase": "response",
                "input_summary": f"leak {FAKE_GITHUB_PAT}",
                "policy_decision": {"action": "BLOCK", "risk_score": 1.0, "detector_hits": []},
            }
        ],
    )
    db = tmp_path / "platform" / "evidence.db"
    store = SqliteEvidenceStore(db)
    import_trace_events(store, traces)

    window = store.decisions()
    assert FAKE_GITHUB_PAT not in str(window.model_dump())
    assert FAKE_GITHUB_PAT not in db.read_bytes().decode("latin-1")


def test_store_overview_matches_file_overview_decisions(tmp_path) -> None:
    traces = tmp_path / "traces"
    rows = [
        _event(
            1,
            action="BLOCK",
            phase="tool_call",
            detectors=[
                {
                    "detector_name": "tool_call_argument_scanner",
                    "recommended_action": "BLOCK",
                    "score": 1.0,
                }
            ],
        ),
        _event(2, action="ALLOW", phase="response", detectors=[]),
        _event(
            3,
            action="WARN",
            phase="response",
            detectors=[
                {
                    "detector_name": "nimbus_lite_ledger",
                    "recommended_action": "WARN",
                    "score": 0.6,
                    "evidence": {"cumulative_score": 0.6},
                }
            ],
        ),
    ]
    _write_trace(traces, rows)
    settings = Settings(policy_mode=PolicyMode.BALANCED, traces_dir=traces)

    file_overview = collect_platform_overview(
        settings=settings,
        provider_name="mock",
        braintrust_enabled=False,
        ml_probe_available=False,
        reports_dir=tmp_path / "reports",
        certifications=[],
        canaries=[],
    ).model_dump()

    store = SqliteEvidenceStore(settings.evidence_db_path)
    store_overview = build_overview_from_store(
        store=store,
        settings=settings,
        provider_name="mock",
        braintrust_enabled=False,
        ml_probe_available=False,
        reports_dir=tmp_path / "reports",
        certifications=[],
        canaries=[],
    ).model_dump()

    decisions_store = store_overview["decisions"]
    decisions_file = file_overview["decisions"]
    assert decisions_store["total"] == decisions_file["total"]
    assert decisions_store["by_action"] == decisions_file["by_action"]
    assert decisions_store["by_phase"] == decisions_file["by_phase"]
    assert decisions_store["detector_hits"] == decisions_file["detector_hits"]
    assert store_overview["schema_version"] == file_overview["schema_version"]
    assert store_overview["sessions"][0]["session_id"] == "s1"


def test_store_sessions_reflect_latest_action_and_nimbus(tmp_path) -> None:
    traces = tmp_path / "traces"
    _write_trace(
        traces,
        [
            _event(1, session="risky", action="ALLOW", created=1.0),
            _event(
                2,
                session="risky",
                action="BLOCK",
                created=9.0,
                detectors=[
                    {
                        "detector_name": "nimbus_lite_ledger",
                        "recommended_action": "WARN",
                        "score": 0.6,
                        "evidence": {"cumulative_score": 1.4},
                    }
                ],
            ),
        ],
    )
    store = SqliteEvidenceStore(tmp_path / "platform" / "evidence.db")
    import_trace_events(store, traces)

    window = store.sessions()
    assert window.total == 1  # one distinct session
    session = window.latest[0]
    assert session["session_id"] == "risky"
    assert session["events"] == 2
    assert session["latest_action"] == "BLOCK"  # newest event's action
    assert session["nimbus_cumulative_score"] == 1.4


def test_store_session_nimbus_uses_max_not_trailing_event(tmp_path) -> None:
    # The nimbus ledger is monotonic, so a session's risk is its peak score. A trailing
    # event with no nimbus detector (e.g. a benign canary plant, nimbus 0) must not zero
    # the session's reported cumulative score.
    traces = tmp_path / "traces"
    _write_trace(
        traces,
        [
            _event(1, session="risky", action="ALLOW", created=1.0),
            _event(
                2,
                session="risky",
                action="BLOCK",
                created=5.0,
                detectors=[
                    {
                        "detector_name": "nimbus_lite_ledger",
                        "recommended_action": "WARN",
                        "score": 0.6,
                        "evidence": {"cumulative_score": 1.4},
                    }
                ],
            ),
            _event(3, session="risky", action="ALLOW", created=9.0),  # trailing plant, nimbus 0
        ],
    )
    store = SqliteEvidenceStore(tmp_path / "platform" / "evidence.db")
    import_trace_events(store, traces)

    session = store.sessions().latest[0]
    assert session["events"] == 3
    assert session["latest_action"] == "ALLOW"  # newest event's action (event 3)
    assert session["nimbus_cumulative_score"] == 1.4  # MAX over session, not the trailing 0
