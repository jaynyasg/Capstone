"""Platform evidence overview aggregates local Aegis evidence surfaces."""

from __future__ import annotations

import json
from pathlib import Path

from aegis import AegisClient, PolicyMode, Settings
from aegis.cift import CiftCalibrationRequest, CiftCertificationStore, calibrate_model
from aegis.platform.evidence import collect_platform_overview, load_trace_events
from tests.conftest import FAKE_GITHUB_PAT
from tests.test_cift import _passing_metrics


def test_platform_overview_aggregates_runtime_evidence_without_raw_canaries(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr("aegis.tracing._try_braintrust", lambda: None)
    settings = Settings(policy_mode=PolicyMode.BALANCED, traces_dir=tmp_path / "traces")
    client = AegisClient(settings=settings)
    plant = client.plant_canary("github", session_id="platform-s1")
    client.guard_response(f"leaked marker {plant.token}", session_id="platform-s1")

    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "metrics.json").write_text(
        '{"balanced":{"attack_detection_rate":1.0,"benign_allow_rate":1.0,'
        '"benign_false_blocks":0,"evidence_completeness":1.0,"avg_latency_ms":1.5,'
        '"success_criteria":{"honeytoken_blocked":true},'
        '"detector_hit_distribution":{"honeytoken_detector":1}}}',
        encoding="utf-8",
    )

    cift_store = CiftCertificationStore(tmp_path / "cift" / "certifications.jsonl")
    cert = calibrate_model(
        CiftCalibrationRequest(
            model_id="llama-local",
            provider_url="http://127.0.0.1:9000",
            metadata={"operator_note": FAKE_GITHUB_PAT},
        ),
        _passing_metrics(),
    )
    cift_store.append(cert)

    overview = collect_platform_overview(
        settings=settings,
        provider_name="mock",
        braintrust_enabled=False,
        ml_probe_available=False,
        reports_dir=reports,
    )
    body = overview.model_dump()

    assert body["status"]["provider"] == "mock"
    assert body["status"]["policy_mode"] == "balanced"
    assert body["evals"]["balanced"]["success_criteria"]["honeytoken_blocked"] is True
    assert body["canaries"]["total"] == 1
    assert body["canaries"]["by_format"] == {"github-ghp": 1}
    assert body["cift"]["total"] == 1
    assert body["cift"]["latest"][0]["certification_id"] == cert.certification_id
    assert body["sessions"][0]["session_id"] == "platform-s1"
    assert body["sessions"][0]["nimbus_cumulative_score"] >= 1.0
    assert plant.token not in str(body)
    assert FAKE_GITHUB_PAT not in str(body)


def test_platform_overview_projects_raw_canary_records_to_safe_metadata(tmp_path) -> None:
    settings = Settings(policy_mode=PolicyMode.BALANCED, traces_dir=tmp_path / "traces")
    raw_token = "ghp_1234567890abcdefghijABCDEFGHIJ123456"

    overview = collect_platform_overview(
        settings=settings,
        provider_name="mock",
        braintrust_enabled=False,
        ml_probe_available=False,
        reports_dir=tmp_path / "reports",
        canaries=[
            {
                "token": raw_token,
                "normalized": raw_token,
                "canary_id": "ht_safe",
                "service": "github",
                "session_id": "s1",
                "plant_location": f"doc {raw_token}",
                "planted_at": 10.0,
                "format_slug": "github-ghp",
            }
        ],
        certifications=[],
    )
    body = overview.model_dump()

    assert body["canaries"]["total"] == 1
    assert body["canaries"]["by_format"] == {"github-ghp": 1}
    assert "token" not in body["canaries"]["latest"][0]
    assert "normalized" not in body["canaries"]["latest"][0]
    assert raw_token not in str(body)


def test_platform_overview_redacts_untrusted_artifacts_and_degrades(tmp_path) -> None:
    traces = tmp_path / "traces"
    traces.mkdir()
    (traces / "bad.jsonl").write_text("{not json}\n", encoding="utf-8")
    (traces / "s1.jsonl").write_text(
        json.dumps(
            {
                "created_at": 2.0,
                "session_id": "s1",
                "phase": "response",
                "input_summary": f"raw {FAKE_GITHUB_PAT}",
                "policy_decision": {"action": "BLOCK", "risk_score": 1.0, "detector_hits": []},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "metrics.json").write_text("{not json}", encoding="utf-8")

    overview = collect_platform_overview(
        settings=Settings(policy_mode=PolicyMode.BALANCED, traces_dir=traces),
        provider_name="mock",
        braintrust_enabled=False,
        ml_probe_available=False,
        canaries=[
            {
                "token": "unsafe-raw-canary-value",
                "normalized": "unsafe-raw-canary-value",
                "service": "custom",
                "format_slug": "custom",
                "planted_at": 1.0,
            }
        ],
        certifications=[{"model_id": "llama-local", "metadata": {"note": FAKE_GITHUB_PAT}}],
        reports_dir=reports,
    )
    body = overview.model_dump()

    assert body["evals"] == {}
    assert body["decisions"]["recent"][0]["summary"] == "raw [REDACTED:secret]"
    assert body["canaries"]["by_format"] == {"custom": 1}
    assert "token" not in body["canaries"]["latest"][0]
    assert "normalized" not in body["canaries"]["latest"][0]
    assert FAKE_GITHUB_PAT not in str(body)
    assert "unsafe-raw-canary-value" not in str(body)


def test_load_trace_events_skips_unreadable_files(tmp_path, monkeypatch) -> None:
    traces = tmp_path / "traces"
    traces.mkdir()
    good = traces / "good.jsonl"
    bad = traces / "bad.jsonl"
    good.write_text(json.dumps({"created_at": 1.0, "session_id": "good"}) + "\n", encoding="utf-8")
    bad.write_text(json.dumps({"created_at": 2.0, "session_id": "bad"}) + "\n", encoding="utf-8")

    original_read_text = Path.read_text

    def read_text_or_lock(self, *args, **kwargs):
        if self == bad:
            raise OSError("locked")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text_or_lock)

    rows = load_trace_events(traces)

    assert [row["session_id"] for row in rows] == ["good"]
