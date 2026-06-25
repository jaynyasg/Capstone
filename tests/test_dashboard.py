"""C14 — static dashboard renders metrics + decisions, escapes content, matches palette."""

from __future__ import annotations

from aegis.dashboard.render import generate, render_html

SAMPLE_METRICS = {
    "balanced": {
        "attack_detection_rate": 1.0,
        "benign_allow_rate": 1.0,
        "benign_false_blocks": 0,
        "evidence_completeness": 1.0,
        "avg_latency_ms": 0.84,
        "success_criteria": {"unsafe_handled_rate>=0.8": True, "honeytoken_blocked": True},
        "detector_hit_distribution": {"nimbus_lite_ledger": 9, "tool_call_argument_scanner": 4},
    }
}
SAMPLE_CASES = [
    {
        "id": "tool-email-001",
        "category": "tool_call_exfiltration",
        "baseline_leaked": True,
        "worst_action": "BLOCK",
    },
]
SAMPLE_DECISIONS = [
    {
        "phase": "tool_call",
        "tool_name": "send_email",
        "input_summary": "to=attacker@evil.test",
        "policy_decision": {
            "action": "BLOCK",
            "detector_hits": [
                {"detector_name": "tool_call_argument_scanner", "recommended_action": "BLOCK"},
                {"detector_name": "secret_pattern_scanner", "recommended_action": "ALLOW"},
            ],
        },
    }
]
SAMPLE_PLATFORM = {
    "status": {
        "gateway": "ok",
        "provider": "mock",
        "policy_mode": "balanced",
        "braintrust": False,
        "ml_probe": False,
    },
    "decisions": {"total": 1, "by_action": {"BLOCK": 1}, "by_phase": {"tool_call": 1}},
    "evals": {
        "balanced": {
            "attack_detection_rate": 1.0,
            "benign_allow_rate": 1.0,
            "success_criteria": {"honeytoken_blocked": True},
        }
    },
    "cift": {"total": 1, "latest": [{"model_id": "llama-local", "level": "gateway_calibrated"}]},
    "canaries": {"total": 1, "by_format": {"github-ghp": 1}, "latest": []},
    "sessions": [{"session_id": "s1", "nimbus_cumulative_score": 1.0, "events": 3}],
    "evidence_paths": {"traces": ".aegis/traces", "evals": "evals/reports"},
}


def test_renders_core_sections() -> None:
    html = render_html(SAMPLE_METRICS, SAMPLE_CASES, SAMPLE_DECISIONS)
    assert "#0d0d0d" in html  # Ship/Linear background palette
    assert "Aegis" in html
    assert "100%" in html  # detection rate KPI
    assert "LEAKS" in html  # baseline column
    assert "BLOCK" in html  # action pill
    assert "tool_call_argument_scanner" in html  # detector distribution + fired


def test_renders_platform_cockpit() -> None:
    html = render_html(SAMPLE_METRICS, SAMPLE_CASES, SAMPLE_DECISIONS, platform=SAMPLE_PLATFORM)

    assert "Platform cockpit" in html
    assert "provider" in html
    assert "mock" in html
    assert "CIFT certificates" in html
    assert "github-ghp" in html
    assert "s1" in html


def test_escapes_decision_content() -> None:
    rows = [
        {
            "phase": "response",
            "input_summary": "<script>alert(1)</script>",
            "policy_decision": {"action": "ALLOW", "detector_hits": []},
        }
    ]
    html = render_html(SAMPLE_METRICS, [], rows)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_empty_state_does_not_crash() -> None:
    html = render_html(None, [], [])
    assert "aegis-eval" in html  # guidance shown
    assert "No decisions yet" in html


def test_recent_decisions_ordered_by_timestamp(tmp_path) -> None:
    import json

    from aegis.dashboard.render import load_recent_decisions

    traces = tmp_path / "traces"
    traces.mkdir()
    # Older event in an alphabetically-LATER file; newer event in an earlier file.
    (traces / "zzz.jsonl").write_text(
        json.dumps({"created_at": 100.0, "session_id": "zzz", "phase": "response"}) + "\n",
        encoding="utf-8",
    )
    (traces / "aaa.jsonl").write_text(
        json.dumps({"created_at": 200.0, "session_id": "aaa", "phase": "response"}) + "\n",
        encoding="utf-8",
    )
    rows = load_recent_decisions(traces)
    assert [r["session_id"] for r in rows] == ["aaa", "zzz"]  # newest first, not file order


def test_auto_refresh_meta_only_when_requested() -> None:
    assert 'http-equiv="refresh"' not in render_html(None, [], [])
    assert 'http-equiv="refresh"' in render_html(None, [], [], auto_refresh=5)


def test_generate_writes_file(tmp_path) -> None:
    out = generate(
        traces_dir=tmp_path / "traces",
        reports_dir=tmp_path / "reports",
        out=tmp_path / "dashboard" / "index.html",
    )
    assert out.exists()
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")
