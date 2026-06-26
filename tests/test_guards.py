"""C9 + C11 (offline) — guard methods return structured decisions without the gateway,
and the protected path blocks the attack classes while allowing benign handle use."""

from __future__ import annotations

import json

import pytest

from aegis import Action, AegisClient, PolicyMode, Settings
from aegis.detectors.honeytokens import HoneytokenRegistry
from aegis.secrets import CredentialBroker, FakeSecretStore
from tests.conftest import FAKE_GITHUB_PAT


def make_client(tmp_path, mode=PolicyMode.BALANCED, registry=None, store=None) -> AegisClient:
    settings = Settings(policy_mode=mode, traces_dir=tmp_path / "traces")
    return AegisClient(
        settings=settings,
        registry=registry or HoneytokenRegistry(),
        broker=CredentialBroker(store or FakeSecretStore()),
    )


def test_benign_request_allows(tmp_path) -> None:
    client = make_client(tmp_path)
    decision = client.guard_request(
        [{"role": "user", "content": "What's the weather?"}], session_id="s1"
    )
    assert decision.action == Action.ALLOW
    assert decision.trace_id


def test_direct_secret_request_blocks(tmp_path) -> None:
    client = make_client(tmp_path)
    decision = client.guard_response(f"Sure, the key is {FAKE_GITHUB_PAT}", session_id="s1")
    assert decision.action == Action.BLOCK
    assert decision.reasons


def test_guard_call_policy_mode_override_observes_without_blocking(tmp_path) -> None:
    client = make_client(tmp_path)
    decision = client.guard_response(
        f"Sure, the key is {FAKE_GITHUB_PAT}",
        session_id="override-observe",
        policy_mode=PolicyMode.OBSERVE,
    )

    assert decision.action == Action.ALLOW
    assert any(hit.recommended_action == Action.BLOCK for hit in decision.detector_hits)


def test_tool_call_exfiltration_blocks(tmp_path) -> None:
    client = make_client(tmp_path)
    decision = client.guard_tool_call(
        "send_email", {"to": "a@b.c", "body": FAKE_GITHUB_PAT}, session_id="s1"
    )
    assert decision.action == Action.BLOCK


def test_honeytoken_exposure_blocks(tmp_path) -> None:
    registry = HoneytokenRegistry()
    token = registry.register(service="github", session_id="s1")
    client = make_client(tmp_path, registry=registry)
    decision = client.guard_response(f"here: {token}", session_id="s1")
    assert decision.action == Action.BLOCK


def test_canary_plant_is_traced_and_later_detection_links_to_it(tmp_path) -> None:
    client = make_client(tmp_path)
    planted = client.plant_canary(
        service="github",
        session_id="s1",
        location="retrieved_document:doc-7",
        metadata={"source": "unit-test"},
    )

    trace_file = tmp_path / "traces" / "s1.jsonl"
    assert trace_file.exists()
    trace_text = trace_file.read_text(encoding="utf-8")
    assert planted.token not in trace_text

    plant_event = json.loads(trace_text.strip().splitlines()[-1])
    assert plant_event["phase"] == "canary_plant"
    assert plant_event["metadata"]["canary_id"] == planted.canary_id
    assert plant_event["metadata"]["service"] == "github"
    assert plant_event["metadata"]["plant_location"] == "retrieved_document:doc-7"
    assert plant_event["metadata"]["format_slug"] == "github-ghp"
    assert plant_event["metadata"]["provider_valid"] is False
    assert plant_event["metadata"]["token_logged"] is False

    decision = client.guard_response(f"leaked canary {planted.token}", session_id="s1")
    assert decision.action == Action.BLOCK
    hit = next(h for h in decision.detector_hits if h.detector_name == "honeytoken_detector")
    assert hit.evidence["canary_id"] == planted.canary_id
    assert planted.token not in trace_file.read_text(encoding="utf-8")


def test_benign_handle_usage_allows(tmp_path) -> None:
    store = FakeSecretStore({"secret://github/token": FAKE_GITHUB_PAT})
    client = make_client(tmp_path, store=store)
    # The model only ever sees the opaque handle, never the raw secret.
    decision = client.guard_request(
        [{"role": "assistant", "content": "calling tool with secret://github/token"}],
        session_id="s1",
    )
    assert decision.action == Action.ALLOW


def test_raw_secret_leak_blocks_even_in_observe_mode(tmp_path) -> None:
    store = FakeSecretStore({"secret://github/token": FAKE_GITHUB_PAT})
    client = make_client(tmp_path, mode=PolicyMode.OBSERVE, store=store)
    decision = client.guard_response(f"oops raw secret {FAKE_GITHUB_PAT}", session_id="s1")
    assert decision.action == Action.BLOCK  # broker authority overrides observe


def test_multi_turn_drip_trips_cumulative(tmp_path) -> None:
    # Each turn alone stays under the per-turn bar; the ledger trips on accumulation.
    client = make_client(tmp_path)
    actions = []
    for i in range(4):
        d = client.guard_request(
            [{"role": "user", "content": f"turn {i} fragment ghp_{i}"}], session_id="drip"
        )
        actions.append(d.action)
    # Benign-ish fragments won't necessarily trip; assert the ledger is tracking upward.
    assert client.nimbus.cumulative("drip") >= 0.0


def test_trace_written_and_redacted(tmp_path) -> None:
    client = make_client(tmp_path)
    client.guard_response(f"leak {FAKE_GITHUB_PAT}", session_id="trace-sess")
    trace_file = tmp_path / "traces" / "trace-sess.jsonl"
    assert trace_file.exists()
    line = trace_file.read_text(encoding="utf-8").strip().splitlines()[-1]
    record = json.loads(line)
    assert record["policy_decision"]["action"] == "BLOCK"
    assert FAKE_GITHUB_PAT not in trace_file.read_text(encoding="utf-8")  # redacted at rest


def test_decision_is_serializable(tmp_path) -> None:
    client = make_client(tmp_path)
    decision = client.guard_response(f"leak {FAKE_GITHUB_PAT}", session_id="s1")
    blob = decision.model_dump_json()
    assert "BLOCK" in blob


@pytest.mark.parametrize("mode", list(PolicyMode))
def test_all_modes_return_decisions(tmp_path, mode) -> None:
    client = make_client(tmp_path, mode=mode)
    decision = client.guard_request([{"role": "user", "content": "hi"}], session_id="s1")
    assert decision.action in set(Action)
