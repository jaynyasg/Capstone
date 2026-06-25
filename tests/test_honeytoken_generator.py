"""DP-HONEY-style shape generator integrated into Aegis honeytokens."""

from __future__ import annotations

from aegis import Action, AegisClient, PolicyMode, Settings
from aegis.secrets.honeytoken_generator import (
    default_format_for_service,
    generate_honeytoken,
    get_honeytoken_format,
    list_honeytoken_format_slugs,
)

REQUIRED_FORMATS = {
    "anthropic-api-key",
    "aws-access-key-id",
    "aws-secret-access-key",
    "database-password",
    "generic-sk",
    "github-fine-grained",
    "github-ghp",
    "github-oauth",
    "github-refresh",
    "github-server-to-server",
    "github-user-to-server",
    "google-api-key",
    "jwt",
    "oauth-bearer",
    "openai-project-key",
    "sendgrid-key",
    "slack-bot-token",
    "slack-user-token",
    "slack-webhook-url",
    "ssh-private-key",
    "stripe-sk-live",
    "twilio-account-sid",
    "twilio-api-key-sid",
}


def test_generator_covers_dp_honey_formats() -> None:
    assert set(list_honeytoken_format_slugs()) >= REQUIRED_FORMATS


def test_generated_examples_validate_against_their_specs() -> None:
    for slug in sorted(REQUIRED_FORMATS):
        generated = generate_honeytoken(slug, seed=123)
        spec = get_honeytoken_format(slug)
        assert spec.validate(generated.token), (slug, generated.token)
        assert generated.provider_valid is False
        assert "not provider-valid" in generated.safety_note


def test_github_classic_token_has_valid_checksum() -> None:
    generated = generate_honeytoken("github-ghp", seed=7)
    token = generated.token
    spec = get_honeytoken_format("github-ghp")
    replacement = "0" if token[-1] != "0" else "1"

    assert token.startswith("ghp_")
    assert spec.validate(token)
    assert not spec.validate(token[:-1] + replacement)


def test_service_defaults_pick_provider_shapes() -> None:
    assert default_format_for_service("github") == "github-ghp"
    assert default_format_for_service("openai") == "openai-project-key"
    assert default_format_for_service("unknown") == "generic-sk"


def test_provider_shaped_canary_is_allowed_when_planted_in_request(tmp_path) -> None:
    client = AegisClient(
        Settings(policy_mode=PolicyMode.BALANCED, traces_dir=tmp_path / "traces")
    )
    plant = client.plant_canary("github", session_id="s1")

    request_decision = client.guard_request(
        [{"role": "system", "content": f"Retrieved marker: {plant.token}"}],
        session_id="s1",
    )
    response_decision = client.guard_response(
        f"Leaked marker: {plant.token}", session_id="s1"
    )

    assert plant.token.startswith("ghp_")
    assert plant.format_slug == "github-ghp"
    assert request_decision.action == Action.ALLOW
    assert response_decision.action == Action.BLOCK
