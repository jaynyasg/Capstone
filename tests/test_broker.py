"""C8 — broker resolves handles in trusted path; raw secret in context forces non-allow."""

from __future__ import annotations

import pytest

from aegis.contracts import Action
from aegis.secrets import CredentialBroker, FakeSecretStore
from tests.conftest import FAKE_GITHUB_PAT


def _broker() -> CredentialBroker:
    store = FakeSecretStore({"secret://github/token": FAKE_GITHUB_PAT})
    return CredentialBroker(store)


def test_resolve_handle_in_trusted_path() -> None:
    assert _broker().resolve("secret://github/token") == FAKE_GITHUB_PAT


def test_resolve_unknown_handle_raises() -> None:
    with pytest.raises(KeyError):
        _broker().resolve("secret://github/missing")


def test_resolve_non_handle_raises() -> None:
    with pytest.raises(ValueError):
        _broker().resolve("github/token")


def test_raw_secret_in_context_forces_block_and_redacts() -> None:
    a = _broker().assess_context(f"my key is {FAKE_GITHUB_PAT}, use it")
    assert a.raw_secret_present is True
    assert a.critical is True
    assert a.forced_action == Action.BLOCK
    assert FAKE_GITHUB_PAT not in a.redacted_text
    assert "secret://github/token" in a.leaked_handles


def test_local_test_mode_does_not_force_block() -> None:
    a = _broker().assess_context(f"key {FAKE_GITHUB_PAT}", local_test_mode=True)
    assert a.raw_secret_present is True
    assert a.critical is True
    assert a.forced_action is None  # local test mode is permitted


def test_opaque_handle_is_not_a_raw_leak() -> None:
    a = _broker().assess_context("please use secret://github/token for the call")
    assert a.raw_secret_present is False
    assert a.forced_action is None
