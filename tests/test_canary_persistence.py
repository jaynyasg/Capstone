"""U3 — durable canary vault: restart-safe detection without exposing raw tokens.

A "restart" is modelled as a second AegisClient sharing the same platform state dir and key:
the new client restores planted canaries from the vault and detects later leaks. Key loss
degrades detection visibly while keeping safe metadata readable; it never leaks raw tokens.
"""

from __future__ import annotations

import sqlite3

import pytest
from cryptography.fernet import Fernet

from aegis import AegisClient, Settings
from aegis.contracts import Action
from aegis.platform.store import WarningType


@pytest.fixture(autouse=True)
def _no_braintrust(monkeypatch) -> None:
    monkeypatch.setattr("aegis.tracing._try_braintrust", lambda: None)


def _settings(tmp_path, key: str | None):
    return Settings(
        traces_dir=tmp_path / "traces",
        platform_dir=tmp_path / "platform",
        canary_vault_key=key,
    )


def test_exact_canary_blocked_after_restart(tmp_path) -> None:
    key = Fernet.generate_key().decode()
    settings = _settings(tmp_path, key)

    planter = AegisClient(settings=settings)
    plant = planter.plant_canary("github", session_id="s1")

    restarted = AegisClient(settings=settings)  # fresh process, same vault + key
    decision = restarted.guard_response(f"the secret is {plant.token}", session_id="s1")
    assert decision.action == Action.BLOCK


def test_smeared_canary_blocked_in_response_and_tool_args_after_restart(tmp_path) -> None:
    key = Fernet.generate_key().decode()
    settings = _settings(tmp_path, key)

    plant = AegisClient(settings=settings).plant_canary("aws", session_id="s1")
    restarted = AegisClient(settings=settings)

    spaced = " ".join(plant.token)  # smeared across whitespace
    assert restarted.guard_response(f"leak {spaced}", session_id="s1").action == Action.BLOCK
    assert (
        restarted.guard_tool_call("send_email", {"body": f"key={plant.token}"}, "s1").action
        == Action.BLOCK
    )


def test_vault_never_exposes_raw_token(tmp_path) -> None:
    key = Fernet.generate_key().decode()
    settings = _settings(tmp_path, key)

    planter = AegisClient(settings=settings)
    plant = planter.plant_canary("github", session_id="s1")

    # The token is encrypted at rest — its plaintext bytes never appear in the vault file.
    assert plant.token.encode("utf-8") not in settings.canary_vault_path.read_bytes()

    restarted = AegisClient(settings=settings)
    restarted.guard_response(f"leak {plant.token}", session_id="s1")

    trace = (settings.traces_dir / "s1.jsonl").read_text(encoding="utf-8")
    assert plant.token not in trace  # redacted at rest

    safe = restarted.registry.safe_records("s1")
    assert plant.token not in str(safe)
    assert all("token" not in record for record in safe)
    assert safe[0]["lifecycle_state"] in {"planted", "detected"}


def test_missing_key_keeps_safe_metadata_and_degrades(tmp_path) -> None:
    key = Fernet.generate_key().decode()
    planter = AegisClient(settings=_settings(tmp_path, key))
    plant = planter.plant_canary("github", session_id="s1", location="retrieved_doc")

    # Restart with NO key: safe metadata stays visible, restart detection is degraded.
    restarted = AegisClient(settings=_settings(tmp_path, None))

    safe = restarted.registry.safe_records("s1")
    assert len(safe) == 1
    assert safe[0]["service"] == "github"
    assert safe[0]["plant_location"] == "retrieved_doc"
    assert plant.token not in str(safe)

    assert restarted.registry.is_canary(plant.token) is False  # not restored without the key
    warnings = restarted.registry.health_warnings()
    assert any(w.warning_type is WarningType.DEGRADED for w in warnings)


def test_invalid_key_degrades_without_crashing(tmp_path) -> None:
    key = Fernet.generate_key().decode()
    AegisClient(settings=_settings(tmp_path, key)).plant_canary("github", session_id="s1")

    # A wrong (but well-formed) key cannot decrypt; detection degrades, metadata survives.
    wrong_key = Fernet.generate_key().decode()
    restarted = AegisClient(settings=_settings(tmp_path, wrong_key))
    assert len(restarted.registry.safe_records("s1")) == 1
    warnings = restarted.registry.health_warnings()
    assert any(w.warning_type in {WarningType.DEGRADED, WarningType.CORRUPT_ROW} for w in warnings)


def test_corrupt_vault_row_warns_and_valid_rows_restore(tmp_path) -> None:
    key = Fernet.generate_key().decode()
    settings = _settings(tmp_path, key)
    planter = AegisClient(settings=settings)
    good = planter.plant_canary("github", session_id="s1")
    bad = planter.plant_canary("aws", session_id="s1")

    # Tamper one row's ciphertext so it cannot be decrypted.
    conn = sqlite3.connect(settings.canary_vault_path)
    conn.execute(
        "UPDATE canaries SET token_cipher=? WHERE canary_id=?",
        (b"not-a-valid-fernet-token", bad.canary_id),
    )
    conn.commit()
    conn.close()

    restarted = AegisClient(settings=settings)
    assert restarted.registry.is_canary(good.token) is True  # valid row restored
    assert restarted.registry.is_canary(bad.token) is False  # corrupt row skipped

    warnings = restarted.registry.health_warnings()
    assert any(w.warning_type is WarningType.CORRUPT_ROW for w in warnings)


def test_detection_advances_lifecycle_to_detected(tmp_path) -> None:
    key = Fernet.generate_key().decode()
    settings = _settings(tmp_path, key)
    plant = AegisClient(settings=settings).plant_canary("github", session_id="s1")

    restarted = AegisClient(settings=settings)
    restarted.guard_response(f"leak {plant.token}", session_id="s1")

    records = restarted.registry.safe_records("s1")
    [record] = [r for r in records if r["canary_id"] == plant.canary_id]
    assert record["lifecycle_state"] == "detected"


def test_corrupt_vault_db_degrades_without_crashing_guard_path(tmp_path) -> None:
    key = Fernet.generate_key().decode()
    settings = _settings(tmp_path, key)
    AegisClient(settings=settings).plant_canary("github", session_id="s1")

    # The vault file is corrupted entirely (e.g. a half-restored backup, not just a bad row).
    settings.canary_vault_path.write_bytes(b"this is not a valid sqlite database at all")

    # A new client must still construct and guard normally — durable-canary storage failure
    # degrades visibly, it does not brick the guard path.
    restarted = AegisClient(settings=settings)
    assert restarted.guard_response("a benign message", session_id="s1").action == Action.ALLOW
    warnings = restarted.registry.health_warnings()
    assert any(w.warning_type is WarningType.DEGRADED for w in warnings)
