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
from aegis.platform.canaries import CanaryVault
from aegis.platform.store import WarningType


def _store(vault: CanaryVault, canary_id: str, token: str, service: str = "github") -> None:
    vault.store(
        canary_id=canary_id,
        token=token,
        service=service,
        session_id="s1",
        plant_location="env",
        planted_at=1.0,
        format_slug="github-ghp",
        provider_valid=False,
        safety_note="",
        spec_hash="",
    )


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


def test_wrong_key_collapses_to_one_recoverable_warning(tmp_path) -> None:
    db = tmp_path / "vault.db"
    vault = CanaryVault(db, Fernet.generate_key().decode())
    for i in range(3):
        _store(vault, f"c{i}", f"tok{i}")

    # Reopen with a different VALID-format key: every token fails to decrypt. This is a
    # recoverable key mismatch, not data corruption, so it must collapse to ONE "do not delete"
    # signal rather than N per-row CORRUPT_ROW warnings that invite deleting a recoverable vault.
    wrong = CanaryVault(db, Fernet.generate_key().decode())
    assert wrong.restore() == []  # nothing decrypts under the wrong key

    warnings = wrong.health_warnings()
    corrupt_row = [w for w in warnings if w.warning_type is WarningType.CORRUPT_ROW]
    degraded = [w for w in warnings if w.warning_type is WarningType.DEGRADED]
    assert corrupt_row == []  # no per-row corruption noise
    assert len(degraded) == 1
    assert "recoverable" in degraded[0].detail.lower()
    assert "do not delete" in degraded[0].detail.lower()


def test_partial_corruption_keeps_capped_per_row_warnings(tmp_path) -> None:
    db = tmp_path / "vault.db"
    key = Fernet.generate_key().decode()
    vault = CanaryVault(db, key)
    _store(vault, "good", "tok")  # one decryptable row proves the key is correct

    # Seven genuinely-corrupt rows alongside the good one: the key is right, so these are real
    # per-row corruption, surfaced as CORRUPT_ROW but capped so the health panel stays readable.
    conn = sqlite3.connect(db)
    for i in range(7):
        conn.execute(
            "INSERT INTO canaries (canary_id, token_cipher, service, planted_at, format_slug, "
            "provider_valid, lifecycle_state) VALUES (?,?,?,?,?,?,?)",
            (f"bad{i}", b"not-a-valid-fernet-token", "github", 1.0, "github-ghp", 0, "planted"),
        )
    conn.commit()
    conn.close()

    reopened = CanaryVault(db, key)
    assert [r["canary_id"] for r in reopened.restore()] == ["good"]  # the good row still restores
    corrupt_row = [
        w for w in reopened.health_warnings() if w.warning_type is WarningType.CORRUPT_ROW
    ]
    assert len(corrupt_row) <= 6  # 7 failures capped to <= 5 per-row + 1 summary
    assert any("more" in w.detail.lower() for w in corrupt_row)  # summary names the remainder


def test_detection_advances_lifecycle_to_detected(tmp_path) -> None:
    key = Fernet.generate_key().decode()
    settings = _settings(tmp_path, key)
    plant = AegisClient(settings=settings).plant_canary("github", session_id="s1")

    restarted = AegisClient(settings=settings)
    restarted.guard_response(f"leak {plant.token}", session_id="s1")

    records = restarted.registry.safe_records("s1")
    [record] = [r for r in records if r["canary_id"] == plant.canary_id]
    assert record["lifecycle_state"] == "detected"


def test_canary_stored_without_key_is_skipped_not_corrupt_on_restore(tmp_path) -> None:
    db = tmp_path / "vault.db"
    # Plant while NO key is configured: the token is never encrypted (token_cipher is NULL),
    # only safe metadata is stored.
    _store(CanaryVault(db, None), "c0", "tok")

    # Reopen WITH a valid key: a NULL-cipher row has no token to decrypt, so it is skipped
    # cleanly — that is not corruption and must not raise a CORRUPT_ROW warning.
    keyed = CanaryVault(db, Fernet.generate_key().decode())
    assert keyed.restore() == []  # nothing to restore (no ciphertext was ever stored)
    corrupt = [w for w in keyed.health_warnings() if w.warning_type is WarningType.CORRUPT_ROW]
    assert corrupt == []


def test_mark_expired_advances_lifecycle(tmp_path) -> None:
    db = tmp_path / "vault.db"
    vault = CanaryVault(db, Fernet.generate_key().decode())
    _store(vault, "c0", "tok")

    vault.mark_expired("c0")
    [rec] = vault.safe_records()
    assert rec["lifecycle_state"] == "expired"


def test_mark_detected_canaries_with_empty_evidence_is_safe_no_op(tmp_path) -> None:
    from aegis.contracts import DetectorResult

    client = AegisClient(settings=_settings(tmp_path, Fernet.generate_key().decode()))
    plant = client.plant_canary("github", session_id="s1")

    # A honeytoken hit carrying no canary_id (empty evidence), and an empty results list, must
    # both be safe no-ops: no crash and no lifecycle advance.
    client._mark_detected_canaries([])
    client._mark_detected_canaries(
        [
            DetectorResult(
                detector_name="honeytoken_detector",
                score=1.0,
                confidence=1.0,
                recommended_action=Action.BLOCK,
                evidence={},
            )
        ]
    )

    [rec] = [r for r in client.registry.safe_records("s1") if r["canary_id"] == plant.canary_id]
    assert rec["lifecycle_state"] == "planted"  # unchanged — nothing was marked detected


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
