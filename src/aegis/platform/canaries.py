"""Durable canary vault (U3): restart-safe detection without exposing raw tokens.

The vault persists planted canaries to a local SQLite file. Two trust tiers live in one
row (KTD6):

* **Safe metadata** (service, format, lifecycle, …) is stored as *plaintext* columns and is
  readable with no key — so the dashboard and exports can always show *what* was planted.
* **The raw token** is stored only as a *Fernet-encrypted* blob. Restoring it for restart
  detection requires the operator-provided key; losing the key degrades detection but never
  hides the safe metadata.

The decrypted token is handed back only to the in-process :class:`HoneytokenRegistry`, which
needs it in memory for substring/normalized matching — it never enters a trace, API
response, dashboard, or export. The key is operator-provided via ``AEGIS_CANARY_VAULT_KEY``;
the vault never mints a throwaway key (KTD13). An absent, invalid, or unusable key surfaces
as degraded health rather than a silent failure.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aegis.platform.store import HealthSeverity, HealthWarning, WarningType

if TYPE_CHECKING:
    from cryptography.fernet import Fernet

_SCHEMA = """
CREATE TABLE IF NOT EXISTS canaries (
    canary_id       TEXT PRIMARY KEY,
    token_cipher    BLOB,
    service         TEXT NOT NULL DEFAULT 'unknown',
    session_id      TEXT,
    plant_location  TEXT,
    planted_at      REAL NOT NULL DEFAULT 0,
    format_slug     TEXT NOT NULL DEFAULT 'unknown',
    provider_valid  INTEGER NOT NULL DEFAULT 0,
    safety_note     TEXT,
    spec_hash       TEXT,
    lifecycle_state TEXT NOT NULL DEFAULT 'planted'
);
"""

# Canary lifecycle states (R10). Automatic expiry policy is intentionally minimal in this
# slice; the state is supported so callers can set it explicitly.
PLANTED = "planted"
DETECTED = "detected"
EXPIRED = "expired"
INVALID = "invalid"

_SAFE_COLUMNS = (
    "canary_id",
    "service",
    "session_id",
    "plant_location",
    "planted_at",
    "format_slug",
    "provider_valid",
    "safety_note",
    "spec_hash",
    "lifecycle_state",
)


class CanaryVault:
    """SQLite-backed durable canary store with encrypted raw tokens."""

    def __init__(self, path: Path | str, key: str | None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._key_provided = bool(key)
        self._fernet = _make_fernet(key)
        self._row_warnings: list[HealthWarning] = []
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    @property
    def can_persist(self) -> bool:
        """Whether tokens can be encrypted (a usable key + cryptography are available)."""
        return self._fernet is not None

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ----- writes --------------------------------------------------------

    def store(
        self,
        *,
        canary_id: str,
        token: str,
        service: str,
        session_id: str,
        plant_location: str,
        planted_at: float,
        format_slug: str,
        provider_valid: bool,
        safety_note: str,
        spec_hash: str,
    ) -> None:
        """Persist a planted canary. Token is encrypted only when a key is available."""
        cipher = self._fernet.encrypt(token.encode("utf-8")) if self._fernet else None
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO canaries
                   (canary_id, token_cipher, service, session_id, plant_location, planted_at,
                    format_slug, provider_valid, safety_note, spec_hash, lifecycle_state)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    canary_id,
                    cipher,
                    service,
                    session_id,
                    plant_location,
                    planted_at,
                    format_slug,
                    1 if provider_valid else 0,
                    safety_note,
                    spec_hash,
                    PLANTED,
                ),
            )

    def mark_detected(self, canary_id: str) -> None:
        self._set_lifecycle(canary_id, DETECTED)

    def mark_expired(self, canary_id: str) -> None:
        self._set_lifecycle(canary_id, EXPIRED)

    def _set_lifecycle(self, canary_id: str, state: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE canaries SET lifecycle_state=? WHERE canary_id=?", (state, canary_id)
            )

    # ----- reads ---------------------------------------------------------

    def safe_records(self, session_id: str | None = None) -> list[dict[str, Any]]:
        """Plaintext safe metadata only — never the token. Readable without a key."""
        clause = " WHERE session_id=?" if session_id is not None else ""
        params = (session_id,) if session_id is not None else ()
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {', '.join(_SAFE_COLUMNS)} FROM canaries{clause} "
                "ORDER BY planted_at DESC, canary_id DESC",
                params,
            ).fetchall()
        return [_safe_row(row) for row in rows]

    def restore(self) -> list[dict[str, Any]]:
        """Decrypt persisted tokens for the in-memory registry (requires the key).

        Records corrupt/undecryptable rows as warnings (see :meth:`health_warnings`) and
        returns only the rows it could restore. Rows stored without a token (planted while
        no key was configured) are skipped — their safe metadata stays visible.
        """
        self._row_warnings = []
        if self._fernet is None:
            return []
        restored: list[dict[str, Any]] = []
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT token_cipher, {', '.join(_SAFE_COLUMNS)} FROM canaries"
            ).fetchall()
        for row in rows:
            cipher = row["token_cipher"]
            if cipher is None:
                continue
            try:
                token = self._fernet.decrypt(cipher).decode("utf-8")
            except Exception:  # noqa: BLE001 - a bad row must not abort restore of good rows
                self._row_warnings.append(
                    HealthWarning(
                        source_kind="canaries",
                        warning_type=WarningType.CORRUPT_ROW,
                        severity=HealthSeverity.WARNING,
                        detail=f"canary {row['canary_id']} could not be decrypted",
                        count=1,
                    )
                )
                continue
            record = _safe_row(row)
            record["token"] = token
            restored.append(record)
        return restored

    def health_warnings(self) -> list[HealthWarning]:
        """Degraded/corrupt warnings: key-loss disables restart detection; bad rows warn."""
        warnings = list(self._row_warnings)
        if self._fernet is None and (self._key_provided or self._row_count() > 0):
            warnings.append(
                HealthWarning(
                    source_kind="canaries",
                    warning_type=WarningType.DEGRADED,
                    severity=HealthSeverity.ERROR,
                    detail="canary vault key unavailable or invalid: restart detection degraded",
                )
            )
        return warnings

    def _row_count(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM canaries").fetchone()[0]


def _safe_row(row: sqlite3.Row) -> dict[str, Any]:
    data = {key: row[key] for key in _SAFE_COLUMNS}
    data["provider_valid"] = bool(data.get("provider_valid"))
    return data


def _make_fernet(key: str | None) -> Fernet | None:
    """Build a Fernet from an operator key, or None if absent/invalid/unavailable."""
    if not key:
        return None
    try:
        from cryptography.fernet import Fernet

        return Fernet(key if isinstance(key, bytes) else key.encode("utf-8"))
    except Exception:  # noqa: BLE001 - invalid key or missing dependency degrades visibly
        return None
