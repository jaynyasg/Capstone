"""Startup settings — env (.env) overlaid on policy.yaml. Fully optional; sane defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml
from dotenv import load_dotenv

from aegis.policy.engine import PolicyMode

DEFAULT_POLICY_PATH = Path("policy.yaml")


def load_env() -> None:
    """Load .env then .env.local (local overrides), matching common tool convention.

    Idempotent and safe to call from any entry point (client, tracer, scripts).
    """
    load_dotenv(".env", override=False)
    load_dotenv(".env.local", override=True)


@dataclass
class Settings:
    policy_mode: PolicyMode = PolicyMode.BALANCED
    local_test_mode: bool = False
    warn_threshold: float = 0.6
    block_threshold: float = 1.0
    traces_dir: Path = Path(".aegis/traces")
    enable_ml_probe: bool = False
    ml_probe_path: Path = Path("models/aegis_risk_probe.pt")
    platform_dir: Path | None = None
    # Operator-provided Fernet key for the durable canary vault. Absent means restart
    # detection is disabled (degraded) — we never silently mint a throwaway key (KTD13).
    canary_vault_key: str | None = None

    @property
    def platform_state_dir(self) -> Path:
        """Shared local platform state root (SQLite evidence + canary vault).

        Defaults next to ``traces_dir`` under the same ``.aegis`` root so traces, CIFT
        records, the evidence store, and the canary vault share one backup/restore story
        (KTD13). Deriving from ``traces_dir`` keeps test state isolated under tmp dirs.
        """
        if self.platform_dir is not None:
            return self.platform_dir
        return self.traces_dir.parent / "platform"

    @property
    def evidence_db_path(self) -> Path:
        """Local SQLite evidence read model."""
        return self.platform_state_dir / "evidence.db"

    @property
    def canary_vault_path(self) -> Path:
        """Local durable canary vault (encrypted raw tokens + plaintext safe metadata)."""
        return self.platform_state_dir / "canary_vault.db"

    @classmethod
    def load(cls, policy_path: Path | str = DEFAULT_POLICY_PATH) -> Settings:
        load_env()
        data: dict = {}
        path = Path(policy_path)
        if path.exists():
            data = yaml.safe_load(path.read_text()) or {}
        nimbus = data.get("nimbus", {})

        # Env overrides YAML overrides defaults.
        mode = os.environ.get("AEGIS_POLICY_MODE", data.get("mode", "balanced"))
        ml = data.get("ml_probe", {})
        ml_default = "1" if ml.get("enabled") else "0"
        platform_dir_env = os.environ.get("AEGIS_PLATFORM_DIR", data.get("platform_dir"))
        return cls(
            policy_mode=PolicyMode(mode),
            local_test_mode=os.environ.get("AEGIS_LOCAL_TEST_MODE", "0") == "1",
            warn_threshold=float(nimbus.get("warn_threshold", 0.6)),
            block_threshold=float(nimbus.get("block_threshold", 1.0)),
            traces_dir=Path(data.get("traces_dir", ".aegis/traces")),
            enable_ml_probe=os.environ.get("AEGIS_ENABLE_ML_PROBE", ml_default) == "1",
            ml_probe_path=Path(
                os.environ.get("AEGIS_ML_PROBE_PATH", ml.get("path", "models/aegis_risk_probe.pt"))
            ),
            platform_dir=Path(platform_dir_env) if platform_dir_env else None,
            canary_vault_key=os.environ.get("AEGIS_CANARY_VAULT_KEY", data.get("canary_vault_key")),
        )
