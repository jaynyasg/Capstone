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
        )
