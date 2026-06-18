"""MLRiskProbe — one auxiliary signal, never the policy owner (PRD §6.2 / FR-14).

Hard guarantees:
- Caps its recommended action at WARN. It can never block on its own.
- If torch or the model artifact is missing/unloadable, it degrades to ALLOW and records
  `degraded_mode` so the trace shows the system fell back to deterministic detectors.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aegis.contracts import Action, DetectorResult
from aegis.detectors.base import ScanContext, timed
from aegis.detectors.ml.features import FEATURE_DIM, FEATURE_NAMES, extract_features

DEFAULT_MODEL_PATH = Path("models/aegis_risk_probe.pt")


class MLRiskProbe:
    name = "ml_risk_probe"

    def __init__(self, model_path: Path | str = DEFAULT_MODEL_PATH, threshold: float = 0.5) -> None:
        self.model_path = Path(model_path)
        self.threshold = threshold
        self._model = None
        self._torch = None
        self.degraded_reason: str | None = None
        self._load()

    @property
    def available(self) -> bool:
        return self._model is not None

    def _load(self) -> None:
        try:
            import torch

            from aegis.detectors.ml._model import RiskMLP
        except ImportError:
            self.degraded_reason = "torch not installed"
            return
        if not self.model_path.exists():
            self.degraded_reason = f"model artifact missing: {self.model_path}"
            return
        try:
            blob = torch.load(self.model_path, map_location="cpu", weights_only=False)
            if blob.get("feature_names") != FEATURE_NAMES:
                self.degraded_reason = "feature schema drift; artifact incompatible"
                return
            model = RiskMLP(FEATURE_DIM, blob.get("hidden", 16))
            model.load_state_dict(blob["state_dict"])
            model.eval()
            self._model = model
            self._torch = torch
            self.threshold = blob.get("threshold", self.threshold)
        except Exception as exc:  # noqa: BLE001 — any load failure must degrade, not crash
            self.degraded_reason = f"load failed: {type(exc).__name__}"

    def score(
        self,
        ctx: ScanContext,
        detector_results: list[DetectorResult],
        nimbus_cumulative: float,
    ) -> DetectorResult:
        with timed() as elapsed:
            features = extract_features(ctx, detector_results, nimbus_cumulative)
            if not self.available:
                return self._degraded(elapsed())
            tensor = self._torch.tensor([features], dtype=self._torch.float32)
            with self._torch.no_grad():
                probability = float(self._model(tensor).item())
            ms = elapsed()

        # Authoritative cap: the probe may WARN but never block on its own.
        action = Action.WARN if probability >= self.threshold else Action.ALLOW
        return DetectorResult(
            detector_name=self.name,
            score=probability,
            confidence=0.5,
            recommended_action=action,
            evidence={
                "probe_score": round(probability, 4),
                "threshold": self.threshold,
                "degraded_mode": False,
                "authoritative": False,
            },
            latency_ms=ms,
        )

    def _degraded(self, ms: float) -> DetectorResult:
        return DetectorResult(
            detector_name=self.name,
            score=0.0,
            confidence=0.0,
            recommended_action=Action.ALLOW,
            evidence={
                "degraded_mode": True,
                "reason": self.degraded_reason,
                "authoritative": False,
            },
            latency_ms=ms,
        )

    def describe(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "degraded_reason": self.degraded_reason,
            "model_path": str(self.model_path),
            "threshold": self.threshold,
        }
