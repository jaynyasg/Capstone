"""Online observe-mode learner.

This is the live "Observe + Learn" path: when observe mode sees a high-confidence leak, the
first occurrence is allowed but used as a positive training example for a tiny PyTorch MLP.
If a later event scores above the learned threshold, the learner recommends BLOCK. The model
stores numeric feature vectors only; it never stores raw prompt/secret text.
"""

from __future__ import annotations

from typing import Any

from aegis.contracts import Action, DetectorResult, Phase
from aegis.detectors.base import ScanContext, timed
from aegis.detectors.ml.features import FEATURE_DIM, extract_features

TRAINABLE_DETECTORS = frozenset(
    {
        "secret_pattern_scanner",
        "encoding_scanner",
        "honeytoken_detector",
        "tool_call_argument_scanner",
        "credential_broker",
    }
)


class ObserveOnlineLearner:
    """Tiny online MLP trained from observe-mode leak evidence."""

    name = "observe_ml_learner"

    def __init__(self, threshold: float = 0.7, train_epochs: int = 80) -> None:
        self.threshold = threshold
        self.train_epochs = train_epochs
        self._torch: Any | None = None
        self._model: Any | None = None
        self._optimizer: Any | None = None
        self._loss_fn: Any | None = None
        self._positive_examples: list[list[float]] = []
        self._negative_examples = _benign_anchor_features()
        self.degraded_reason: str | None = None
        self._attempted_load = False

    @property
    def available(self) -> bool:
        return self._model is not None

    @property
    def trained(self) -> bool:
        return bool(self._positive_examples)

    def evaluate(
        self,
        ctx: ScanContext,
        detector_results: list[DetectorResult],
        nimbus_cumulative: float,
    ) -> DetectorResult | None:
        if not _has_trainable_leak(detector_results):
            return None

        with timed() as elapsed:
            features = extract_features(ctx, detector_results, nimbus_cumulative)
            self._ensure_loaded()
            if not self.available:
                return self._degraded(elapsed())

            probability = self._predict(features) if self.trained else 0.0
            if self.trained and probability >= self.threshold:
                return self._result(
                    action=Action.BLOCK,
                    probability=probability,
                    status="ml_matched",
                    latency_ms=elapsed(),
                )

            self._positive_examples.append(features)
            self._fit()
            probability = self._predict(features)
            return self._result(
                action=Action.WARN,
                probability=probability,
                status="ml_trained",
                latency_ms=elapsed(),
            )

    def _ensure_loaded(self) -> None:
        if self._attempted_load:
            return
        self._attempted_load = True
        try:
            import torch

            from aegis.detectors.ml._model import RiskMLP
        except ImportError:
            self.degraded_reason = "torch not installed"
            return

        torch.manual_seed(0)
        self._torch = torch
        self._model = RiskMLP(FEATURE_DIM, hidden=12)
        self._optimizer = torch.optim.Adam(self._model.parameters(), lr=0.03)
        self._loss_fn = torch.nn.BCELoss()

    def _fit(self) -> None:
        if not self.available:
            return
        x_rows = self._negative_examples + self._positive_examples
        y_rows = [0.0] * len(self._negative_examples) + [1.0] * len(self._positive_examples)
        x = self._torch.tensor(x_rows, dtype=self._torch.float32)
        y = self._torch.tensor(y_rows, dtype=self._torch.float32)

        self._model.train()
        for _ in range(self.train_epochs):
            self._optimizer.zero_grad()
            loss = self._loss_fn(self._model(x), y)
            loss.backward()
            self._optimizer.step()
        self._model.eval()

    def _predict(self, features: list[float]) -> float:
        x = self._torch.tensor([features], dtype=self._torch.float32)
        self._model.eval()
        with self._torch.no_grad():
            return float(self._model(x).item())

    def _result(
        self, *, action: Action, probability: float, status: str, latency_ms: float
    ) -> DetectorResult:
        return DetectorResult(
            detector_name=self.name,
            score=probability,
            confidence=0.7,
            recommended_action=action,
            evidence={
                "status": status,
                "ml_trained": True,
                "model": "RiskMLP",
                "training_examples": len(self._negative_examples) + len(self._positive_examples),
                "positive_examples": len(self._positive_examples),
                "raw_secret_logged": False,
                "threshold": self.threshold,
            },
            latency_ms=latency_ms,
        )

    def _degraded(self, ms: float) -> DetectorResult:
        return DetectorResult(
            detector_name=self.name,
            score=0.0,
            confidence=0.0,
            recommended_action=Action.WARN,
            evidence={
                "status": "ml_unavailable",
                "ml_trained": False,
                "reason": self.degraded_reason,
                "raw_secret_logged": False,
            },
            latency_ms=ms,
        )


def _has_trainable_leak(results: list[DetectorResult]) -> bool:
    return any(
        result.detector_name in TRAINABLE_DETECTORS
        and result.recommended_action.severity >= Action.BLOCK.severity
        for result in results
    )


def _benign_anchor_features() -> list[list[float]]:
    anchors = [
        ScanContext(session_id="observe-ml", phase=Phase.REQUEST, text="What is the weather?"),
        ScanContext(
            session_id="observe-ml",
            phase=Phase.REQUEST,
            text="List my repos using secret://github/token.",
        ),
        ScanContext(
            session_id="observe-ml",
            phase=Phase.RESPONSE,
            text="Set GITHUB_TOKEN=your_api_key_here in the local .env file.",
        ),
        ScanContext(
            session_id="observe-ml",
            phase=Phase.TOOL_CALL,
            text="body=Reminder: standup moved to 10am tomorrow.",
            tool_name="send_email",
            tool_arguments={"to": "team@example.com", "body": "Reminder: standup moved."},
        ),
    ]
    return [extract_features(ctx, [], 0.0) for ctx in anchors]
