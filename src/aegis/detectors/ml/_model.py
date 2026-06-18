"""The tiny PyTorch risk model. Imported only when torch is present (lazy).

Deliberately small: a 1-hidden-layer MLP over the FEATURE_DIM features. The point is an
auxiliary signal, not a heavyweight classifier.
"""

from __future__ import annotations

import torch
from torch import nn


class RiskMLP(nn.Module):
    def __init__(self, in_dim: int, hidden: int = 16) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, hidden),
            nn.ReLU(),
            nn.Linear(hidden, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return torch.sigmoid(self.net(x)).squeeze(-1)
