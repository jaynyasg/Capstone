"""Optional ML risk probe — one non-authoritative signal (PRD §6.2 / FR-14).

Deterministic detectors remain authoritative for blocking. Importing this package does
NOT import torch; torch is loaded lazily only when the probe is actually used.
"""

from aegis.detectors.ml.features import FEATURE_DIM, FEATURE_NAMES, extract_features

__all__ = ["FEATURE_DIM", "FEATURE_NAMES", "extract_features"]
