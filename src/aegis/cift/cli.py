"""`aegis-cift-calibrate` — record a model-specific calibration certificate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from aegis.cift.calibration import calibrate_model
from aegis.cift.contracts import CiftCalibrationRequest
from aegis.cift.store import CiftCertificationStore


def main() -> int:
    parser = argparse.ArgumentParser(description="Calibrate a hosted model for Aegis/CIFT claims.")
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--provider-url", default="local")
    parser.add_argument("--activation-endpoint")
    parser.add_argument("--supports-activations", action="store_true")
    parser.add_argument("--activation-sample-count", type=int, default=0)
    parser.add_argument("--activation-separation-score", type=float)
    parser.add_argument("--metrics", default="evals/reports/metrics.json")
    parser.add_argument("--out", default=".aegis/cift/certifications.jsonl")
    args = parser.parse_args()

    metrics_path = Path(args.metrics)
    metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else {}
    request = CiftCalibrationRequest(
        model_id=args.model_id,
        provider_url=args.provider_url,
        supports_activations=args.supports_activations,
        activation_endpoint=args.activation_endpoint,
        activation_sample_count=args.activation_sample_count,
        activation_separation_score=args.activation_separation_score,
    )
    cert = calibrate_model(request, metrics)
    CiftCertificationStore(args.out).append(cert)
    print(cert.model_dump_json(indent=2))
    return 0 if cert.status != "FAIL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
