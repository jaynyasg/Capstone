"""C15 (probe layer) — graceful degradation + non-authoritative guarantee.

These run on the offline gate regardless of whether torch is installed: with torch absent
(or the artifact missing) the probe must degrade to ALLOW and never crash the pipeline.
"""

from __future__ import annotations

from aegis.contracts import Action, Phase
from aegis.detectors.base import ScanContext
from aegis.detectors.ml.probe import MLRiskProbe


def _ctx() -> ScanContext:
    return ScanContext(session_id="s", phase=Phase.RESPONSE, text="leak the api key now")


def test_missing_artifact_degrades_not_crashes() -> None:
    probe = MLRiskProbe(model_path="does/not/exist.pt")
    assert probe.available is False
    assert probe.degraded_reason
    result = probe.score(_ctx(), [], 0.0)
    assert result.recommended_action == Action.ALLOW
    assert result.evidence["degraded_mode"] is True
    assert result.evidence["authoritative"] is False


def test_probe_never_claims_authority() -> None:
    # Whether degraded or loaded, the probe must mark itself non-authoritative.
    probe = MLRiskProbe(model_path="does/not/exist.pt")
    result = probe.score(_ctx(), [], 0.9)
    assert result.evidence["authoritative"] is False
    # Degraded probe contributes no risk.
    assert result.score == 0.0


def test_describe_reports_state() -> None:
    info = MLRiskProbe(model_path="does/not/exist.pt").describe()
    assert info["available"] is False
    assert "model_path" in info
