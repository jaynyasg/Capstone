"""Trace sink — required local JSONL, optional Braintrust (PRD §4.4.10, failure-mode §9).

Braintrust is an *evidence* mechanism, not a defense: if its key is absent or the import
fails, Aegis writes local JSONL and continues. One JSON line per guarded event.
"""

from __future__ import annotations

import os
from pathlib import Path

from aegis.contracts import AegisEvent


class Tracer:
    def __init__(self, traces_dir: Path | str = ".aegis/traces") -> None:
        self.traces_dir = Path(traces_dir)
        self._braintrust = _try_braintrust()

    @property
    def braintrust_enabled(self) -> bool:
        return self._braintrust is not None

    def record(self, event: AegisEvent) -> Path:
        """Append the (already redacted) event to its session's JSONL file."""
        self.traces_dir.mkdir(parents=True, exist_ok=True)
        path = self.traces_dir / f"{event.session_id}.jsonl"
        line = event.model_dump_json()
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        if self._braintrust is not None:
            self._log_braintrust(event)
        return path

    def _log_braintrust(self, event: AegisEvent) -> None:
        try:
            self._braintrust.log(
                input={"phase": event.phase, "summary": event.input_summary},
                output=event.policy_decision.model_dump() if event.policy_decision else None,
                metadata={"session_id": event.session_id, "event_id": event.event_id},
            )
        except Exception:  # noqa: BLE001 — observability must never break the guard path
            self._braintrust = None


def _try_braintrust():
    """Return a Braintrust logger if keyed and importable, else None (silent fallback)."""
    # Load .env / .env.local so the key activates regardless of how the client was built.
    from aegis.config import load_env

    load_env()
    if not os.environ.get("BRAINTRUST_API_KEY"):
        return None
    try:
        import braintrust

        return braintrust.init_logger(project="Aegis Credential Defense")
    except Exception:  # noqa: BLE001 — absence of Braintrust is an expected, supported state
        return None
