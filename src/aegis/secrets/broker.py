"""Credential broker (C8 / FR-9 / PRD §6.5).

Two jobs:
1. Resolve opaque `secret://...` handles to raw values *inside trusted tool execution only*.
2. Assert that raw secret values never enter model-visible context. If one does (and the
   run is not explicit local test mode), redact it, mark the event critical, and force a
   non-allow decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis.contracts import Action
from aegis.secrets.fake_store import FakeSecretStore

HANDLE_PREFIX = "secret://"
_REDACTION = "[REDACTED:secret]"


@dataclass
class BrokerAssessment:
    raw_secret_present: bool
    leaked_handles: list[str] = field(default_factory=list)
    redacted_text: str = ""
    critical: bool = False
    forced_action: Action | None = None


class CredentialBroker:
    def __init__(self, store: FakeSecretStore | None = None) -> None:
        self.store = store or FakeSecretStore()

    def resolve(self, handle: str) -> str:
        """Resolve a handle to its raw value — call ONLY inside trusted tool execution."""
        if not handle.startswith(HANDLE_PREFIX):
            raise ValueError(f"not a secret handle: {handle!r}")
        value = self.store.get(handle)
        if value is None:
            raise KeyError(f"unknown secret handle: {handle!r}")
        return value

    def assess_context(self, text: str, *, local_test_mode: bool = False) -> BrokerAssessment:
        """Check model-visible text for raw secret values (not opaque handles)."""
        if not text:
            return BrokerAssessment(raw_secret_present=False, redacted_text=text)

        leaked: list[str] = []
        redacted = text
        for handle, value in self.store.items():
            if value and value in redacted:
                leaked.append(handle)
                redacted = redacted.replace(value, _REDACTION)

        if not leaked:
            return BrokerAssessment(raw_secret_present=False, redacted_text=text)

        # Raw secret in context is always critical; only local test mode avoids forcing block.
        forced = None if local_test_mode else Action.BLOCK
        return BrokerAssessment(
            raw_secret_present=True,
            leaked_handles=leaked,
            redacted_text=redacted,
            critical=True,
            forced_action=forced,
        )
