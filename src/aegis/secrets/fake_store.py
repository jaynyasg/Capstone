"""Local fake secret store (MVP only — never a production secret manager).

Resolves opaque handles like `secret://github/token` to raw values held in memory,
seeded from a dict or environment variables. Out of scope: rotation, IAM, cloud KMS.
"""

from __future__ import annotations

import os


class FakeSecretStore:
    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self._secrets: dict[str, str] = dict(secrets or {})

    @classmethod
    def from_env(cls, mapping: dict[str, str]) -> FakeSecretStore:
        """Build from {handle: ENV_VAR_NAME}, skipping vars that are unset."""
        resolved = {
            handle: os.environ[var] for handle, var in mapping.items() if os.environ.get(var)
        }
        return cls(resolved)

    def put(self, handle: str, value: str) -> None:
        self._secrets[handle] = value

    def get(self, handle: str) -> str | None:
        return self._secrets.get(handle)

    def handles(self) -> list[str]:
        return list(self._secrets)

    def items(self) -> list[tuple[str, str]]:
        return list(self._secrets.items())
