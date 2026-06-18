"""Provider abstraction — model calls hidden behind one interface (PRD §4.4.3).

Policy logic never imports a vendor SDK; it speaks these normalized types so a second
provider can be added without touching the security path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass
class ProviderResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: Any = None


class Provider(Protocol):
    name: str

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse: ...
