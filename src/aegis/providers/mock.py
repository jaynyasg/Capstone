"""Deterministic mock provider — offline tests and the scripted demo fallback (PRD §3.7)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from aegis.providers.base import Provider, ProviderResponse, ToolCall

Responder = Callable[[list[dict[str, Any]]], ProviderResponse]


class MockProvider(Provider):
    """Returns scripted responses. Use `responder` for dynamic behavior, else a fixed reply."""

    name = "mock"

    def __init__(
        self,
        text: str = "ok",
        tool_calls: list[ToolCall] | None = None,
        responder: Responder | None = None,
    ) -> None:
        self._text = text
        self._tool_calls = tool_calls or []
        self._responder = responder

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        if self._responder is not None:
            return self._responder(messages)
        return ProviderResponse(text=self._text, tool_calls=list(self._tool_calls))
