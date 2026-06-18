"""Live OpenAI adapter (gpt-4o-mini by default). One of N adapters behind Provider.

Validates the SDK response shape at the seam before handing tool calls inward.
"""

from __future__ import annotations

import json
from typing import Any

from aegis.providers.base import Provider, ProviderResponse, ToolCall


class OpenAIProvider(Provider):
    name = "openai"

    def __init__(self, model: str = "gpt-4o-mini", api_key: str | None = None) -> None:
        from openai import OpenAI  # imported lazily so offline tests never need the SDK

        self.model = model
        self._client = OpenAI(api_key=api_key) if api_key else OpenAI()

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        kwargs: dict[str, Any] = {"model": self.model, "messages": messages}
        if tools:
            kwargs["tools"] = tools
        completion = self._client.chat.completions.create(**kwargs)
        message = completion.choices[0].message
        return ProviderResponse(
            text=message.content or "",
            tool_calls=_parse_tool_calls(message),
            raw=completion,
        )


def _parse_tool_calls(message: Any) -> list[ToolCall]:
    """Guard truncation / shape-drift: malformed tool-call JSON degrades to {} not a crash."""
    calls: list[ToolCall] = []
    for call in getattr(message, "tool_calls", None) or []:
        try:
            args = json.loads(call.function.arguments or "{}")
        except (json.JSONDecodeError, AttributeError):
            args = {"_unparsed": getattr(getattr(call, "function", None), "arguments", "")}
        calls.append(ToolCall(name=call.function.name, arguments=args))
    return calls
