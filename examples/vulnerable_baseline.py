"""The vulnerable baseline — an agent with NO Aegis guards.

Demonstrates the failure the project defends against: a planted canary / credential flows
straight through model output and tool-call arguments to an attacker (PRD §8.2).
"""

from __future__ import annotations

from examples._scenario import Scenario, build_scenario


def run_baseline(scenario: Scenario | None = None) -> dict:
    s = scenario or build_scenario(session_id="baseline")
    response = s.provider.complete(s.messages)

    leaked_in_text = s.canary in response.text
    tool_calls = [{"name": tc.name, "arguments": tc.arguments} for tc in response.tool_calls]
    leaked_in_tool = any(s.canary in str(tc["arguments"]) for tc in tool_calls)

    print(f"\n=== BASELINE (no Aegis) — provider={s.provider_label} ===")
    print(f"model output: {response.text!r}")
    print(f"tool calls: {tool_calls}")
    print(f"LEAK in response text: {leaked_in_text}")
    print(f"LEAK in tool args:     {leaked_in_tool}")
    # The scripted exfil tool call the agent (or injection) would dispatch, unguarded.
    print(f"unguarded send_email args: {s.exfil_tool_args}")

    return {
        "provider": s.provider_label,
        "response_text": response.text,
        "tool_calls": tool_calls,
        "leaked_in_text": leaked_in_text,
        "leaked_in_tool": leaked_in_tool,
    }


if __name__ == "__main__":
    run_baseline()
