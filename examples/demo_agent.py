"""The protected agent — the same flow routed through Aegis guards.

guard_request -> model -> guard_response, plus guard_tool_call before any dispatch.
Run directly to see a baseline-vs-protected comparison. Live if OPENAI_API_KEY is set,
otherwise a scripted mock (the demo always runs).
"""

from __future__ import annotations

from aegis import AegisClient, PolicyMode, Settings
from aegis.secrets import CredentialBroker
from examples._scenario import Scenario, build_scenario
from examples.vulnerable_baseline import run_baseline


def build_client(scenario: Scenario, mode: PolicyMode = PolicyMode.BALANCED) -> AegisClient:
    return AegisClient(
        settings=Settings(policy_mode=mode),
        registry=scenario.registry,
        broker=CredentialBroker(scenario.store),
    )


def run_protected(scenario: Scenario | None = None, mode: PolicyMode = PolicyMode.BALANCED) -> dict:
    s = scenario or build_scenario(session_id="protected")
    client = build_client(s, mode)

    # 1. Guard the request (planted canary in untrusted doc is the planting site -> allowed).
    req = client.guard_request(s.messages, session_id=s.session_id)

    # 2. Call the model only if the request is permitted.
    response = s.provider.complete(s.messages)

    # 3. Guard the model output before returning it to the user.
    resp = client.guard_response(response.text, session_id=s.session_id)

    # 4. Guard the exfiltration tool call before any dispatch (the capstone differentiator).
    tool = client.guard_tool_call(
        s.exfil_tool_name, s.exfil_tool_args or {}, session_id=s.session_id
    )

    print(f"\n=== PROTECTED (Aegis, mode={mode}) — provider={s.provider_label} ===")
    print(f"guard_request  -> {req.action}  reasons={req.reasons}")
    print(f"model output: {response.text!r}")
    print(f"guard_response -> {resp.action}  reasons={resp.reasons}")
    print(f"guard_tool_call({s.exfil_tool_name}) -> {tool.action}  reasons={tool.reasons}")

    return {
        "request": req.action,
        "response": resp.action,
        "tool_call": tool.action,
        "blocked_egress": not resp.allowed or not tool.allowed,
    }


def main() -> None:
    s = build_scenario(session_id="demo")
    run_baseline(s)
    # Fresh session id for the protected run so the ledger starts clean.
    s.session_id = "demo-protected"
    run_protected(s)


if __name__ == "__main__":
    main()
