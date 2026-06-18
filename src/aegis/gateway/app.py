"""FastAPI gateway (FR-2) — a thin local service over the SAME AegisClient.

The gateway never reimplements security logic: it calls the SDK guards, forwards only
allowed/sanitized traffic to a provider, scans the response and any tool calls, and records
traces. Apps that route through it accumulate real traces (a live capture path), and the
dashboard is served from those traces at `GET /`.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse

from aegis.client import AegisClient
from aegis.config import Settings
from aegis.dashboard.render import (
    DEFAULT_REPORTS_DIR,
    load_cases,
    load_metrics,
    load_recent_decisions,
    render_html,
)
from aegis.gateway.auth import add_basic_auth, add_rate_limit, auth_from_env
from aegis.gateway.models import (
    ChatRequest,
    GuardRequestBody,
    GuardResponseBody,
    GuardToolBody,
)
from aegis.gateway.playground import render_playground
from aegis.providers.base import Provider

_REFUSAL = "[blocked by Aegis: withheld]"


def _build_provider() -> Provider:
    """Live OpenAI adapter when keyed, else a deterministic mock (offline-safe)."""
    if os.environ.get("OPENAI_API_KEY"):
        from aegis.providers.openai_adapter import OpenAIProvider

        return OpenAIProvider("gpt-4o-mini")
    from aegis.providers.mock import MockProvider

    return MockProvider(text="ok")


def create_app(
    settings: Settings | None = None,
    provider: Provider | None = None,
    client: AegisClient | None = None,
    auth: tuple[str, str] | None = None,
    rate_limit_per_min: int | None = None,
) -> FastAPI:
    settings = settings or Settings.load()
    client = client or AegisClient(settings=settings)
    provider = provider or _build_provider()

    app = FastAPI(title="Aegis Gateway", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "policy_mode": str(settings.policy_mode),
            "provider": provider.name,
            "braintrust": client.tracer.braintrust_enabled,
            "ml_probe": client.ml_probe.available if client.ml_probe else False,
        }

    @app.post("/v1/chat/completions")
    def chat(req: ChatRequest) -> dict[str, Any]:
        """Full proxy: guard request -> provider -> guard tool calls + response."""
        request_decision = client.guard_request(req.messages, req.tools, req.session_id)
        if not request_decision.allowed:
            return {
                "session_id": req.session_id,
                "blocked": True,
                "output": _REFUSAL,
                "tool_calls": [],
                "aegis": {
                    "request": request_decision.model_dump(),
                    "response": None,
                    "tool_calls": [],
                },
            }

        completion = provider.complete(req.messages, req.tools)

        tool_results = []
        for call in completion.tool_calls:
            decision = client.guard_tool_call(call.name, call.arguments, req.session_id)
            tool_results.append((call, decision))

        response_decision = client.guard_response(completion.text, req.session_id)
        blocked = not response_decision.allowed or any(not d.allowed for _, d in tool_results)
        output = completion.text if response_decision.allowed else _REFUSAL

        return {
            "session_id": req.session_id,
            "blocked": blocked,
            "output": output,
            "tool_calls": [
                {"name": c.name, "allowed": d.allowed, "decision": d.model_dump()}
                for c, d in tool_results
            ],
            "aegis": {
                "request": request_decision.model_dump(),
                "response": response_decision.model_dump(),
                "tool_calls": [d.model_dump() for _, d in tool_results],
            },
        }

    @app.post("/guard/request")
    def guard_request(body: GuardRequestBody) -> dict[str, Any]:
        return client.guard_request(
            body.messages, body.tools, body.session_id, body.metadata
        ).model_dump()

    @app.post("/guard/tool_call")
    def guard_tool_call(body: GuardToolBody) -> dict[str, Any]:
        return client.guard_tool_call(
            body.tool_name, body.arguments, body.session_id, body.metadata
        ).model_dump()

    @app.post("/guard/response")
    def guard_response(body: GuardResponseBody) -> dict[str, Any]:
        return client.guard_response(body.output, body.session_id, body.metadata).model_dump()

    @app.get("/api/decisions")
    def decisions(limit: int = 25) -> dict[str, Any]:
        return {"decisions": load_recent_decisions(settings.traces_dir, limit)}

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        """Serve the dashboard live from current traces + eval metrics."""
        metrics = load_metrics(DEFAULT_REPORTS_DIR)
        cases = load_cases(DEFAULT_REPORTS_DIR)
        recent = load_recent_decisions(settings.traces_dir)
        nav = (
            '<a href="/try" style="font-size:13px;color:#005ea2;margin-right:14px">'
            "Test console →</a>"
        )
        # Served view re-reads traces every request; meta-refresh makes the feed live.
        return render_html(metrics, cases, recent, nav_html=nav, auto_refresh=5)

    @app.get("/try", response_class=HTMLResponse)
    def playground() -> str:
        """Interactive console: type a message, see the live AegisDecision."""
        return render_playground()

    @app.get("/favicon.ico")
    def favicon() -> Response:
        return Response(status_code=204)

    # Hardening for public deploys. Middleware added later runs first, so register the
    # rate limiter first and auth last → auth is the outermost gate.
    limit = rate_limit_per_min
    if limit is None:
        limit = int(os.environ.get("AEGIS_RATE_LIMIT_PER_MIN", "60"))
    if limit > 0:
        add_rate_limit(app, limit)

    credentials = auth if auth is not None else auth_from_env()
    if credentials is not None:
        add_basic_auth(app, credentials[0], credentials[1])

    return app
