"""FastAPI gateway (FR-2) — a thin local service over the SAME AegisClient.

The gateway never reimplements security logic: it calls the SDK guards, forwards only
allowed/sanitized traffic to a provider, scans the response and any tool calls, and records
traces. Apps that route through it accumulate real traces (a live capture path), and the
dashboard is served from those traces at `GET /`.
"""

from __future__ import annotations

import os
import sqlite3
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.responses import HTMLResponse

from aegis.cift import CiftCalibrationRequest, CiftCertificationStore, calibrate_model
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
    CiftCalibrationBody,
    GuardRequestBody,
    GuardResponseBody,
    GuardToolBody,
    PlantCanaryBody,
)
from aegis.gateway.playground import render_playground
from aegis.platform import PlatformOverview, load_eval_metrics_with_health
from aegis.platform.exports import collect_audit_bundle, render_markdown_bundle
from aegis.platform.snapshots import SnapshotCache
from aegis.platform.sqlite_store import SqliteEvidenceStore, build_overview_from_store, sync_store
from aegis.platform.store import (
    SCHEMA_VERSION,
    EvidenceHealth,
    EvidenceQuery,
    RecordWindow,
)
from aegis.providers.base import Provider

_REFUSAL = "[blocked by Aegis: withheld]"


def _window_response(kind: str, window: RecordWindow) -> dict[str, Any]:
    """Versioned drilldown envelope: schema version + query metadata + truthful total."""
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "query": window.query.model_dump(),
        "total": window.total,
        "latest": window.latest,
    }


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
    cift_store = CiftCertificationStore(settings.cift_path)
    store = SqliteEvidenceStore(settings.evidence_db_path)

    app = FastAPI(title="Aegis Gateway", version="0.1.0")

    def _query(
        limit: int = 25,
        offset: int = 0,
        session_id: str | None = None,
        action: str | None = None,
        phase: str | None = None,
        detector: str | None = None,
        model_id: str | None = None,
        since: float | None = None,
        until: float | None = None,
    ) -> EvidenceQuery:
        # EvidenceQuery clamps unsafe limits/offsets, so every platform endpoint bounds reads
        # consistently regardless of the query string the caller sent.
        return EvidenceQuery(
            limit=limit,
            offset=offset,
            session_id=session_id,
            action=action,
            phase=phase,
            detector=detector,
            model_id=model_id,
            since=since,
            until=until,
        )

    def _sync_store() -> None:
        try:
            sync_store(store, settings, canaries=client.registry.safe_records())
        except sqlite3.OperationalError:
            # A transient lock during import (e.g. a concurrent writer) must not 500 a read: the
            # store already holds the previously imported rows, so serve those. Raw JSONL remains
            # the source of truth, so the next successful sync catches up.
            pass

    def _platform_overview(query: EvidenceQuery | None = None) -> PlatformOverview:
        return build_overview_from_store(
            store=store,
            settings=settings,
            provider_name=provider.name,
            braintrust_enabled=client.tracer.braintrust_enabled,
            ml_probe_available=client.ml_probe.available if client.ml_probe else False,
            canaries=client.registry.safe_records(),
            metrics=load_metrics(DEFAULT_REPORTS_DIR),
            extra_warnings=client.registry.health_warnings(),
            reports_dir=DEFAULT_REPORTS_DIR,
            query=query or EvidenceQuery(),
        )

    snapshot_cache = SnapshotCache(
        builder=lambda: _platform_overview(EvidenceQuery()),
        refresh_interval=settings.snapshot_refresh_seconds,
        stale_after=settings.snapshot_stale_seconds,
    )

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

    @app.post("/canaries/plant")
    def plant_canary(body: PlantCanaryBody) -> dict[str, Any]:
        return client.plant_canary(
            body.service,
            body.session_id,
            body.location,
            body.format_slug,
            body.metadata,
        ).model_dump()

    @app.get("/api/canaries")
    def canaries(session_id: str | None = None) -> dict[str, Any]:
        return {"canaries": client.registry.safe_records(session_id)}

    @app.post("/cift/calibrate")
    def cift_calibrate(body: CiftCalibrationBody) -> dict[str, Any]:
        metrics = load_metrics(DEFAULT_REPORTS_DIR)
        request = CiftCalibrationRequest(**body.model_dump())
        cert = calibrate_model(request, metrics)
        cift_store.append(cert)
        return cert.model_dump()

    @app.get("/api/cift/certifications")
    def cift_certifications(model_id: str | None = None, limit: int = 25) -> dict[str, Any]:
        return {"certifications": cift_store.list(model_id, limit)}

    @app.get("/api/decisions")
    def decisions(limit: int = 25) -> dict[str, Any]:
        return {"decisions": load_recent_decisions(settings.traces_dir, limit)}

    @app.get("/api/platform/overview")
    def platform_overview(limit: int = 25) -> dict[str, Any]:
        # The overview is the global cockpit; per-session/action/phase filtering is a drilldown
        # concern (e.g. /api/platform/decisions?session_id=…), so the overview takes no filter
        # params. That keeps it internally consistent — total always equals the sum of each
        # breakdown — and lets the default shape be served from the cache.
        query = _query(limit=limit)
        # Only the unfiltered default shape is cacheable; pydantic value-equality tracks new
        # query fields automatically (a hand-rolled field list would silently go stale).
        if query == EvidenceQuery():
            return snapshot_cache.get().model_dump()  # cached + freshness-labelled
        return _platform_overview(query).model_dump()

    @app.get("/api/platform/decisions")
    def platform_decisions(
        limit: int = 25,
        offset: int = 0,
        session_id: str | None = None,
        action: str | None = None,
        phase: str | None = None,
        detector: str | None = None,
        since: float | None = None,
        until: float | None = None,
    ) -> dict[str, Any]:
        _sync_store()
        query = _query(
            limit=limit,
            offset=offset,
            session_id=session_id,
            action=action,
            phase=phase,
            detector=detector,
            since=since,
            until=until,
        )
        return _window_response("decisions", store.decisions(query))

    @app.get("/api/platform/sessions")
    def platform_sessions(limit: int = 25, offset: int = 0) -> dict[str, Any]:
        _sync_store()
        return _window_response("sessions", store.sessions(_query(limit=limit, offset=offset)))

    @app.get("/api/platform/detectors")
    def platform_detectors(limit: int = 25, offset: int = 0) -> dict[str, Any]:
        _sync_store()
        return _window_response("detectors", store.detectors(_query(limit=limit, offset=offset)))

    @app.get("/api/platform/canaries")
    def platform_canaries(
        limit: int = 25, offset: int = 0, session_id: str | None = None
    ) -> dict[str, Any]:
        _sync_store()
        query = _query(limit=limit, offset=offset, session_id=session_id)
        return _window_response("canaries", store.canaries(query))

    @app.get("/api/platform/cift")
    def platform_cift(
        limit: int = 25, offset: int = 0, model_id: str | None = None
    ) -> dict[str, Any]:
        _sync_store()
        query = _query(limit=limit, offset=offset, model_id=model_id)
        return _window_response("cift", store.cift(query))

    @app.get("/api/platform/health")
    def platform_health() -> dict[str, Any]:
        _sync_store()
        _, metrics_warnings = load_eval_metrics_with_health(DEFAULT_REPORTS_DIR)
        health = EvidenceHealth.from_warnings(
            store.health().warnings + metrics_warnings + client.registry.health_warnings()
        )
        return {"schema_version": SCHEMA_VERSION, **health.model_dump()}

    @app.get("/api/platform/export")
    def platform_export(
        fmt: str = Query("json", alias="format"),
        limit: int = 200,
        offset: int = 0,
        session_id: str | None = None,
        action: str | None = None,
        phase: str | None = None,
    ) -> Any:
        # Validate the format up front so an unknown value is a clear 400, never a silent
        # JSON default, and a bad request skips the (heavier) overview/bundle build.
        fmt_norm = fmt.lower()
        if fmt_norm not in ("json", "md", "markdown"):
            raise HTTPException(
                status_code=400, detail=f"unsupported format '{fmt}'; use one of: json, md"
            )
        query = _query(
            limit=limit, offset=offset, session_id=session_id, action=action, phase=phase
        )
        overview = _platform_overview(query)
        bundle = collect_audit_bundle(overview=overview, store=store, query=query)
        if fmt_norm in ("md", "markdown"):
            return Response(
                render_markdown_bundle(bundle), media_type="text/markdown; charset=utf-8"
            )
        return bundle

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        """Serve the operator console from the shared platform contract (one evidence source)."""
        cases = load_cases(DEFAULT_REPORTS_DIR)
        platform = snapshot_cache.get()  # shares the cache + freshness with the API
        nav = (
            '<a href="/try" style="font-size:13px;color:#005ea2;margin-right:14px">'
            "Test console →</a>"
        )
        # The cache refreshes within its window; the meta-refresh keeps the feed live.
        return render_html(
            platform.model_dump(),
            cases=cases,
            nav_html=nav,
            auto_refresh=5,
        )

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
