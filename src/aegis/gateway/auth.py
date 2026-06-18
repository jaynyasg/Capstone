"""Gateway hardening for public deployment — HTTP Basic Auth + per-IP rate limiting.

Both are opt-in: with no credentials configured the gateway is open (local dev stays
frictionless); set AEGIS_AUTH_USER / AEGIS_AUTH_PASSWORD to password-gate a public deploy.
This is demo-grade protection, not an identity system (PRD non-goal: no RBAC/tenancy).
"""

from __future__ import annotations

import base64
import binascii
import os
import secrets
import time
from collections import defaultdict

from fastapi import FastAPI, Request, Response

# Always reachable so platform health checks (Render) don't 401.
_OPEN_PATHS = {"/health"}


def auth_from_env() -> tuple[str, str] | None:
    user = os.environ.get("AEGIS_AUTH_USER")
    password = os.environ.get("AEGIS_AUTH_PASSWORD")
    return (user, password) if user and password else None


def add_basic_auth(app: FastAPI, user: str, password: str) -> None:
    """Require HTTP Basic Auth on every route except the health check."""

    @app.middleware("http")
    async def _basic_auth(request: Request, call_next):
        if request.url.path in _OPEN_PATHS:
            return await call_next(request)
        if _credentials_ok(request.headers.get("authorization", ""), user, password):
            return await call_next(request)
        return Response(
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="Aegis"'},
            content="authentication required",
        )


def _credentials_ok(header: str, user: str, password: str) -> bool:
    if not header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(header[6:]).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    got_user, _, got_pass = decoded.partition(":")
    # Constant-time compare on both fields to avoid timing leaks.
    return secrets.compare_digest(got_user, user) and secrets.compare_digest(got_pass, password)


def add_rate_limit(app: FastAPI, per_minute: int) -> None:
    """Fixed-window per-IP limit on POST requests (the costly / abusable ones)."""
    hits: dict[str, list[float]] = defaultdict(list)

    @app.middleware("http")
    async def _rate_limit(request: Request, call_next):
        if request.method != "POST":
            return await call_next(request)
        ip = _client_ip(request)
        now = time.time()
        recent = [t for t in hits[ip] if now - t < 60.0]
        if len(recent) >= per_minute:
            return Response(status_code=429, content="rate limit exceeded; try again shortly")
        recent.append(now)
        hits[ip] = recent
        return await call_next(request)


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
