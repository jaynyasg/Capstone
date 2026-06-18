"""FastAPI gateway — local service wrapping the Aegis SDK (FR-2)."""

from aegis.gateway.app import create_app

__all__ = ["create_app"]
