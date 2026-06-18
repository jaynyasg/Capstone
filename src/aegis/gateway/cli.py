"""`aegis-gateway` — run the local FastAPI service with uvicorn.

Env toggles:
  AEGIS_GATEWAY_HOST   bind host   (default 127.0.0.1)
  AEGIS_GATEWAY_PORT   bind port   (default 8000)
  AEGIS_GATEWAY_RELOAD 1 to auto-restart on source changes (dev; default off)
"""

from __future__ import annotations

import os


def main() -> int:
    import uvicorn

    host = os.environ.get("AEGIS_GATEWAY_HOST", "127.0.0.1")
    port = int(os.environ.get("AEGIS_GATEWAY_PORT", "8000"))
    reload = os.environ.get("AEGIS_GATEWAY_RELOAD", "0") == "1"

    print(
        f"Aegis gateway on http://{host}:{port}  "
        f"(dashboard at /, test console at /try, health at /health)"
        + ("  [reload on]" if reload else "")
    )
    # Import string + factory so --reload can re-import the app on file changes.
    uvicorn.run(
        "aegis.gateway.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
