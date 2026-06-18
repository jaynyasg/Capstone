"""`aegis-dashboard` — regenerate the static HTML console from traces + eval metrics."""

from __future__ import annotations

from aegis.dashboard.render import (
    DEFAULT_OUT,
    DEFAULT_REPORTS_DIR,
    DEFAULT_TRACES_DIR,
    generate,
)


def main() -> int:
    out = generate(DEFAULT_TRACES_DIR, DEFAULT_REPORTS_DIR, DEFAULT_OUT)
    print(f"dashboard written: {out.resolve()}")
    print(f"open it: file:///{out.resolve().as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
