"""The verify gate — offline, deterministic checks only (ruff + pytest).

Bound to the project Stop hook so it can never silently rot. Live LLM / Braintrust /
deploy oracles run on demand, never here: a slow or flaky gate trains you to ignore it.
"""

from __future__ import annotations

import shutil
import subprocess
import sys


def _run(name: str, args: list[str]) -> int:
    exe = shutil.which(name) or name
    print(f"\n$ {name} {' '.join(args)}")
    return subprocess.run([exe, *args]).returncode  # noqa: S603 — fixed, local dev tools


def main() -> int:
    rc = 0
    rc |= _run("ruff", ["check", "."])
    rc |= _run("pytest", ["-q", "-m", "not live"])
    if rc:
        print("\nverify: FAIL")
        sys.exit(1)
    print("\nverify: OK")
    return 0


if __name__ == "__main__":
    main()
