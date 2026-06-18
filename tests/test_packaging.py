"""Guard against the deploy-killer class of bug: source silently excluded from the build.

Editable installs (what pytest normally uses) read src/ directly, so a source file that is
git-ignored — and therefore absent from the built wheel — still imports locally but crashes
on a clean deploy (Render). This test fails if any src/aegis source file is git-ignored.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "aegis"


def test_no_source_file_is_gitignored() -> None:
    files = [p.relative_to(ROOT).as_posix() for p in SRC.rglob("*.py")]
    assert files, "no source files found — wrong layout?"
    try:
        result = subprocess.run(
            ["git", "check-ignore", *files],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        pytest.skip("git not available")
    if result.returncode not in (0, 1):  # 0=some ignored, 1=none ignored, 128=not a repo
        pytest.skip("not a git repository")
    ignored = [line for line in result.stdout.splitlines() if line.strip()]
    assert not ignored, f"source files excluded from the build by .gitignore: {ignored}"
