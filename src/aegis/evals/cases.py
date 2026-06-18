"""Eval case schema + YAML loader (FR-12).

Cases are validated against this pydantic schema at the seam — a malformed YAML case is a
loud error, not a silent skip. A step is rendered just before it runs: canary placeholders
are substituted with the session's registered tokens, then optional encoding is applied.
"""

from __future__ import annotations

import base64
import re
import urllib.parse
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

DEFAULT_CASES_DIR = Path("evals/cases")

# Attack vs benign categories (drives detection-rate vs false-block metrics).
ATTACK_CATEGORIES = {
    "encoded_single_turn",
    "multi_turn_drip",
    "tool_call_exfiltration",
    "canary_touch",
}
BENIGN_CATEGORIES = {
    "benign_normal",
    "benign_secret_handle",
    "false_positive_benign",
}

_CANARY_RE = re.compile(r"\{\{canary:([a-z0-9_]+)\}\}")


class CanarySpec(BaseModel):
    service: str


class Setup(BaseModel):
    secrets: dict[str, str] = Field(default_factory=dict)
    canaries: list[CanarySpec] = Field(default_factory=list)


class EvalStep(BaseModel):
    guard: Literal["request", "tool_call", "response"]
    text: str = ""
    tool_name: str | None = None
    arguments: dict[str, Any] | None = None
    encode: Literal["base64", "hex", "url", "fragment"] | None = None
    expect: str = "allow"


class EvalCase(BaseModel):
    id: str
    title: str
    category: str
    severity: str = "medium"
    setup: Setup = Field(default_factory=Setup)
    steps: list[EvalStep]

    @property
    def is_attack(self) -> bool:
        return self.category in ATTACK_CATEGORIES


def _encode(value: str, kind: str | None) -> str:
    if kind is None:
        return value
    if kind == "base64":
        return base64.b64encode(value.encode()).decode()
    if kind == "hex":
        return value.encode().hex()
    if kind == "url":
        return urllib.parse.quote(value, safe="")
    if kind == "fragment":
        return " ".join(value[i : i + 4] for i in range(0, len(value), 4))
    raise ValueError(f"unknown encode kind: {kind}")


def _substitute(value: str, canary_map: dict[str, str]) -> str:
    def repl(m: re.Match[str]) -> str:
        service = m.group(1)
        if service not in canary_map:
            raise KeyError(f"case references unregistered canary service {service!r}")
        return canary_map[service]

    return _CANARY_RE.sub(repl, value)


def render_step(
    step: EvalStep, canary_map: dict[str, str]
) -> tuple[str, str | None, dict[str, Any] | None]:
    """Resolve placeholders + encoding into the concrete payload handed to a guard."""
    text = _encode(_substitute(step.text, canary_map), step.encode)
    arguments = None
    if step.arguments is not None:
        arguments = {
            k: _encode(_substitute(str(v), canary_map), step.encode)
            for k, v in step.arguments.items()
        }
    return text, step.tool_name, arguments


def load_cases(cases_dir: Path | str = DEFAULT_CASES_DIR) -> list[EvalCase]:
    """Load and validate every *.yaml case under `cases_dir` (sorted for determinism)."""
    directory = Path(cases_dir)
    if not directory.exists():
        raise FileNotFoundError(f"cases dir not found: {directory}")
    cases: list[EvalCase] = []
    for path in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        raw = data["cases"] if isinstance(data, dict) and "cases" in data else data
        for entry in raw:
            cases.append(EvalCase.model_validate(entry))
    return cases
