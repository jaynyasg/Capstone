"""Shared credential-shape matching — the single source of truth for "is this a secret".

Used by the direct pattern scanner, the encoding scanner (post-decode), and the tool-call
argument scanner. Returns redacted evidence only; raw secrets never leave here.
"""

from __future__ import annotations

import re
from typing import Any

# (kind, compiled pattern). The capturing group, when present, is the high-entropy body
# used for the placeholder / low-entropy check.
CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("github_pat", re.compile(r"\bghp_([A-Za-z0-9]{36})\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?([A-Za-z0-9_-]{20,})\b")),
    ("aws_access_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("slack_token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "connection_string",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:@/]+:[^\s:@/]+@[^\s/]+"),
    ),
]

_PLACEHOLDER_MARKERS = ("example", "your_", "_here", "placeholder", "dummy", "xxxx", "<", ">")


def _looks_placeholder(full_match: str, body: str | None) -> bool:
    """True for documentation/example/placeholder values that must not be flagged."""
    low = full_match.lower()
    if any(marker in low for marker in _PLACEHOLDER_MARKERS):
        return True
    # Low-entropy bodies (e.g. all-x or all-zero placeholders) are not real secrets.
    if body and len(body) >= 12 and len(set(body)) <= 4:
        return True
    return False


def redact(value: str, keep: int = 4) -> str:
    """Log-safe preview that never contains the full secret."""
    value = value.strip()
    if len(value) <= keep:
        return f"…[{len(value)} chars]"
    return f"{value[:keep]}…[{len(value)} chars]"


def redact_text(text: str, marker: str = "[REDACTED:secret]") -> str:
    """Mask every credential match in `text` — for log-safe summaries."""
    if not text:
        return text
    spans = sorted(
        ((m["start"], m["end"]) for m in find_credentials(text)),
        reverse=True,
    )
    for start, end in spans:
        text = text[:start] + marker + text[end:]
    return text


def find_credentials(text: str) -> list[dict[str, Any]]:
    """Return one redacted evidence dict per distinct credential match in `text`."""
    if not text:
        return []
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for kind, pattern in CREDENTIAL_PATTERNS:
        for m in pattern.finditer(text):
            body = m.group(1) if m.groups() else None
            if _looks_placeholder(m.group(0), body):
                continue
            key = (kind, m.start())
            if key in seen:
                continue
            seen.add(key)
            found.append(
                {
                    "kind": kind,
                    "preview": redact(m.group(0)),
                    "start": m.start(),
                    "end": m.end(),
                }
            )
    return found
