"""Encoding scanner — decode base64/hex/url/fragmentation, then scan for secrets (C2).

Closes the "encoded leak bypasses scanner" failure mode (PRD §9): decode common
transforms before applying the credential patterns.
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from typing import Any

from aegis.contracts import Action, DetectorResult
from aegis.detectors._credutil import find_credentials
from aegis.detectors.base import ScanContext, timed

_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_TOKEN = re.compile(r"\b[0-9a-fA-F]{32,}\b")


def _try_base64(token: str) -> str | None:
    try:
        raw = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return None
    text = raw.decode("utf-8", errors="ignore")
    return text if text.isprintable() and text else None


def _try_hex(token: str) -> str | None:
    if len(token) % 2 != 0:
        return None
    try:
        raw = bytes.fromhex(token)
    except ValueError:
        return None
    text = raw.decode("utf-8", errors="ignore")
    return text if text.isprintable() and text else None


def _decoded_candidates(text: str) -> list[tuple[str, str]]:
    """Yield (encoding, decoded_text) pairs to re-scan for credentials."""
    out: list[tuple[str, str]] = []
    for token in _B64_TOKEN.findall(text):
        decoded = _try_base64(token)
        if decoded:
            out.append(("base64", decoded))
    for token in _HEX_TOKEN.findall(text):
        decoded = _try_hex(token)
        if decoded:
            out.append(("hex", decoded))
    if "%" in text:
        out.append(("url", urllib.parse.unquote(text)))
    # Fragmentation: strip whitespace so split tokens recombine (ghp_ 0123 4567 -> ghp_0123...).
    despaced = re.sub(r"\s+", "", text)
    if despaced != text:
        out.append(("fragmentation", despaced))
    return out


class EncodingScanner:
    name = "encoding_scanner"

    def scan(self, ctx: ScanContext) -> DetectorResult:
        with timed() as elapsed:
            matches: list[dict[str, Any]] = []
            seen: set[tuple[str, str]] = set()
            for encoding, decoded in _decoded_candidates(ctx.text):
                for cred in find_credentials(decoded):
                    key = (encoding, cred["kind"])
                    if key in seen:
                        continue
                    seen.add(key)
                    matches.append({"encoding": encoding, **cred})
            ms = elapsed()
        if matches:
            return DetectorResult(
                detector_name=self.name,
                score=0.85,
                confidence=0.9,
                recommended_action=Action.BLOCK,
                evidence={"matches": matches, "count": len(matches)},
                latency_ms=ms,
            )
        return DetectorResult(
            detector_name=self.name,
            score=0.0,
            confidence=0.85,
            recommended_action=Action.ALLOW,
            evidence={"matches": []},
            latency_ms=ms,
        )
