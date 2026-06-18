"""C2 — encoding scanner decodes base64/hex/url/fragmentation before scanning."""

from __future__ import annotations

import base64
import urllib.parse

from aegis.contracts import Action
from aegis.detectors.encodings import EncodingScanner
from tests.conftest import FAKE_CONN_STRING, FAKE_GITHUB_PAT, request_ctx

scanner = EncodingScanner()


def test_decodes_base64_secret() -> None:
    encoded = base64.b64encode(FAKE_GITHUB_PAT.encode()).decode()
    result = scanner.scan(request_ctx(f"decode this: {encoded}"))
    assert result.score >= 0.7
    assert result.recommended_action in (Action.BLOCK, Action.ESCALATE)
    assert "base64" in {m["encoding"] for m in result.evidence["matches"]}


def test_decodes_hex_secret() -> None:
    encoded = FAKE_GITHUB_PAT.encode().hex()
    result = scanner.scan(request_ctx(encoded))
    assert result.score >= 0.7
    assert "hex" in {m["encoding"] for m in result.evidence["matches"]}


def test_decodes_url_secret() -> None:
    # A connection string has reserved chars (://@:), so url-encoding actually transforms it.
    encoded = urllib.parse.quote(FAKE_CONN_STRING, safe="")
    result = scanner.scan(request_ctx(f"https://x.test/?q={encoded}"))
    assert result.score >= 0.7
    assert "url" in {m["encoding"] for m in result.evidence["matches"]}


def test_reconstructs_fragmented_secret() -> None:
    # Attacker splits the token to dodge a naive scan.
    fragmented = " ".join(FAKE_GITHUB_PAT[i : i + 4] for i in range(0, len(FAKE_GITHUB_PAT), 4))
    result = scanner.scan(request_ctx(fragmented))
    assert result.score >= 0.7
    assert "fragmentation" in {m["encoding"] for m in result.evidence["matches"]}


def test_ignores_benign_encodings() -> None:
    encoded = base64.b64encode(b"the quick brown fox jumps").decode()
    result = scanner.scan(request_ctx(encoded))
    assert result.recommended_action == Action.ALLOW
    assert result.score < 0.5
