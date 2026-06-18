"""Shared fixtures + deterministic fake secrets (never real credentials)."""

from __future__ import annotations

import pytest

from aegis.contracts import Phase
from aegis.detectors.base import ScanContext

# Deterministic, structurally-valid-but-fake credentials used across detector tests.
FAKE_GITHUB_PAT = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"  # 36-char body
FAKE_OPENAI_KEY = "sk-proj-" + "abcd1234EFGH5678" * 3  # 48-char body, mixed
FAKE_AWS_KEY = "AKIA1234567890ABCDEF"  # 16-char body
FAKE_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEA0123456789abcdefABCDEF\n"
    "-----END RSA PRIVATE KEY-----"
)
FAKE_CONN_STRING = "postgresql://admin:s3cr3tPass@db.internal:5432/prod"

# Benign look-alikes that must NOT be flagged in balanced mode.
PLACEHOLDER_PAT = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
AWS_DOC_EXAMPLE = "AKIAIOSFODNN7EXAMPLE"
PLACEHOLDER_TEXT = "Set API_KEY=your_api_key_here in your .env file"


def request_ctx(text: str, session_id: str = "s-test") -> ScanContext:
    return ScanContext(session_id=session_id, phase=Phase.REQUEST, text=text)


def response_ctx(text: str, session_id: str = "s-test") -> ScanContext:
    return ScanContext(session_id=session_id, phase=Phase.RESPONSE, text=text)


def tool_ctx(name: str, arguments: dict, session_id: str = "s-test") -> ScanContext:
    return ScanContext(
        session_id=session_id,
        phase=Phase.TOOL_CALL,
        tool_name=name,
        tool_arguments=arguments,
    )


@pytest.fixture
def fake_secrets() -> dict[str, str]:
    return {
        "github": FAKE_GITHUB_PAT,
        "openai": FAKE_OPENAI_KEY,
        "aws": FAKE_AWS_KEY,
        "pem": FAKE_PEM,
        "conn": FAKE_CONN_STRING,
    }
