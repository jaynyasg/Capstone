"""Shape-only honeytoken generator adapted from the DP-HONEY format registry.

Generated values mimic credential families closely enough to exercise scanners, but every
format is synthetic-only: Aegis never claims provider validity, authentication, signing, or
decryptability for generated canaries.
"""

from __future__ import annotations

import hashlib
import json
import random
import string
import zlib
from collections.abc import Callable
from dataclasses import dataclass

UPPER = string.ascii_uppercase
LOWER = string.ascii_lowercase
DIGITS = string.digits
ALNUM = UPPER + LOWER + DIGITS
UPPER_DIGITS = UPPER + DIGITS
BASE64 = ALNUM + "+/"
BASE64URL = ALNUM + "-_"
PASSWORD = ALNUM + "!@#$%^&*()-_=+"
HEX = "0123456789abcdef"
SHAPE_ONLY = (
    "Shape-only synthetic value: not provider-valid, signed, decryptable, "
    "authenticated, or usable."
)

DEFAULT_SERVICE_FORMATS = {
    "anthropic": "anthropic-api-key",
    "aws": "aws-access-key-id",
    "database": "database-password",
    "github": "github-ghp",
    "google": "google-api-key",
    "openai": "openai-project-key",
    "slack": "slack-bot-token",
    "stripe": "stripe-sk-live",
    "twilio": "twilio-account-sid",
}


@dataclass(frozen=True)
class Literal:
    text: str

    def to_dict(self) -> dict[str, object]:
        return {"kind": "literal", "text": self.text}


@dataclass(frozen=True)
class Variable:
    name: str
    alphabet: str
    length: int

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "variable",
            "name": self.name,
            "alphabet": self.alphabet,
            "length": self.length,
        }


@dataclass(frozen=True)
class Checksum:
    name: str
    length: int
    algorithm: str

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "checksum",
            "name": self.name,
            "length": self.length,
            "algorithm": self.algorithm,
        }


Segment = Literal | Variable | Checksum


@dataclass(frozen=True)
class HoneytokenFormat:
    slug: str
    name: str
    description: str
    category: str
    segments: tuple[Segment, ...]
    safety_note: str
    provider_valid: bool = False
    scannable: bool = True
    extra_predicate: Callable[[str], bool] | None = None

    def variable_segments(self) -> list[Variable]:
        return [segment for segment in self.segments if isinstance(segment, Variable)]

    def assemble(self, variables: list[str]) -> str:
        out: list[str] = []
        checksum_input: list[str] = []
        vi = 0
        for segment in self.segments:
            if isinstance(segment, Literal):
                out.append(segment.text)
            elif isinstance(segment, Variable):
                value = variables[vi]
                out.append(value)
                checksum_input.append(value)
                vi += 1
            else:
                out.append(
                    _compute_checksum(
                        segment.algorithm, "".join(checksum_input), segment.length
                    )
                )
        return "".join(out)

    def validate(self, token: str) -> bool:
        return self.extract_variables(token) is not None and (
            self.extra_predicate is None or self.extra_predicate(token)
        )

    def extract_variables(self, token: str) -> list[str] | None:
        pos = 0
        variables: list[str] = []
        checksum_input: list[str] = []
        for segment in self.segments:
            if isinstance(segment, Literal):
                if not token.startswith(segment.text, pos):
                    return None
                pos += len(segment.text)
            elif isinstance(segment, Variable):
                chunk = token[pos : pos + segment.length]
                if len(chunk) != segment.length or any(c not in segment.alphabet for c in chunk):
                    return None
                variables.append(chunk)
                checksum_input.append(chunk)
                pos += segment.length
            else:
                chunk = token[pos : pos + segment.length]
                if len(chunk) != segment.length:
                    return None
                expected = _compute_checksum(
                    segment.algorithm, "".join(checksum_input), segment.length
                )
                if chunk != expected:
                    return None
                pos += segment.length
        return variables if pos == len(token) else None

    def random_example(
        self,
        rng: random.Random | random.SystemRandom | None = None,
        max_attempts: int = 1000,
    ) -> str:
        sampler = rng or random.SystemRandom()
        for _ in range(max_attempts):
            variables = [
                "".join(sampler.choice(segment.alphabet) for _ in range(segment.length))
                for segment in self.variable_segments()
            ]
            token = self.assemble(variables)
            if self.extra_predicate is None or self.extra_predicate(token):
                return token
        raise RuntimeError(f"could not generate spec-valid honeytoken for {self.slug!r}")

    def to_snapshot(self) -> dict[str, object]:
        return {
            "slug": self.slug,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "provider_valid": self.provider_valid,
            "safety_note": self.safety_note,
            "segments": [segment.to_dict() for segment in self.segments],
        }

    def spec_hash(self) -> str:
        blob = json.dumps(self.to_snapshot(), sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class GeneratedHoneytoken:
    token: str
    format_slug: str
    provider_valid: bool
    safety_note: str
    spec_hash: str


class HoneytokenGenerator:
    def __init__(self, seed: int | None = None) -> None:
        self._rng: random.Random | random.SystemRandom
        self._rng = random.Random(seed) if seed is not None else random.SystemRandom()

    def generate(self, format_slug: str) -> GeneratedHoneytoken:
        spec = get_honeytoken_format(format_slug)
        token = spec.random_example(self._rng)
        return GeneratedHoneytoken(
            token=token,
            format_slug=spec.slug,
            provider_valid=spec.provider_valid,
            safety_note=spec.safety_note,
            spec_hash=spec.spec_hash(),
        )


def list_honeytoken_format_slugs() -> list[str]:
    return sorted(_FORMATS)


def list_honeytoken_formats() -> list[HoneytokenFormat]:
    return [_FORMATS[slug] for slug in list_honeytoken_format_slugs()]


def get_honeytoken_format(slug: str) -> HoneytokenFormat:
    try:
        return _FORMATS[slug]
    except KeyError:
        known = ", ".join(list_honeytoken_format_slugs())
        raise ValueError(f"unknown honeytoken format {slug!r}. Known formats: {known}") from None


def default_format_for_service(service: str) -> str:
    return DEFAULT_SERVICE_FORMATS.get(service.lower(), "generic-sk")


def generate_honeytoken(format_slug: str, seed: int | None = None) -> GeneratedHoneytoken:
    return HoneytokenGenerator(seed=seed).generate(format_slug)


def _password_predicate(token: str) -> bool:
    return (
        any(c in LOWER for c in token)
        and any(c in UPPER for c in token)
        and any(c in DIGITS for c in token)
    )


_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _to_base62(number: int) -> str:
    if number == 0:
        return _BASE62[0]
    digits: list[str] = []
    while number:
        number, remainder = divmod(number, 62)
        digits.append(_BASE62[remainder])
    return "".join(reversed(digits))


def _github_crc32_base62(body: str, length: int) -> str:
    checksum = zlib.crc32(body.encode("ascii")) & 0xFFFFFFFF
    return _to_base62(checksum).rjust(length, _BASE62[0])[:length]


def _compute_checksum(algorithm: str, body: str, length: int) -> str:
    if algorithm == "github-crc32-base62":
        return _github_crc32_base62(body, length)
    raise KeyError(f"unknown checksum algorithm: {algorithm}")


def _note(prefix: str) -> str:
    return prefix + " " + SHAPE_ONLY


_SPECS: tuple[HoneytokenFormat, ...] = (
    HoneytokenFormat(
        slug="aws-access-key-id",
        name="AWS Access Key ID",
        description="AWS access key identifier shape.",
        category="cloud-key",
        segments=(Literal("AKIA"), Variable("body", UPPER_DIGITS, 16)),
        safety_note=_note("AKIA-prefixed identifier shape."),
    ),
    HoneytokenFormat(
        slug="aws-secret-access-key",
        name="AWS Secret Access Key",
        description="AWS secret access key shape.",
        category="cloud-secret",
        segments=(Variable("body", BASE64, 40),),
        safety_note=_note("40-character AWS-secret shape."),
        scannable=False,
    ),
    HoneytokenFormat(
        slug="oauth-bearer",
        name="OAuth Bearer Token",
        description="Opaque OAuth bearer token shape.",
        category="token",
        segments=(Variable("token", BASE64URL, 40),),
        safety_note=_note("Opaque bearer-token shape."),
        scannable=False,
    ),
    HoneytokenFormat(
        slug="generic-sk",
        name="Generic sk- API Key",
        description="Generic sk-prefixed API key shape.",
        category="api-key",
        segments=(Literal("sk-"), Variable("body", ALNUM, 48)),
        safety_note=_note("'sk-'-prefixed API-key shape."),
    ),
    HoneytokenFormat(
        slug="database-password",
        name="Database Password",
        description="Mixed-class database password shape.",
        category="password",
        segments=(Variable("password", PASSWORD, 20),),
        safety_note=_note("Random strong-password shape."),
        scannable=False,
        extra_predicate=_password_predicate,
    ),
    HoneytokenFormat(
        slug="jwt",
        name="JWT-shaped Token",
        description="Three base64url segments joined by dots.",
        category="jwt",
        segments=(
            Variable("header", BASE64URL, 20),
            Literal("."),
            Variable("payload", BASE64URL, 40),
            Literal("."),
            Variable("signature", BASE64URL, 43),
        ),
        safety_note=_note("JWT-shaped only; signature segment is random and not verifiable."),
    ),
    HoneytokenFormat(
        slug="ssh-private-key",
        name="SSH Private Key Marker",
        description="OpenSSH private-key marker shape.",
        category="private-key",
        segments=(
            Literal("-----BEGIN OPENSSH PRIVATE KEY----- "),
            Variable("body", BASE64URL, 64),
            Literal(" -----END OPENSSH PRIVATE KEY-----"),
        ),
        safety_note=_note("Private-key-shaped marker only; body is not usable key material."),
    ),
    HoneytokenFormat(
        slug="stripe-sk-live",
        name="Stripe sk_live_ Secret Key",
        description="Stripe live-mode secret key shape.",
        category="api-key",
        segments=(Literal("sk_live_"), Variable("body", ALNUM, 24)),
        safety_note=_note("'sk_live_'-prefixed Stripe-key shape."),
    ),
    HoneytokenFormat(
        slug="github-ghp",
        name="GitHub Personal Access Token",
        description="GitHub classic PAT shape with checksum-valid body.",
        category="vcs-token",
        segments=(
            Literal("ghp_"),
            Variable("body", ALNUM, 30),
            Checksum("crc", 6, "github-crc32-base62"),
        ),
        safety_note=_note("'ghp_' GitHub-token shape with valid checksum."),
    ),
    HoneytokenFormat(
        slug="slack-bot-token",
        name="Slack Bot Token",
        description="Slack xoxb bot token shape.",
        category="token",
        segments=(
            Literal("xoxb-"),
            Variable("a", DIGITS, 12),
            Literal("-"),
            Variable("b", DIGITS, 12),
            Literal("-"),
            Variable("c", ALNUM, 24),
        ),
        safety_note=_note("'xoxb-' Slack-bot-token shape."),
    ),
    HoneytokenFormat(
        slug="slack-user-token",
        name="Slack User Token",
        description="Slack xoxp user token shape.",
        category="token",
        segments=(
            Literal("xoxp-"),
            Variable("a", DIGITS, 12),
            Literal("-"),
            Variable("b", DIGITS, 12),
            Literal("-"),
            Variable("c", ALNUM, 24),
        ),
        safety_note=_note("'xoxp-' Slack-user-token shape."),
    ),
    HoneytokenFormat(
        slug="slack-webhook-url",
        name="Slack Webhook URL",
        description="Slack incoming webhook URL shape.",
        category="webhook",
        segments=(
            Literal("https://hooks.slack.com/services/T"),
            Variable("t", UPPER_DIGITS, 10),
            Literal("/B"),
            Variable("b", UPPER_DIGITS, 10),
            Literal("/"),
            Variable("s", ALNUM, 24),
        ),
        safety_note=_note("Slack-webhook-URL shape."),
    ),
    HoneytokenFormat(
        slug="google-api-key",
        name="Google API Key",
        description="Google AIza API key shape.",
        category="api-key",
        segments=(Literal("AIza"), Variable("body", BASE64URL, 35)),
        safety_note=_note("'AIza' Google-API-key shape."),
    ),
    HoneytokenFormat(
        slug="openai-project-key",
        name="OpenAI Project Key",
        description="OpenAI sk-proj key shape.",
        category="api-key",
        segments=(Literal("sk-proj-"), Variable("body", BASE64URL, 48)),
        safety_note=_note("'sk-proj-' OpenAI-key shape."),
    ),
    HoneytokenFormat(
        slug="anthropic-api-key",
        name="Anthropic API Key",
        description="Anthropic sk-ant-api03 key shape.",
        category="api-key",
        segments=(Literal("sk-ant-api03-"), Variable("body", BASE64URL, 93), Literal("AA")),
        safety_note=_note("'sk-ant-api03-' Anthropic-key shape."),
    ),
    HoneytokenFormat(
        slug="sendgrid-key",
        name="SendGrid API Key",
        description="SendGrid SG key shape.",
        category="api-key",
        segments=(
            Literal("SG."),
            Variable("a", BASE64URL, 22),
            Literal("."),
            Variable("b", BASE64URL, 43),
        ),
        safety_note=_note("'SG.' SendGrid-key shape."),
    ),
    HoneytokenFormat(
        slug="twilio-account-sid",
        name="Twilio Account SID",
        description="Twilio AC account SID shape.",
        category="cloud-key",
        segments=(Literal("AC"), Variable("body", HEX, 32)),
        safety_note=_note("'AC' Twilio-Account-SID shape."),
    ),
    HoneytokenFormat(
        slug="twilio-api-key-sid",
        name="Twilio API Key SID",
        description="Twilio SK API key SID shape.",
        category="cloud-key",
        segments=(Literal("SK"), Variable("body", HEX, 32)),
        safety_note=_note("'SK' Twilio-API-key-SID shape."),
    ),
    HoneytokenFormat(
        slug="github-oauth",
        name="GitHub OAuth Token",
        description="GitHub gho OAuth token shape with checksum-valid body.",
        category="vcs-token",
        segments=(
            Literal("gho_"),
            Variable("body", ALNUM, 30),
            Checksum("crc", 6, "github-crc32-base62"),
        ),
        safety_note=_note("'gho_' GitHub-OAuth-token shape with valid checksum."),
    ),
    HoneytokenFormat(
        slug="github-user-to-server",
        name="GitHub User-to-Server Token",
        description="GitHub ghu app user-to-server token shape.",
        category="vcs-token",
        segments=(
            Literal("ghu_"),
            Variable("body", ALNUM, 30),
            Checksum("crc", 6, "github-crc32-base62"),
        ),
        safety_note=_note("'ghu_' GitHub-token shape with valid checksum."),
    ),
    HoneytokenFormat(
        slug="github-server-to-server",
        name="GitHub Server-to-Server Token",
        description="Legacy GitHub ghs installation token shape.",
        category="vcs-token",
        segments=(
            Literal("ghs_"),
            Variable("body", ALNUM, 30),
            Checksum("crc", 6, "github-crc32-base62"),
        ),
        safety_note=_note("'ghs_' legacy GitHub-installation-token shape with valid checksum."),
    ),
    HoneytokenFormat(
        slug="github-refresh",
        name="GitHub Refresh Token",
        description="GitHub ghr refresh token shape.",
        category="vcs-token",
        segments=(
            Literal("ghr_"),
            Variable("body", ALNUM, 30),
            Checksum("crc", 6, "github-crc32-base62"),
        ),
        safety_note=_note("'ghr_' GitHub-token shape with valid checksum."),
    ),
    HoneytokenFormat(
        slug="github-fine-grained",
        name="GitHub Fine-grained PAT",
        description="GitHub github_pat fine-grained PAT shape.",
        category="vcs-token",
        segments=(
            Literal("github_pat_"),
            Variable("a", ALNUM, 22),
            Literal("_"),
            Variable("b", ALNUM, 59),
        ),
        safety_note=_note("'github_pat_' fine-grained-PAT shape; no checksum-valid claim."),
    ),
)

_FORMATS = {spec.slug: spec for spec in _SPECS}
