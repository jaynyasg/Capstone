"""U4 — versioned platform API: drilldowns, bounded queries, redacted audit exports.

Offline: a MockProvider is injected so the gateway needs no network. Every platform read is
store-backed and bounded; exports come in JSON (tooling) and Markdown (human review) from the
same redacted bundle.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aegis import PolicyMode, Settings
from aegis.gateway.app import create_app
from aegis.platform.store import MAX_LIMIT, SCHEMA_VERSION
from aegis.providers.mock import MockProvider
from tests.conftest import FAKE_GITHUB_PAT


@pytest.fixture(autouse=True)
def _no_external(monkeypatch) -> None:
    monkeypatch.setattr("aegis.tracing._try_braintrust", lambda: None)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("AEGIS_AUTH_USER", raising=False)
    monkeypatch.delenv("AEGIS_AUTH_PASSWORD", raising=False)
    monkeypatch.delenv("AEGIS_RATE_LIMIT_PER_MIN", raising=False)


def _client(tmp_path, provider=None) -> TestClient:
    settings = Settings(policy_mode=PolicyMode.BALANCED, traces_dir=tmp_path / "traces")
    return TestClient(create_app(settings=settings, provider=provider or MockProvider(text="ok")))


def _seed_block(c: TestClient) -> dict:
    """Plant a canary and leak it -> one BLOCK decision traced for session s1."""
    plant = c.post("/canaries/plant", json={"session_id": "s1", "service": "github"}).json()
    c.post("/guard/response", json={"session_id": "s1", "output": f"leak {plant['token']}"})
    return plant


def test_overview_response_is_versioned_and_truthful(tmp_path) -> None:
    c = _client(tmp_path)
    _seed_block(c)
    body = c.get("/api/platform/overview").json()

    assert body["schema_version"] == SCHEMA_VERSION
    assert "generated_at" in body["snapshot"]
    assert body["query"]["limit"] == 25
    assert body["decisions"]["total"] >= 1
    assert body["health"]["status"] in {"healthy", "degraded"}


def test_overview_is_globally_consistent_and_ignores_session_filter(tmp_path) -> None:
    c = _client(tmp_path)
    # Two sessions with different actions: a session-scoped total would diverge from the global
    # breakdowns, which is exactly the inconsistency (total != sum(by_action)) this guards.
    c.post("/guard/response", json={"session_id": "s1", "output": "all clear"})  # ALLOW on s1
    plant = c.post("/canaries/plant", json={"session_id": "s2", "service": "github"}).json()
    c.post("/guard/response", json={"session_id": "s2", "output": f"leak {plant['token']}"})  # s2

    body = c.get("/api/platform/overview", params={"session_id": "s1"}).json()
    decisions = body["decisions"]
    # The overview is the global cockpit; filtering is a drilldown concern, so session_id is
    # ignored and the overview stays internally consistent (total == sum of each breakdown).
    assert body["query"]["session_id"] is None
    assert decisions["total"] == sum(decisions["by_action"].values())
    assert decisions["total"] == sum(decisions["by_phase"].values())
    assert decisions["total"] >= 2  # both sessions counted (global, not scoped to s1)


def test_excessive_and_negative_limits_clamp_consistently(tmp_path) -> None:
    c = _client(tmp_path)
    _seed_block(c)

    over = c.get("/api/platform/decisions", params={"limit": 100000}).json()
    assert over["query"]["limit"] == MAX_LIMIT  # excessive -> ceiling

    negative = c.get("/api/platform/decisions", params={"limit": -5}).json()
    assert negative["query"]["limit"] == 25  # negative -> default

    overview = c.get("/api/platform/overview", params={"limit": 100000}).json()
    assert overview["query"]["limit"] == MAX_LIMIT  # same rule on the overview


def test_drilldowns_report_truthful_totals_and_bounded_windows(tmp_path) -> None:
    c = _client(tmp_path)
    for i in range(8):
        c.post("/guard/response", json={"session_id": "s1", "output": f"hello {i}"})

    window = c.get("/api/platform/decisions", params={"limit": 3}).json()
    assert window["kind"] == "decisions"
    assert window["total"] >= 8  # all matching
    assert len(window["latest"]) == 3  # bounded window

    for kind in ("sessions", "detectors", "canaries", "cift"):
        envelope = c.get(f"/api/platform/{kind}").json()
        assert envelope["schema_version"] == SCHEMA_VERSION
        assert envelope["kind"] == kind
        assert "total" in envelope


def test_drilldown_survives_transient_import_lock(tmp_path, monkeypatch) -> None:
    import sqlite3

    c = _client(tmp_path)
    _seed_block(c)
    first = c.get("/api/platform/decisions")  # imports the trace into the store
    assert first.status_code == 200 and first.json()["total"] >= 1

    # A transient SQLite lock on the next import must not 500 the read: the store already holds
    # the previously imported rows, so the drilldown serves those (raw JSONL stays the source).
    def _locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr("aegis.gateway.app.sync_store", _locked)
    resp = c.get("/api/platform/decisions")
    assert resp.status_code == 200  # served prior rows, not a 500
    assert resp.json()["total"] >= 1


def test_export_json_and_markdown_share_scope_and_redact(tmp_path) -> None:
    c = _client(tmp_path)
    plant = _seed_block(c)

    js = c.get("/api/platform/export", params={"format": "json", "session_id": "s1"})
    md = c.get("/api/platform/export", params={"format": "md", "session_id": "s1"})
    assert js.status_code == 200 and md.status_code == 200
    assert "text/markdown" in md.headers["content-type"]

    bundle = js.json()
    assert bundle["schema_version"] == SCHEMA_VERSION
    assert bundle["query"]["session_id"] == "s1"
    assert bundle["decisions"]["total"] >= 1

    assert "Aegis audit bundle" in md.text
    assert "session_id=s1" in md.text  # same redacted scope as the JSON bundle
    assert plant["token"] not in js.text
    assert plant["token"] not in md.text


def test_export_unknown_format_is_rejected_not_silently_json(tmp_path) -> None:
    c = _client(tmp_path)
    _seed_block(c)

    bad = c.get("/api/platform/export", params={"format": "csv"})
    assert bad.status_code == 400  # unknown format rejected, never a silent JSON default

    # The supported formats still succeed (json is also the no-param default).
    assert c.get("/api/platform/export", params={"format": "json"}).status_code == 200
    assert c.get("/api/platform/export", params={"format": "md"}).status_code == 200
    assert c.get("/api/platform/export").status_code == 200


def test_api_and_export_preserve_secret_redaction(tmp_path) -> None:
    c = _client(tmp_path)
    c.post("/guard/response", json={"session_id": "s1", "output": f"the key is {FAKE_GITHUB_PAT}"})

    decisions = c.get("/api/platform/decisions", params={"session_id": "s1"})
    export_json = c.get("/api/platform/export", params={"format": "json", "session_id": "s1"})
    export_md = c.get("/api/platform/export", params={"format": "md", "session_id": "s1"})
    assert FAKE_GITHUB_PAT not in decisions.text
    assert FAKE_GITHUB_PAT not in export_json.text
    assert FAKE_GITHUB_PAT not in export_md.text  # markdown export must redact too


def test_corrupt_source_surfaces_in_health_and_export(tmp_path) -> None:
    c = _client(tmp_path)
    c.post("/guard/response", json={"session_id": "s1", "output": "hello"})
    (tmp_path / "traces" / "bad.jsonl").write_text("{not json}\n", encoding="utf-8")

    health = c.get("/api/platform/health").json()
    assert health["schema_version"] == SCHEMA_VERSION
    assert health["status"] == "degraded"
    kinds = {(w["source_kind"], w["warning_type"]) for w in health["warnings"]}
    assert ("traces", "corrupt_row") in kinds

    markdown = c.get("/api/platform/export", params={"format": "md"}).text
    assert "degraded" in markdown.lower()


def test_overview_snapshot_is_cached_within_window(tmp_path) -> None:
    c = _client(tmp_path)
    _seed_block(c)

    first = c.get("/api/platform/overview").json()
    second = c.get("/api/platform/overview").json()
    # Two rapid default requests reuse one snapshot (< 5s refresh window): the first builds
    # it (live), the second is served from cache. Asserting == "cached" (not a permissive set)
    # makes the test fail if caching regresses to rebuilding every request.
    assert first["snapshot"]["generated_at"] == second["snapshot"]["generated_at"]
    assert first["snapshot"]["freshness"] == "live"
    assert second["snapshot"]["freshness"] == "cached"

    # The overview takes no filter params: a stray session_id is ignored, so the request is
    # still served from the same cached global snapshot (filtering is a drilldown concern).
    ignored_filter = c.get("/api/platform/overview", params={"session_id": "s1"}).json()
    assert ignored_filter["snapshot"]["freshness"] == "cached"
    assert ignored_filter["snapshot"]["generated_at"] == first["snapshot"]["generated_at"]
