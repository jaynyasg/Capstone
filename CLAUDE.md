# Aegis — Build Contract (for agents)

Runtime credential defense for LLM agents. SDK-first; FastAPI gateway and Streamlit
dashboard wrap the **same** SDK. Source of truth for all security decisions is the SDK.
Full spec: `PRD.md` and `AEGIS_TECHNICAL_PLAN.md`. This file is the *build contract* —
stack, boundaries, and the claim list that defines "done".

## Stack & tooling
- Python ≥3.11, managed by **uv**. `uv sync` to install, `uv run <cmd>` to run.
- pydantic v2 (contracts), FastAPI (gateway), static HTML (dashboard), openai (provider).
- Platform vNext deps: stdlib `sqlite3` (local evidence read model), `cryptography` (canary vault).
- Tests: **pytest**. Lint: **ruff**. Gate: `uv run aegis-verify` (offline, deterministic).
- Layout: `src/aegis/` package, `tests/`, `examples/`, `policy.yaml`.

## Hard boundaries (non-goals — do NOT build)
- No production secret manager / rotation / IAM. Local fake store (env or JSON) only. (The
  canary vault's local `cryptography`/Fernet encryption protects canary tokens at rest — it is
  NOT a secret manager; the key is operator-provided via `AEGIS_CANARY_VAULT_KEY`, never minted.
  The SQLite evidence store is a local, rebuildable read model for redacted guard-decision
  metadata — it holds no raw secrets and replaces no real secret manager or hosted database.)
- No LLM-as-only-detector. Deterministic detectors are authoritative for blocking.
- No PyTorch/CIFT as a hard dependency. ML probe is an optional *signal*, never the owner.
- No CI/CD, no SaaS/tenancy/RBAC/billing. Local-run + Stop-hook gate is the safety net.
- No complex policy DSL. Independent rules; engine picks the most severe action.

## The boundary contract (the spine — `src/aegis/contracts.py`)
One typed seam mirrored everywhere: `AegisEvent` (PRD §4.3), `DetectorResult` (§6.1),
`AegisDecision` (§4.3). Validate every external/LLM payload against it *at the seam*.
Actions: `ALLOW · WARN · SANITIZE · BLOCK · ESCALATE`. Phases: `request · tool_call · response`.

## Verify gate
`uv run aegis-verify` = ruff check + pytest (excluding `@pytest.mark.live`). Must be green
before Stop. Live LLM / Braintrust / deploy oracles run **on demand**, never on the gate.

## Claim list (done-criterion — re-grade against this in the audit)
Each claim → its cheapest re-runnable check. `[ ]` = not yet green.

### Deterministic (unit tests — the dominant oracle, build first)
- [x] C1  Secret pattern scanner flags API keys/tokens/PEM/conn-strings; ignores benign examples. (FR-4/8.1) → tests/test_patterns.py
- [x] C2  Encoding scanner decodes base64/hex/url/split-token before scanning. (8.1) → tests/test_encodings.py
- [x] C3  Honeytoken detector matches exact + normalized canaries in output & tool args; egress-only. (FR-6) → tests/test_honeytokens.py
- [x] C4  Tool-call arg scanner flags suspicious send_email/http_request/query_database args. (FR-5) → tests/test_tool_args.py
- [x] C5  Nimbus-lite ledger accumulates per-session leakage; trips warn/block thresholds. (FR-7) → tests/test_nimbus.py
- [x] C6  Policy engine maps detector evidence → action under observe/balanced/strict. (FR-8) → tests/test_policy.py
- [x] C7  Every detector returns name/score/confidence/recommended_action/latency_ms/evidence. (FR-4) → asserted across detector tests
- [x] C8  Credential broker resolves secret:// handles in trusted path; raw secret in context → redact+critical+non-allow. (FR-9/§6.5) → tests/test_broker.py
- [x] C9  Guard methods return structured AegisDecision; callable without the gateway. (FR-1) → tests/test_guards.py

### Integration / eval (on-demand oracles — not on the Stop gate)
- [x] C10 Vulnerable baseline would leak a fake secret via unguarded tool args (live gpt-4o-mini demo). (8.2) → examples/vulnerable_baseline.py
- [x] C11 Protected path blocks direct + encoded + tool-arg + honeytoken leaks; allows benign handle use. (8.2) → tests/test_guards.py + live demo (tool-call BLOCK)
- [x] C12 Each evaluated turn writes structured JSONL trace (+ Braintrust when keyed). (FR-10) → tracing.py, tests/test_guards.py::test_trace_written_and_redacted
- [x] C13 Eval harness runs benign + 3 attack classes with repeatable summary artifacts. (FR-12) → `uv run aegis-eval`, src/aegis/evals/, tests/test_evals.py

### Human-judgment / scale-path (noted, not gated)
- [x] C14 Static HTML dashboard shows recent decisions/detectors/risk/latency/mode. (FR-11) → `uv run aegis-dashboard`, src/aegis/dashboard/, tests/test_dashboard.py. Ship/Linear dark palette (ref: Week6/Week5 web app).
- [x] C15 Optional PyTorch risk probe as one non-authoritative signal; WARN-capped; degrades gracefully. (FR-14) → src/aegis/detectors/ml/, tests/test_ml_*.py

### Platform vNext (evidence layer — deterministic unit + integration tests, on the gate)
- [x] C16 Versioned platform contract: bounded/clamped query, total-vs-latest windows, health distinguishing healthy-empty from missing/unreadable/corrupt. (R1/R3/R4/R5/R12/R15/R21) → src/aegis/platform/store.py, tests/test_platform_contracts.py + tests/test_platform.py
- [x] C17 SQLite evidence store: idempotent redacted JSONL import, COUNT(*) totals + LIMIT windows, per-source import health; raw JSONL stays source of truth. (R2/R6/R13/R22) → src/aegis/platform/sqlite_store.py + importers.py, tests/test_platform_store.py
- [x] C18 Durable canary vault: Fernet-encrypted tokens at rest, restart-safe exact+smeared detection; key-loss/corrupt rows degrade visibly (safe metadata stays, no raw token leaks). (R7-R11/R23/R29) → src/aegis/platform/canaries.py, tests/test_canary_persistence.py
- [x] C19 Versioned platform API + drilldowns + JSON/Markdown audit exports; redaction preserved; bounded queries. (R12-R16/R24) → src/aegis/gateway/app.py + src/aegis/platform/exports.py, tests/test_platform_api.py
- [x] C20 Snapshot cache with live/cached/stale freshness; cached reads never hide store/key-loss health. (R5/R6) → src/aegis/platform/snapshots.py, tests/test_snapshots.py
- [x] C21 Operator dashboard renders the platform contract (no duplicate parsing); health/freshness/drilldowns/empty-state distinctions. (R17-R21/R25) → src/aegis/dashboard/render.py, tests/test_dashboard.py
- [x] C22 Claim discipline: docs separate shipped MVP from vNext; Basic Auth demo-grade + evidence named; local-state backup/restore + canary key-loss recovery documented; offline gate stays deterministic. (R26-R30/SC1-SC6) → README.md, CLAUDE.md, architecture.md

## Run it (additions)
- Eval: `uv run aegis-eval` → evals/reports/{summary.md,results.jsonl,metrics.json}
- Dashboard: `uv run aegis-dashboard` → dashboard/index.html (open in browser; regenerate to refresh)
- ML probe (optional): `uv sync --extra ml && uv run aegis-train-probe` → models/aegis_risk_probe.pt;
  enable via `AEGIS_ENABLE_ML_PROBE=1` or policy.yaml `ml_probe.enabled: true`. Absent torch/artifact → degraded (deterministic detectors authoritative).
- Platform API: `uv run aegis-gateway` → `GET /api/platform/{overview,decisions,sessions,detectors,canaries,cift,health}` and `/api/platform/export?format={json,md}` (versioned, bounded, redacted). Local state under `.aegis/platform/` (evidence.db, canary_vault.db).
- Durable canaries: set `AEGIS_CANARY_VAULT_KEY` (Fernet key) for restart-safe detection; absent/invalid key → in-memory only, health marks degraded (never silent).

## Run it
- Tests/gate: `uv run aegis-verify`  ·  Live demo: `uv run python -m examples.demo_agent`
- Gateway (FR-2): `uv run aegis-gateway` → http://127.0.0.1:8000 (proxy + /guard/* + dashboard at /). src/aegis/gateway/, tests/test_gateway.py
- Stop hook (bind the gate so it can't rot) — add to `.claude/settings.json` (needs your approval):
  `{"hooks":{"Stop":[{"matcher":"","hooks":[{"type":"command","command":"uv run aegis-verify"}]}]}}`

## Skill routing

When the user's request matches an available skill, invoke it via the Skill tool. When in doubt, invoke the skill.

Key routing rules:
- Product ideas/brainstorming → invoke /office-hours
- Strategy/scope → invoke /plan-ceo-review
- Architecture → invoke /plan-eng-review
- Design system/plan review → invoke /design-consultation or /plan-design-review
- Full review pipeline → invoke /autoplan
- Bugs/errors → invoke /investigate
- QA/testing site behavior → invoke /qa or /qa-only
- Code review/diff check → invoke /review
- Visual polish → invoke /design-review
- Ship/deploy/PR → invoke /ship or /land-and-deploy
- Save progress → invoke /context-save
- Resume context → invoke /context-restore
- Author a backlog-ready spec/issue → invoke /spec
