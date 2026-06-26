# Aegis — Runtime Credential Defense for LLM Agents

Aegis is an LLM security gateway platform with SDK and proxy deployment modes. It sits
between an LLM agent and the model/tools it calls, inspects requests, model output, and
**structured tool-call arguments**, scores exfiltration risk, and enforces configurable
policy with auditable evidence — so credentials are harder to leak through prompt
injection, encoded payloads, low-rate multi-turn drip, or tool-call arguments.

> **Claim discipline.** This is a demo-grade capstone, not a production guarantee. The
> leakage ledger is a cumulative *signal*, not a formal proof; the tool-call scanner covers a
> scoped set of schemas; the offline ML probe is an auxiliary signal; Observe + Learn can
> block repeated learned patterns but is not a production guarantee. See [Limitations](#limitations).

Gauntlet AI capstone. Full spec in [`PRD.md`](PRD.md), current system architecture in
[`architecture.md`](architecture.md), technical plan in
[`AEGIS_TECHNICAL_PLAN.md`](AEGIS_TECHNICAL_PLAN.md), and build contract in
[`CLAUDE.md`](CLAUDE.md).

---

## Why

Useful agents must read untrusted content, hold task context, and call tools — and
credentials often live right next to attacker-controlled text. Indirect prompt injection can
then steer an agent into revealing a secret directly, encoding it, leaking it slowly across
turns, or placing it into a tool-call argument. Output-only text filters miss most of that
surface. Aegis guards the **runtime path** where agents read context, call tools, and handle
secrets.

## How it works

Every guarded turn runs the same **Inspect → Score → Enforce** pipeline, then writes a
redacted trace:

```
            guard_request / guard_tool_call / guard_response
                              │
              Inspect ────────┼──────── deterministic detectors + credential broker
                              │
              Score ──────────┼──────── Nimbus-lite cumulative leakage ledger
                              │         (+ Observe + Learn online MLP in observe mode)
                              │         (+ optional ML risk probe, non-authoritative)
                              │
              Enforce ────────┼──────── policy engine → ALLOW · WARN · SANITIZE · BLOCK · ESCALATE
                              │
              Trace ──────────┴──────── .aegis/traces/<session>.jsonl  (+ Braintrust if keyed)
```

The **SDK is the single source of truth** for security decisions — the eval harness,
gateway, and dashboard call it, never reimplementing the logic. The platform layer then
aggregates the evidence around that guard path: traces, eval metrics, CIFT certificates,
canary lifecycle records, policy status, ML-probe state, and Nimbus session risk.

## Quickstart

Requires [uv](https://docs.astral.sh/uv/) and Python ≥ 3.11.

```bash
uv sync --extra dev          # install
uv sync --extra dev --extra ml  # optional: enable local PyTorch ML paths
uv run aegis-verify          # gate: ruff + pytest (offline, deterministic)
uv run python -m examples.demo_agent   # baseline-vs-protected demo (live gpt-4o-mini or mock)
uv run aegis-eval            # run the eval suite → evals/reports/
uv run aegis-dashboard       # render dashboard/index.html (open in a browser)
uv run aegis-gateway         # run the local service → http://127.0.0.1:8000
```

Configuration is optional — Aegis runs fully offline with sane defaults. To enable live
features, copy `env.example` to `.env` (or `.env.local`) and set keys:

- `OPENAI_API_KEY` — live `gpt-4o-mini` provider (otherwise a deterministic mock is used)
- `BRAINTRUST_API_KEY` — hosted traces/experiments (otherwise local JSONL only)
- `AEGIS_CANARY_VAULT_KEY` — Fernet key enabling durable (restart-safe) canary detection
  (otherwise durable detection is disabled; see [Operating the platform](#operating-the-platform-local-state-backups-keys))
- `AEGIS_SNAPSHOT_REFRESH_SECONDS` / `AEGIS_SNAPSHOT_STALE_SECONDS` — overview cache windows
  (defaults 5s / 60s)

## SDK usage

```python
from aegis import AegisClient

aegis = AegisClient()  # loads policy.yaml + .env; defaults to "balanced" mode

# 1) Guard the request before calling the model
decision = aegis.guard_request(messages, session_id="demo-1")
if decision.action == "ALLOW":
    output = llm.call(messages)

    # 2) Guard structured tool calls before dispatch (the differentiator)
    tool_decision = aegis.guard_tool_call("send_email", arguments, session_id="demo-1")
    if tool_decision.action != "ALLOW":
        ...  # blocked with structured evidence

    # 3) Guard model output before returning it
    final = aegis.guard_response(output, session_id="demo-1")
```

Every guard returns an `AegisDecision` (`action`, `risk_score`, `reasons`, `detector_hits`,
`trace_id`). The decision contract and `AegisEvent` live in `src/aegis/contracts.py` — the
typed seam every layer mirrors.

To plant and audit a honeytoken before model exposure:

```python
plant = aegis.plant_canary(
    service="github",
    session_id="demo-1",
    location="retrieved_document:vendor-email-7",
    format_slug="github-ghp",  # optional; GitHub is the default shape for this service
)
messages.append({"role": "system", "content": f"Audit marker: {plant.token}"})
```

Honeytokens use the DP-HONEY-style shape generator from `CapstoneHoney`: they can mimic
provider credential families such as GitHub, OpenAI, Slack, Stripe, AWS, and Twilio, while
remaining shape-only synthetic values. The raw token is returned to the caller for
placement, but traces store only safe metadata such as `canary_id`, service, session,
placement location, `format_slug`, `provider_valid=false`, and the format spec hash. If
that token later appears in model output or a tool argument, the detector evidence links
the leak back to the same `canary_id`.

## Run as a service (gateway)

`uv run aegis-gateway` starts a local FastAPI service that wraps the **same** SDK — apps can
route through it instead of embedding `AegisClient`, and every call accumulates real traces
(a live capture path the dashboard then reflects).

| Endpoint | Purpose |
| --- | --- |
| `GET /` | The dashboard, served live from current traces + eval metrics |
| `GET /health` | Liveness + active policy mode, provider, Braintrust/ML-probe status |
| `POST /v1/chat/completions` | Full proxy: guard request → provider → guard tool calls + response |
| `POST /guard/request` · `/guard/tool_call` · `/guard/response` | Direct SDK guards over HTTP, return an `AegisDecision` |
| `POST /canaries/plant` | Create a honeytoken, optionally with `format_slug`, trace its model-visible placement, and return the token to plant |
| `GET /api/canaries` | Safe canary inventory (`canary_id`, service, session, placement, format metadata; no raw token) |
| `POST /cift/calibrate` | Record a model-specific CIFT/gateway calibration certificate |
| `GET /api/cift/certifications` | Recent calibration certificates by hosted model |
| `GET /api/decisions` | Recent decisions as JSON |
| `GET /api/platform/overview` | Versioned platform evidence overview (schema version, query metadata, totals, health, freshness) |
| `GET /api/platform/{decisions,sessions,detectors,canaries,cift}` | Bounded, versioned drilldowns — truthful totals + a latest window |
| `GET /api/platform/health` | Evidence health: missing / unreadable / corrupt / partial / degraded warnings |
| `GET /api/platform/export?format={json,md}` | Redacted audit bundle for a query scope — JSON for tooling, Markdown for review |

Every `/api/platform/*` response carries a `schema_version` and echoes its query window. Read
limits are bounded by default and clamped (negative/zero → default, excessive → ceiling), so a
query string can never trigger an unbounded read. `total` always means all matching records;
`latest` means the returned window.

The provider is chosen by environment: live `gpt-4o-mini` when `OPENAI_API_KEY` is set, else
a deterministic mock. Host/port via `AEGIS_GATEWAY_HOST` / `AEGIS_GATEWAY_PORT`.

```bash
curl -s localhost:8000/health
curl -s -X POST localhost:8000/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"session_id":"demo","messages":[{"role":"user","content":"summarize the doc"}]}'
```

## Deploy (public, password-gated)

The gateway ships a `Dockerfile` and `render.yaml` for a public deploy. It is **gated by HTTP
Basic Auth** — set `AEGIS_AUTH_USER` / `AEGIS_AUTH_PASSWORD` and the whole site requires a
login (one browser prompt); leave them unset and it stays open for local dev. `/health` is
always reachable for platform health checks, and POST endpoints are rate-limited per IP.

> **Basic Auth is demo-grade access control, not an identity system** (no users, roles,
> tenancy, or sessions). It is a single shared password in front of **sensitive evidence**:
> the dashboard, the platform drilldowns, and `/api/platform/export` expose redacted decisions,
> detector evidence, session risk, safe canary metadata, and CIFT records. Redaction keeps raw
> secrets and raw canary tokens out of that evidence, but anyone with the shared login can read
> *what was blocked, when, and for which session*. Treat the deployed URL as a shared-secret
> demo surface, not a multi-user console.

**Render (blueprint):**
1. Push the repo to GitHub.
2. Render dashboard → **New → Blueprint** → select the repo (it reads `render.yaml`).
3. Set the secret env vars (marked `sync: false`, never committed):
   - `OPENAI_API_KEY` — your key; **server-side only**, never sent to the browser.
   - `AEGIS_AUTH_USER`, `AEGIS_AUTH_PASSWORD` — the shared login you hand to graders.
4. Deploy. Visit the URL → browser prompts for the login → dashboard, `/try`, and the API work.

**Two different keys (don't conflate):** `OPENAI_API_KEY` is the *provider* credential (secret,
host-only). The Basic Auth user/password is the *access* credential (what humans enter). Nobody
ever types the OpenAI key into the site.

> **Set a hard spend cap** on your OpenAI account before exposing the live model — Basic Auth
> + rate limiting reduce abuse, but a billing cap is the real backstop.

Any Docker host works (`docker build -t aegis . && docker run -p 8000:8000 -e AEGIS_AUTH_USER=… aegis`).

## Operating the platform (local state, backups, keys)

All platform state is **local** under the `.aegis/` state root (gitignored) — there is no
hosted database or external secret manager. Back up that directory to back up the platform.

| Path | What it holds | Notes |
| --- | --- | --- |
| `.aegis/traces/<session>.jsonl` | Redacted guard events (source of truth) | Replayable; re-importable into the store |
| `.aegis/cift/certifications.jsonl` | CIFT calibration certificates | Append-only JSONL |
| `.aegis/platform/evidence.db` | SQLite bounded read model | Derived/rebuildable from the JSONL above |
| `.aegis/platform/canary_vault.db` | Durable canary vault | Encrypted raw tokens + plaintext safe metadata |

- **Backup / restore.** Copy the whole `.aegis/` directory. The evidence store
  (`evidence.db`) is a rebuildable cache: if you keep the JSONL traces and CIFT records, the
  store re-imports from them idempotently on the next read (delete `evidence.db` to force a
  clean rebuild). The **canary vault is not rebuildable** from JSONL — its encrypted tokens
  only exist in `canary_vault.db`, so back it up alongside the key.
- **Canary vault key.** Durable canary detection requires an operator-provided key in
  `AEGIS_CANARY_VAULT_KEY` (a [Fernet](https://cryptography.io/en/latest/fernet/) key:
  `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`).
  Aegis **never mints a throwaway key** — without a key, durable detection is simply disabled
  and the registry stays in-memory only.
- **Key loss is visible, not silent.** If the key is missing, wrong, or the vault is corrupt,
  Aegis keeps the **safe canary metadata readable** (service, format, lifecycle, plant
  location) and marks restart detection **degraded** in evidence health — it does not pretend
  detection still works. Restore the correct key to recover; canaries planted while no key was
  configured cannot be recovered for matching (plant new ones).
- **Offline audit export.** A reviewer can produce a redacted bundle with no live services:

  ```bash
  curl -s 'localhost:8000/api/platform/export?format=md&session_id=demo-1' > audit.md   # human review
  curl -s 'localhost:8000/api/platform/export?format=json&session_id=demo-1' > audit.json # tooling
  ```

  Both formats describe the same scope and contain no raw secrets or raw canary tokens.

## Detectors

| Detector | What it catches |
| --- | --- |
| `secret_pattern_scanner` | API keys, tokens, PEM blocks, connection strings (ignores `EXAMPLE`/placeholder values) |
| `encoding_scanner` | base64 / hex / url / split-token credentials — decodes then re-scans |
| `honeytoken_detector` | registered canaries leaking into output or tool args (egress-only) |
| `tool_call_argument_scanner` | suspicious `send_email` / `http_request` / `query_database` args before dispatch |
| `partial_leak_detector` | credential *fragments* — fuels drip detection without blocking alone |
| `nimbus_lite_ledger` | per-session cumulative leakage; trips warn/block thresholds across turns |
| `observe_ml_learner` | Observe + Learn online PyTorch learner; trains on observe-mode leak features and can block repeated learned patterns |
| `ml_risk_probe` *(optional)* | auxiliary PyTorch signal; WARN-capped, never authoritative |

The **credential broker** resolves `secret://…` handles only inside trusted tool execution,
and forces a non-allow decision (with redaction + a critical trace) if a raw secret ever
appears in model-visible context.

## Policy modes

| Mode | Behavior |
| --- | --- |
| `observe` | **Observe + Learn**. Records evidence and risk for baseline comparison. First-time leaks pass, then train a tiny online PyTorch learner on numeric features; repeated learned leak patterns are blocked by `observe_ml_learner`. |
| `balanced` | Blocks high-confidence leaks, canaries, tool-call exfiltration, budget exhaustion; warns on ambiguous cases. |
| `strict` | Conservative — elevates most suspicious signals to a block. |

Set via `AEGIS_POLICY_MODE` or `policy.yaml`. Rules are independent; the engine takes the
most severe action. Observe-mode learning is actual runtime ML training when the `ml` extra
is available: it updates a tiny MLP from redacted detector evidence and numeric features.
The online learner does not store raw prompt or secret text; if PyTorch is unavailable, its
trace evidence reports `ml_unavailable` instead of pretending to train.

The deployed dashboard and `/try` Test Console also include an **Observe + Learn / Balanced
/ Strict** selector. It defaults to **Observe + Learn** and sends `policy_mode` on the live
guard request so demos can show first-time observe evidence, online ML training,
repeat-pattern prevention, `balanced` blocking, and `strict` tightening without restarting
the service. The server's configured mode remains the default for normal traffic and for
requests that omit `policy_mode`.

## Evaluation

`uv run aegis-eval` runs 11 scripted scenarios across all 7 PRD categories (benign, encoded,
multi-turn drip, tool-call exfiltration, canary touch, benign-handle, false-positive) through
each policy mode and writes repeatable artifacts to `evals/reports/`
(`summary.md`, `results.jsonl`, `metrics.json`).

Headline result (**balanced** mode):

| Metric | Value |
| --- | --- |
| attack detection rate | 1.0 |
| benign allow rate | 1.0 |
| benign false blocks | 0 |
| evidence completeness | 1.0 |
| avg latency / turn | < 1 ms |

All four PRD success criteria pass: unsafe handled ≥ 0.8, benign allowed ≥ 0.8, tool-call
injection blocked, honeytoken blocked. The one-pass eval suite still treats `observe` as the
baseline comparison mode; repeat-leak prevention is exercised by the live guard and unit
tests. `strict` blocks drip one turn earlier.

## Evidence and learning

Aegis accumulates evidence in two ways. Runtime traces, eval artifacts, detector evidence,
and canary lifecycle records remain the durable audit trail. In **Observe + Learn** mode,
the running gateway also trains a tiny online PyTorch learner from observed leak feature
vectors so repeated learned patterns can be blocked during that process lifetime. Teams can
still promote evidence into new YAML eval cases, dashboard reports, or the offline ML-probe
training run; deterministic detectors and explicit policy rules remain the primary reviewed
enforcement surface.

The platform layer turns that evidence into one read-only contract the gateway API, the
dashboard, and audit exports all consume — see [Production platform layer](#production-platform-layer-vnext).

## Production platform layer (vNext)

The capstone MVP (SDK guards, gateway, eval harness, dashboard) is described above. The
**vNext platform layer** hardens the *evidence surfaces* around that same guard path so a
security engineer can investigate and trust what they see — without changing detection or
making the SDK any less the source of truth.

What is implemented after this work:

- **Bounded evidence read model.** Local JSONL traces, eval metrics, and CIFT records are
  imported (idempotently, with redaction) into a local **SQLite** evidence store
  (`stdlib sqlite3`, no hosted database). Reads use `COUNT(*)` totals and `LIMIT` windows, so
  memory stays flat as evidence grows. Raw JSONL remains the replayable source of truth.
- **Explicit evidence health.** Missing, unreadable, corrupt, or partially-imported sources
  become structured warnings instead of silently degrading to empty — "no evidence" can no
  longer masquerade as "nothing happened."
- **Durable canaries.** Planted honeytokens are persisted to an encrypted local vault
  (`cryptography` Fernet) so detection survives a process restart. Raw tokens are encrypted at
  rest and only ever live in the in-process registry; evidence views show safe metadata only.
- **Versioned platform API + audit exports.** `GET /api/platform/*` drilldowns and JSON/Markdown
  export bundles carry a schema version, bounded query metadata, truthful totals, and preserved
  redaction.
- **Operator console.** The dashboard renders the platform contract directly (one evidence
  source), shows health and live/cached/stale freshness next to the evidence they affect, and
  offers drilldowns that link back into the platform API.
- **Snapshot freshness.** Overview reads are cached for a short window (default 5s refresh, 60s
  stale; configurable) and labelled live / cached / stale so repeated reads stay bounded and a
  cached view never hides a degraded source.

Still **out of scope** (unchanged non-goals): enterprise identity / SSO / RBAC / tenancy /
billing, a production secret manager or credential rotation, a hosted multi-tenant database,
and any formal credential-exfiltration *prevention* guarantee. Basic Auth remains **demo-grade**
access control (see [Deploy](#deploy-public-password-gated)).

## CIFT calibration and certification

CIFT is model-specific. Aegis treats it as a calibration/certification layer around the
model a user hosts, not as a universal detector baked into the gateway. The user can run any
OpenAI-compatible or adapter-backed model behind Aegis, then record what level of claim Aegis
can honestly make for that exact endpoint.

Certification levels:

| Level | Meaning |
| --- | --- |
| `gateway_calibrated` | The Aegis gateway/eval suite passed for this model endpoint, but no activation evidence was available. |
| `activation_ready` | The model exposes activation access, but calibration evidence is not complete enough for a CIFT claim. |
| `cift_certified` | Gateway checks passed and model-specific activation evidence cleared calibration thresholds. |
| `none` | Required calibration evidence failed or is missing. |

CLI example:

```bash
uv run aegis-eval
uv run aegis-cift-calibrate \
  --model-id llama-3.1-local \
  --provider-url http://127.0.0.1:9000/v1
```

Gateway example:

```bash
curl -s -X POST localhost:8000/cift/calibrate \
  -H 'content-type: application/json' \
  -d '{"model_id":"llama-3.1-local","provider_url":"http://127.0.0.1:9000/v1"}'
```

For true CIFT certification, the hosted model must also expose activation evidence:

```bash
uv run aegis-cift-calibrate \
  --model-id llama-3.1-local \
  --provider-url http://127.0.0.1:9000/v1 \
  --supports-activations \
  --activation-endpoint http://127.0.0.1:9000/activations \
  --activation-sample-count 24 \
  --activation-separation-score 0.82
```

Without activation evidence, Aegis can still be useful as a gateway defense, but it will not
label the model CIFT-certified.

## Optional ML risk probe

A small PyTorch MLP scores normalized events as one extra signal. It is **never
authoritative**: it caps its recommendation at WARN and degrades to a no-op (recorded in the
trace) if torch or the model artifact is absent.

This offline-trained probe is separate from **Observe + Learn**. Observe + Learn trains a
runtime MLP inside the running gateway from observed leak feature vectors; the optional probe
is a prebuilt auxiliary score loaded from `models/aegis_risk_probe.pt`.

```bash
uv sync --extra ml
uv run aegis-train-probe                 # → models/aegis_risk_probe.pt
AEGIS_ENABLE_ML_PROBE=1 uv run aegis-eval # enable the probe as a signal
```

The Docker/Render live gateway enables this optional probe by default: the image installs
the `ml` extra, trains the small artifact during build, and starts with
`AEGIS_ENABLE_ML_PROBE=1`. The probe remains WARN-capped and non-authoritative; deterministic
detectors and policy still own blocking.

## Project structure

```
src/aegis/
  contracts.py        # AegisEvent / AegisDecision / DetectorResult — the typed seam
  client.py           # AegisClient — guard_request / guard_tool_call / guard_response
  config.py           # settings: policy mode, thresholds, .env / .env.local loading
  policy/             # policy engine + modes
  detectors/          # patterns, encodings, honeytokens, tool_args, partial, nimbus
    ml/               # shared features, Observe + Learn online learner, optional risk probe
  secrets/            # credential broker + local fake store
  providers/          # provider abstraction: mock + openai (gpt-4o-mini)
  platform/           # vNext evidence layer: contract, SQLite store, importers,
                      #   durable canary vault, audit exports, snapshot cache
  tracing.py          # local JSONL (+ optional Braintrust)
  evals/              # YAML cases, runner, scorers, report, CLI
  dashboard/          # static HTML console generator
  gateway/            # FastAPI service over the SDK (proxy + guard endpoints + dashboard)
examples/             # vulnerable_baseline.py vs demo_agent.py
tests/                # the oracle — deterministic, offline, runs on the gate
policy.yaml           # startup policy
```

## Development

```bash
uv run aegis-verify   # ruff + pytest (excludes live/networked tests) — the gate
uv run pytest         # full test suite
uv run ruff check .   # lint
```

The deterministic detectors and policy are unit-testable without any live provider. The
offline gate runs without live LLM or Braintrust. PyTorch-specific Observe + Learn and probe
tests auto-skip if the `ml` extra is not installed.

### Dashboard visual smoke

The deployed dashboard includes a **Run walkthrough** button that pauses live refresh,
scrolls through each operator section, and shows a step-by-step progress rail plus a
large evidence packet attached to the active section. The dashboard header includes an
**Observe + Learn / Balanced / Strict** selector. Each button click chooses one sample prompt for
the whole 9-step walkthrough, runs that same prompt through every section, and rotates to a
different sample on the next click. Each packet calls out the selected policy mode, active
scenario, prompt/input or operator query, platform data source, and values produced for that
step. Each step also runs the sample prompt through the live guard endpoint with the selected
policy mode and includes a link that opens the same prompt prefilled in the Test Console.
Detector evidence is split into a saved **Eval detector hit distribution** and a per-run
**Live walkthrough detector hits** chart that increments from those live guard responses. At
the end of the run, the bottom **Walkthrough run summary** lists each section in order with
its purpose, data source/query, prompt, action, risk, detectors, and highlighted values.
That last summary is restored after dashboard refreshes and remains visible until the next
walkthrough run starts.
For CI-style evidence, there is also an opt-in Playwright smoke test that opens a rendered
dashboard and captures one screenshot per operator section.

```bash
uv run --extra visual playwright install chromium
AEGIS_VISUAL_ARTIFACTS_DIR=dashboard/visual-smoke \
  uv run --extra visual pytest -m visual tests/test_dashboard_visual.py
```

The normal `aegis-verify` gate excludes `visual` tests so local/browser setup never blocks
the deterministic offline checks.

## Limitations

- Demo-grade defense, **not** production-grade prevention of all credential exfiltration.
- The tool-call scanner is scoped to `send_email`, `http_request`, `query_database`.
- The Nimbus-lite ledger is a cumulative leakage *signal*, not a formal information-flow bound.
- Observe + Learn performs real online PyTorch training, but only from in-process runtime
  feature vectors and only for repeated learned-pattern prevention; it is not durable across
  restart and not a formal adaptive-defense guarantee.
- Cloud/API model support cannot provide white-box (CIFT-style) activation monitoring.
- Platform state is **local**: SQLite evidence store + an encrypted local canary vault under
  `.aegis/`. The vault's `cryptography`/Fernet encryption protects *canary tokens at rest* — it
  is **not** a production secret manager. No credential rotation, hosted/multi-tenant database,
  tenancy, or RBAC; the credential store remains a local fake (env vars or a JSON file).
- Access control on a public deploy is **demo-grade Basic Auth** (a shared password), not an
  identity system — no users, roles, tenancy, SSO, or billing.
- A determined adaptive attacker may find paths around the MVP rules.

## License

Capstone project — see repository for terms.
