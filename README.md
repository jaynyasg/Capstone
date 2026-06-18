# Aegis — Runtime Credential Defense for LLM Agents

Aegis is an SDK-first security layer that sits between an LLM agent and the model/tools it
calls. It inspects requests, model output, and **structured tool-call arguments**, scores
exfiltration risk, and enforces configurable policy with auditable evidence — so credentials
are harder to leak through prompt injection, encoded payloads, low-rate multi-turn drip, or
tool-call arguments.

> **Claim discipline.** This is a demo-grade capstone, not a production guarantee. The
> leakage ledger is a cumulative *signal*, not a formal proof; the tool-call scanner covers a
> scoped set of schemas; the ML probe is an auxiliary signal, never an authority. See
> [Limitations](#limitations).

Gauntlet AI capstone. Full spec in [`PRD.md`](PRD.md) and
[`AEGIS_TECHNICAL_PLAN.md`](AEGIS_TECHNICAL_PLAN.md); build contract in [`CLAUDE.md`](CLAUDE.md).

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
                              │         (+ optional ML risk probe, non-authoritative)
                              │
              Enforce ────────┼──────── policy engine → ALLOW · WARN · SANITIZE · BLOCK · ESCALATE
                              │
              Trace ──────────┴──────── .aegis/traces/<session>.jsonl  (+ Braintrust if keyed)
```

The **SDK is the single source of truth** for security decisions — the eval harness and
dashboard call it, never reimplementing the logic.

## Quickstart

Requires [uv](https://docs.astral.sh/uv/) and Python ≥ 3.11.

```bash
uv sync --extra dev          # install
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
| `GET /api/decisions` | Recent decisions as JSON |

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

## Detectors

| Detector | What it catches |
| --- | --- |
| `secret_pattern_scanner` | API keys, tokens, PEM blocks, connection strings (ignores `EXAMPLE`/placeholder values) |
| `encoding_scanner` | base64 / hex / url / split-token credentials — decodes then re-scans |
| `honeytoken_detector` | registered canaries leaking into output or tool args (egress-only) |
| `tool_call_argument_scanner` | suspicious `send_email` / `http_request` / `query_database` args before dispatch |
| `partial_leak_detector` | credential *fragments* — fuels drip detection without blocking alone |
| `nimbus_lite_ledger` | per-session cumulative leakage; trips warn/block thresholds across turns |
| `ml_risk_probe` *(optional)* | auxiliary PyTorch signal; WARN-capped, never authoritative |

The **credential broker** resolves `secret://…` handles only inside trusted tool execution,
and forces a non-allow decision (with redaction + a critical trace) if a raw secret ever
appears in model-visible context.

## Policy modes

| Mode | Behavior |
| --- | --- |
| `observe` | Never blocks; records evidence and risk for baseline comparison. |
| `balanced` | Blocks high-confidence leaks, canaries, tool-call exfiltration, budget exhaustion; warns on ambiguous cases. |
| `strict` | Conservative — elevates most suspicious signals to a block. |

Set via `AEGIS_POLICY_MODE` or `policy.yaml`. Rules are independent; the engine takes the
most severe action.

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
injection blocked, honeytoken blocked. `observe` mode deliberately detects 0 (the baseline);
`strict` blocks drip one turn earlier.

## Optional ML risk probe

A small PyTorch MLP scores normalized events as one extra signal. It is **never
authoritative**: it caps its recommendation at WARN and degrades to a no-op (recorded in the
trace) if torch or the model artifact is absent.

```bash
uv sync --extra ml
uv run aegis-train-probe                 # → models/aegis_risk_probe.pt
AEGIS_ENABLE_ML_PROBE=1 uv run aegis-eval # enable the probe as a signal
```

## Project structure

```
src/aegis/
  contracts.py        # AegisEvent / AegisDecision / DetectorResult — the typed seam
  client.py           # AegisClient — guard_request / guard_tool_call / guard_response
  config.py           # settings: policy mode, thresholds, .env / .env.local loading
  policy/             # policy engine + modes
  detectors/          # patterns, encodings, honeytokens, tool_args, partial, nimbus
    ml/               # optional risk probe (features, model, training)
  secrets/            # credential broker + local fake store
  providers/          # provider abstraction: mock + openai (gpt-4o-mini)
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

The deterministic detectors and policy are unit-testable without any live provider. Live
LLM, Braintrust, and the trained ML probe are exercised on demand, never on the gate.

## Limitations

- Demo-grade defense, **not** production-grade prevention of all credential exfiltration.
- The tool-call scanner is scoped to `send_email`, `http_request`, `query_database`.
- The Nimbus-lite ledger is a cumulative leakage *signal*, not a formal information-flow bound.
- Cloud/API model support cannot provide white-box (CIFT-style) activation monitoring.
- No production secret-manager, rotation, tenancy, RBAC, or persistence — the credential
  store is a local fake (env vars or a JSON file).
- A determined adaptive attacker may find paths around the MVP rules.

## License

Capstone project — see repository for terms.
