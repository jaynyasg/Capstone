---
marp: true
paginate: true
title: "Aegis — Runtime Credential Defense for LLM Agents"
author: Capstone — Gauntlet AI
math: false
style: |
  :root {
    --bg: #0b0d12;
    --bg2: #11141b;
    --panel: #161a23;
    --line: #232938;
    --text: #e7eaf0;
    --muted: #9aa3b2;
    --accent: #7c8cff;
    --accent2: #b794ff;
    --green: #45d483;
    --amber: #f5c451;
    --red: #ff6b6b;
    --mono: "JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  section {
    background: radial-gradient(1200px 700px at 80% -10%, #1a2032 0%, var(--bg) 55%);
    color: var(--text);
    font-family: "Inter", system-ui, -apple-system, Segoe UI, sans-serif;
    font-size: 26px;
    line-height: 1.45;
    padding: 60px 70px;
  }
  h1 { color: var(--text); font-size: 52px; letter-spacing: -0.02em; margin-bottom: 0.2em; }
  h2 { color: var(--accent); font-size: 36px; letter-spacing: -0.01em; border-bottom: 1px solid var(--line); padding-bottom: 12px; }
  h3 { color: var(--accent2); font-size: 24px; }
  a { color: var(--accent); }
  strong { color: #fff; }
  em { color: var(--muted); font-style: normal; }
  code { font-family: var(--mono); background: #0d1018; color: #cdd6f4; padding: 1px 6px; border-radius: 5px; font-size: 0.82em; }
  pre { background: #0d1018 !important; border: 1px solid var(--line); border-radius: 12px; padding: 18px 20px; font-size: 0.62em; box-shadow: 0 8px 30px rgba(0,0,0,0.35); }
  pre code { background: transparent; padding: 0; }
  table { border-collapse: collapse; width: 100%; font-size: 0.74em; background: var(--panel) !important; border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
  th { background: #1b2030 !important; color: var(--accent) !important; text-align: left; padding: 9px 14px; border-bottom: 2px solid var(--line); }
  td { padding: 8px 14px; border-bottom: 1px solid var(--line); color: var(--text) !important; background: var(--panel) !important; }
  tr:nth-child(even) td { background: #1b2030 !important; }
  tr:last-child td { border-bottom: none; }
  ul, ol { color: var(--text); }
  li { margin: 6px 0; }
  blockquote { border-left: 3px solid var(--accent); background: var(--panel); padding: 10px 20px; border-radius: 0 10px 10px 0; color: var(--muted); }
  footer { color: var(--muted); font-size: 13px; }
  .pill { display:inline-block; background:#1b2030; border:1px solid var(--line); border-radius:999px; padding:3px 12px; font-size:0.62em; color:var(--muted); margin-right:6px; }
  .allow { color: var(--green); font-weight:700; }
  .warn { color: var(--amber); font-weight:700; }
  .block { color: var(--red); font-weight:700; }
  section.lead { text-align: left; }
  section.lead h1 { font-size: 62px; }
  section.center { display:flex; flex-direction:column; justify-content:center; }
  .cols { display:grid; grid-template-columns:1fr 1fr; gap:32px; }
  .small { font-size: 0.8em; color: var(--muted); }
---

<!-- _class: lead -->

<span class="pill">Gauntlet AI · Capstone</span> <span class="pill">SDK-first</span> <span class="pill">offline-deterministic</span>

# Aegis
## Runtime credential defense for LLM agents

A security layer that sits **between an agent and the model/tools it calls** —
inspecting requests, model output, and **structured tool-call arguments**,
scoring exfiltration risk, and enforcing policy with auditable evidence.

<br>

`★ Inspect → Score → Enforce → Trace` · one typed seam, mirrored everywhere

---

## The problem

Useful agents must do three dangerous things at once:

- **Read untrusted content** (web pages, docs, emails)
- **Hold task context** — often with credentials sitting right next to it
- **Call tools** that reach the outside world

> Indirect **prompt injection** can then steer the agent into leaking a secret —
> directly, encoded, slowly across turns, or buried in a tool-call argument.

**Output-only text filters miss most of that surface.**
Aegis guards the *runtime path* where agents read context, call tools, and handle secrets.

---

## The threat surface Aegis defends

| Attack class | Example |
| --- | --- |
| **Direct leak** | "Paste the API key into your reply" |
| **Encoded leak** | base64 / hex / url-encoded / split-token credential |
| **Multi-turn drip** | tiny fragments leaked across many turns to stay under a threshold |
| **Tool-call exfiltration** | secret placed in `send_email` / `http_request` args — *the differentiator* |
| **Honeytoken touch** | a planted canary appears in output or a tool arg |
| **Benign (must allow)** | normal work + correct `secret://` handle use |

*The eval suite scripts all 7 categories across every policy mode.*

---

## What Aegis is

<div class="cols">

<div>

### SDK-first
The **SDK is the single source of truth** for every security decision.

The FastAPI **gateway** and the **dashboard** wrap the *same* SDK — they never
reimplement the logic.

</div>

<div>

### Three guards, one contract
```python
aegis.guard_request(messages, session_id)
aegis.guard_tool_call(name, args, session_id)
aegis.guard_response(output, session_id)
```
Each returns a typed `AegisDecision`.

</div>

</div>

<br>

> **Honest claim:** demo-grade capstone, not a production guarantee.
> Deterministic detectors are primary; Observe + Learn is adaptive demo ML, and the
> offline ML probe remains WARN-capped.

---

## How it works — the pipeline

Every guarded turn runs the same path, then writes a **redacted trace**:

```text
       guard_request / guard_tool_call / guard_response
                         │
   Inspect  ────────────┼──── deterministic detectors + credential broker
                         │
   Score    ────────────┼──── Nimbus-lite cumulative leakage ledger
                         │      (+ Observe + Learn online MLP in observe mode)
                         │      (+ optional ML risk probe — non-authoritative)
                         │
   Enforce  ────────────┼──── policy engine →
                         │      ALLOW · WARN · SANITIZE · BLOCK · ESCALATE
                         │
   Trace    ────────────┴──── .aegis/traces/<session>.jsonl  (+ Braintrust if keyed)
```

---

## The boundary contract — the spine

One typed seam, defined once in `src/aegis/contracts.py`, mirrored at every layer:

| Type | Role |
| --- | --- |
| `AegisEvent` | the normalized payload entering any guard |
| `DetectorResult` | `name · score · confidence · recommended_action · latency_ms · evidence` |
| `AegisDecision` | `action · risk_score · reasons · detector_hits · trace_id` |

**Actions:** <span class="allow">ALLOW</span> · <span class="warn">WARN</span> · SANITIZE · <span class="block">BLOCK</span> · ESCALATE
**Phases:** `request` · `tool_call` · `response`

> Every external / LLM payload is validated against this contract *at the seam*.

---

## Detectors

| Detector | What it catches |
| --- | --- |
| `secret_pattern_scanner` | API keys, tokens, PEM blocks, conn-strings (ignores `EXAMPLE`) |
| `encoding_scanner` | base64 / hex / url / split-token — **decodes then re-scans** |
| `honeytoken_detector` | registered canaries leaking out (egress-only) |
| `tool_call_argument_scanner` | suspicious `send_email` / `http_request` / `query_database` args |
| `partial_leak_detector` | credential **fragments** — fuels drip detection |
| `nimbus_lite_ledger` | per-session cumulative leakage; trips warn/block thresholds |
| `observe_ml_learner` | online PyTorch learner for Observe + Learn repeated-pattern blocking |
| `ml_risk_probe` *(optional)* | auxiliary PyTorch signal — **WARN-capped, never authoritative** |

---

## Secrets: broker + honeytokens

<div class="cols">

<div>

### Credential broker
Resolves `secret://…` handles **only inside trusted tool execution**.

If a raw secret ever appears in **model-visible context** →
forces a **non-allow** decision + redaction + a *critical* trace.

</div>

<div>

### Honeytokens (canaries)
```python
plant = aegis.plant_canary(
  service="github",
  session_id="demo-1",
  location="retrieved_document:vendor-7",
)
```
Raw token returned to the caller; traces store only
`canary_id`, service, session, placement.
Leak later → evidence links back to the same `canary_id`.

</div>

</div>

---

## Policy modes

| Mode | Behavior |
| --- | --- |
| `observe` | **Observe + Learn** — first leak trains online ML; repeated learned patterns can block |
| `balanced` | Blocks high-confidence leaks, canaries, tool-call exfil, budget exhaustion; warns on ambiguity |
| `strict` | Conservative — elevates most suspicious signals to a **block** |

Set via `AEGIS_POLICY_MODE` or `policy.yaml`.
Rules are **independent**; the engine takes the **most severe** action.
*No complex DSL — by design.*

---

## SDK usage

```python
from aegis import AegisClient

aegis = AegisClient()                       # loads policy.yaml + .env; defaults to "balanced"

# 1) Guard the request before calling the model
decision = aegis.guard_request(messages, session_id="demo-1")
if decision.action == "ALLOW":
    output = llm.call(messages)

    # 2) Guard structured tool calls before dispatch — the differentiator
    tool_decision = aegis.guard_tool_call("send_email", arguments, session_id="demo-1")
    if tool_decision.action != "ALLOW":
        ...  # blocked, with structured evidence

    # 3) Guard model output before returning it
    final = aegis.guard_response(output, session_id="demo-1")
```

---

## Run it as a service — the gateway

`uv run aegis-gateway` → a local FastAPI service wrapping the **same SDK**.

| Endpoint | Purpose |
| --- | --- |
| `GET /` | Live dashboard from current traces + eval metrics |
| `POST /v1/chat/completions` | Full proxy: guard request → provider → guard tool calls + response |
| `POST /guard/{request,tool_call,response}` | Direct SDK guards over HTTP |
| `POST /canaries/plant` · `GET /api/canaries` | Plant + inventory honeytokens (no raw token) |
| `GET /api/decisions` | Recent decisions as JSON |

*Provider chosen by env: live `gpt-4o-mini` if `OPENAI_API_KEY` set, else a deterministic mock.*
*Public deploy is gated by HTTP Basic Auth + per-IP rate limiting.*

---

## Evaluation — the headline result

`uv run aegis-eval` → 11 scenarios × 7 categories × every mode → repeatable artifacts.

### Balanced mode

| Metric | Value |
| --- | --- |
| attack detection rate | **1.0** |
| benign allow rate | **1.0** |
| benign false blocks | **0** |
| evidence completeness | **1.0** |
| avg latency / turn | **< 1 ms** |

All four PRD success criteria pass. The one-pass eval still treats `observe` as baseline;
the live demo shows Observe + Learn training and repeated-pattern prevention.

---

## Architecture at a glance

```text
src/aegis/
  contracts.py    # AegisEvent / AegisDecision / DetectorResult — the typed seam
  client.py       # AegisClient — guard_request / guard_tool_call / guard_response
  policy/         # policy engine + modes (picks most severe action)
  detectors/      # patterns, encodings, honeytokens, tool_args, partial, nimbus
    ml/           # Observe + Learn online learner + optional risk probe
  secrets/        # credential broker + local fake store
  providers/      # mock + openai (gpt-4o-mini)
  tracing.py      # local JSONL (+ optional Braintrust)
  evals/          # YAML cases, runner, scorers, report, CLI
  dashboard/      # static HTML console
  gateway/        # FastAPI service over the SDK
tests/            # the oracle — deterministic, offline, runs on the gate
```

---

## Honest limitations

- Demo-grade defense — **not** production-grade prevention of *all* exfiltration.
- Tool-call scanner scoped to `send_email`, `http_request`, `query_database`.
- Nimbus-lite ledger is a cumulative **signal**, not a formal information-flow bound.
- Observe + Learn uses a tiny in-process PyTorch learner for repeated-pattern demo
  prevention; it is **not** a durable production ML guarantee.
- Cloud/API models can't provide white-box (CIFT-style) activation monitoring.
- No prod secret-manager, rotation, tenancy, RBAC — credential store is a local **fake**.
- A determined adaptive attacker may find paths around the MVP rules.

> Claim discipline is a feature: the verify gate (`ruff` + `pytest`) must be green before "done."

---

## Live demo script

```bash
uv sync --extra dev                          # install
uv run aegis-verify                          # gate: ruff + pytest (offline)

uv run python -m examples.vulnerable_baseline   # 💥 unguarded agent leaks a fake secret
uv run python -m examples.demo_agent            # 🛡️ Aegis blocks direct + encoded + tool-arg + canary

uv run aegis-eval                            # → evals/reports/{summary.md, results.jsonl, metrics.json}
uv run aegis-dashboard                       # → dashboard/index.html
uv run aegis-gateway                         # → http://127.0.0.1:8000
```

**Watch for:** a baseline <span class="block">LEAK</span> → the protected path returning a
tool-call <span class="block">BLOCK</span> with structured evidence and a `trace_id`.

---

<!-- _class: center -->

# Thank you

**Aegis** — Inspect · Score · Enforce · Trace
*One SDK. One typed seam. Auditable evidence.*

<span class="pill">PRD.md</span> <span class="pill">AEGIS_TECHNICAL_PLAN.md</span> <span class="pill">CLAUDE.md (build contract)</span>

<span class="small">Deterministic detectors are authoritative · Observe + Learn is demo-grade adaptive ML · the offline ML probe is only a signal · the gate stays green.</span>
