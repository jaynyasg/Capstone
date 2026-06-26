---
date: 2026-06-25
topic: aegis-production-platform-vnext
---

# Aegis Production Platform vNext Requirements

> **Status note (2026-06-26):** this is the historical requirements brainstorm that fed
> the completed platform vNext work. The accepted evidence store, durable canary,
> versioned API, dashboard, export, and documentation items have since shipped. Current
> behavior and limitations are documented in `README.md` and `architecture.md`; Observe +
> Learn online ML was added afterward as an observe-mode demo feature.

## Summary

Aegis vNext turns the current capstone-grade gateway and cockpit into a production-shaped
security platform layer. The SDK guard path remains the source of truth; vNext hardens the
evidence, canary, API, operator, and claim-boundary surfaces around that guard path.

---

## Problem Frame

Aegis already blocks and traces credential-exfiltration paths through SDK guards, the
FastAPI gateway, eval artifacts, CIFT calibration records, and a dashboard cockpit. That
is enough for a strong capstone demo, but it is not enough for a production-platform
claim. The current platform view is mostly a live aggregation of local artifacts, canary
detection is process-local, evidence degradation can look like empty evidence, and the
dashboard is more status board than operator workflow.

The vNext requirements close that gap without changing the core product thesis. The
platform should make the existing defense path durable, inspectable, and trustworthy for
security-oriented users while preserving the README and PRD's claim discipline: demo-grade
defense today, production-shaped platform work only where explicitly delivered.

---

## Actors

- A1. Security engineer: investigates blocked or suspicious agent behavior, checks evidence
  health, exports audit material, and decides whether a platform view can be trusted.
- A2. Agent developer: integrates Aegis through the SDK or gateway, debugs decisions, and
  needs stable API contracts for local or hosted workflows.
- A3. Capstone evaluator: verifies the live demo, eval evidence, limitations, and replayable
  proof without needing hidden context.
- A4. Aegis runtime: ingests guard events, canary lifecycle records, CIFT records, eval
  metrics, and dashboard/API requests.

---

## Key Decisions

- **Full vNext pass, not a narrow cleanup.** The accepted direction is the complete
  platform slice: evidence store, durable canaries, versioned API, operator workflow,
  health, docs, tests, and deployment boundaries.
- **SDK guard path stays authoritative.** vNext must not fork security decisions into the
  platform layer. The platform stores, summarizes, and explains evidence produced by the
  SDK and gateway.
- **EvidenceStore becomes the platform boundary.** Dashboard and API consumers should read
  through one evidence service instead of each layer scanning local artifacts independently.
- **Canaries are durable but still protected.** Restart-safe detection requires persisted
  canary material, but raw canaries must not become casual plaintext audit data.
- **Recovery degrades visibly.** If keys or local evidence state are missing, corrupt, or
  incompatible, Aegis should keep readable safe evidence available while clearly marking
  affected canary matching, exports, and summaries as degraded.
- **Operator workflow outranks dashboard polish.** The UI goal is investigation and trust:
  drilldowns, stale-state warnings, filters, exports, and recovery cues before decorative
  redesign.
- **Security engineer is the primary operator persona.** Dashboard and API behavior should
  optimize first for investigation, evidence health, exports, and trust. Capstone evaluators
  remain a secondary reader for demo proof and claim clarity.
- **Identity risk remains accepted for this slice.** Basic Auth can remain the access
  boundary, but the product must state what sensitive evidence is exposed behind it and
  avoid overclaiming enterprise readiness.

---

## Requirements

**Evidence Backbone**

- R1. Aegis must expose a single platform evidence boundary that serves dashboard,
  API, export, and report consumers.
- R2. The evidence boundary must preserve compatibility with existing local JSONL traces,
  eval metrics, CIFT JSONL records, and safe canary metadata.
- R3. Evidence reads must be bounded by default and must reject or clamp unsafe query
  windows such as negative, zero, or unreasonably large limits.
- R4. Platform summaries must distinguish total matching records from the latest visible
  window.
- R5. Platform summaries must include evidence freshness and health state so missing,
  corrupt, stale, or partially imported evidence does not look like "nothing happened."
- R6. The platform must support a cached overview or equivalent snapshot behavior with
  explicit freshness semantics.

**Canary Durability**

- R7. Planted canaries must survive process restart for detection purposes.
- R8. Persisted canary state must avoid casual plaintext exposure of raw canary values.
- R9. Canary metadata shown in APIs, dashboard, exports, and traces must remain safe to
  display without leaking raw token material.
- R10. Canary lifecycle state must distinguish at least planted, detected, expired, and
  invalid or unreadable records.
- R11. If canary persistence cannot be read because of a missing key, corrupt store, or
  incompatible format, the platform must surface that degraded state to operators.

**Versioned Platform API**

- R12. Platform API responses must include a schema version and enough query metadata for
  clients to understand what slice of evidence they are seeing.
- R13. Platform drilldowns must support decisions, sessions, detectors, canaries, CIFT
  records, and evidence health without requiring callers to parse raw JSONL files.
- R14. API responses must keep redaction guarantees consistent with trace and dashboard
  output.
- R15. API and dashboard consumers must have stable count semantics: totals mean all
  matching records, latest means the returned window.
- R16. Exportable audit bundles must be available in machine-readable and human-readable
  forms while preserving redaction.

**Operator Console**

- R17. The dashboard must help A1 answer what happened, what changed, what evidence is
  degraded, and what can be exported.
- R18. The dashboard must show health and stale-state warnings near the evidence they
  affect.
- R19. The dashboard must provide filters or drilldowns by session, action, phase, detector,
  model or certificate, and time window where those dimensions exist.
- R20. The dashboard must avoid duplicating evidence parsing logic that already belongs to
  the platform evidence boundary.
- R21. Empty states must distinguish "no records exist" from "records may be missing or
  unreadable."

**Testing and Verification**

- R22. Store contract tests must cover counts, latest windows, health warnings, import
  behavior, empty state, and corrupted input.
- R23. Canary tests must prove detection after restart for exact and smeared appearances in
  model output and tool-call arguments.
- R24. Gateway/API tests must cover version metadata, bounded query behavior, truthful
  totals, redaction, degraded evidence, and export behavior.
- R25. Dashboard tests must verify operator-visible health, stale-state, filters or
  drilldowns, and consumption of the platform boundary.
- R26. The offline verify gate must remain deterministic and must not require live model,
  Braintrust, hosted database, or external secret-manager access.

**Claim Discipline and Documentation**

- R27. README and architecture docs must separate the shipped capstone MVP from production
  vNext capabilities.
- R28. Deployment docs must explain Basic Auth as demo-grade access control and identify
  any sensitive evidence exposed behind it.
- R29. Deployment docs must describe local state backup, restore, and key-loss behavior for
  platform evidence and durable canaries.
- R30. Docs must preserve the non-goal that vNext does not create a full enterprise SaaS
  with billing, tenant management, compliance workflows, or full SSO.

---

## Key Flows

- F1. Guarded event to trusted overview
  - **Actors:** A1, A4
  - **Steps:** A guard call records a redacted event; the evidence boundary ingests or
    imports it; the cached overview updates; the API and dashboard show the same counts,
    health, and latest window.
  - **Outcome:** A1 sees current security evidence without relying on raw artifact parsing.

- F2. Durable canary lifecycle
  - **Actors:** A1, A4
  - **Steps:** A canary is planted; safe metadata is visible; protected persisted state is
    written; the process restarts; the registry restores; a later leak is detected and linked
    to the planted canary.
  - **Outcome:** Aegis can still catch planted canaries after restart without exposing raw
    token material to normal evidence views.

- F3. Degraded evidence investigation
  - **Actors:** A1, A3, A4
  - **Steps:** An evidence source is missing, stale, corrupt, or partly unreadable; the
    evidence boundary records a health warning; the API and dashboard display the warning
    near affected summaries and exports.
  - **Outcome:** The user can tell incomplete evidence from genuinely empty evidence.

- F4. Audit export
  - **Actors:** A1, A3
  - **Steps:** A user filters to a session or incident-like set of records; Aegis produces a
    redacted bundle with decisions, detector evidence, canary metadata, CIFT state, eval
    context, and evidence health.
  - **Outcome:** A security reviewer can share or replay evidence without leaking secrets or
    raw canary values.

---

## Acceptance Examples

- AE1. **Covers R3, R12, R15.** Given more platform records than the default visible window,
  when a caller requests the overview, then the response reports total matching records
  separately from the returned latest records and includes schema/query metadata.
- AE2. **Covers R5, R21.** Given one corrupt evidence artifact and one valid artifact, when
  the dashboard renders, then valid evidence remains visible and the corrupt artifact appears
  as a health warning rather than disappearing silently.
- AE3. **Covers R7, R8, R9, R23.** Given a canary planted before restart, when the app
  restarts and the canary later appears in a response or tool-call argument, then Aegis blocks
  the leak, links it to safe canary metadata, and does not expose the raw token in traces,
  dashboard, or export output.
- AE4. **Covers R11, R18, R29.** Given the canary persistence key is missing or invalid, when
  the platform starts, then detection degradation is visible to operators and docs explain the
  recovery or loss behavior.
- AE5. **Covers R16, R24.** Given a blocked session containing detector evidence and canary
  metadata, when a user exports an audit bundle, then the bundle is complete enough to explain
  the block and contains no raw secrets or raw canary tokens.
- AE6. **Covers R20, R25.** Given the dashboard renders platform data, when the evidence
  boundary changes health or count semantics, then dashboard tests fail unless the dashboard
  reflects the shared platform contract.

---

## Success Criteria

- SC1. The offline verification gate passes with the vNext tests added.
- SC2. A planted canary remains detectable after restart in both response and tool-call
  paths.
- SC3. Platform API and dashboard counts remain truthful when total records exceed the
  visible window.
- SC4. Corrupt, stale, missing, or partially imported evidence appears as explicit health
  state.
- SC5. A security reviewer can export a redacted evidence bundle for a blocked session
  without reading raw JSONL files.
- SC6. README, architecture, and deployment docs clearly state what is demo-grade, what is
  production-shaped, and what remains out of scope.

---

## Scope Boundaries

### Deferred for later

- Full enterprise identity, SSO, RBAC, tenancy, and billing.
- Production secret-manager integration and automatic credential rotation.
- Hosted multi-tenant operations and compliance workflows.
- Broader detector or policy rewrites unrelated to the platform evidence boundary.
- External SIEM integrations beyond local exportable bundles.

### Outside this product's identity for vNext

- Replacing the SDK guard path with a separate platform security engine.
- Claiming formal credential-exfiltration prevention guarantees.
- Treating Braintrust, live LLM access, or a hosted database as required for local
  verification.

---

## Dependencies and Assumptions

- D1. Python standard-library storage is acceptable for the local platform boundary unless
  planning finds a concrete reason to add a dependency.
- D2. Operators can tolerate Basic Auth for the capstone/public demo access boundary if docs
  plainly mark it demo-grade.
- D3. Existing trace, eval, CIFT, and canary artifacts remain useful as migration/import
  inputs.
- D4. The platform should be usable offline with deterministic tests and without live
  OpenAI, Braintrust, or hosted database credentials.
- D5. Persisted canary state requires a key-management story even if full production secret
  management remains out of scope.

---

## Outstanding Questions

### Deferred to Planning

- OQ1. Which local storage shape best satisfies the evidence boundary while keeping the
  dependency footprint reasonable?
- OQ2. Which export formats are required for vNext: JSON only, Markdown only, or both?
- OQ3. What cache freshness threshold should mark the overview stale in local and deployed
  modes?

---

## Sources and Research

- `docs/designs/aegis-production-platform-vnext.md` — accepted CEO and engineering review
  direction.
- `CLAUDE.md` — repo build contract, test gate, non-goals, and SDK-source-of-truth rule.
- `README.md` — current claim discipline, gateway endpoints, deploy notes, and limitations.
- `PRD.md` — original product vision, non-goals, functional requirements, and limitation
  language.
- `AEGIS_TECHNICAL_PLAN.md` — original platform/gateway architecture and out-of-scope
  enterprise features.
- `architecture.md` — current untracked architecture narrative that should be reconciled if
  promoted into tracked docs.
