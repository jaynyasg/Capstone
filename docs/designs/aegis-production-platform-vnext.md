# Aegis Production Platform vNext

Status: PROMOTED
Source: /plan-ceo-review on 2026-06-25
Mode: Production Platform / Full Expansion

> **Delivery status (2026-06-25):** all six accepted must-fixes are implemented and on the
> offline verify gate — bounded SQLite evidence store + import health, durable encrypted
> canary vault with restart-safe detection, operator console with drilldowns/health/freshness,
> truthful total-vs-latest semantics, structured evidence health, and a vNext docs section
> separating MVP from production claims. The accepted risk stands: identity remains demo-grade
> Basic Auth. See `README.md` (Production platform layer) and `architecture.md`
> (Platform Evidence Layer). Enterprise SSO/RBAC/tenancy/billing remain future work.
>
> **Current status (2026-06-26):** this file is now a historical design/review record, not
> the canonical architecture. The current project explanation lives in `README.md` and
> `architecture.md`. Observe + Learn online ML was added after this vNext pass and is
> documented there plus in `AEGIS_TECHNICAL_PLAN.md`.

## Historical Verdict

Aegis is a strong capstone MVP and a credible seed for a production security
platform. It should not claim production-platform readiness until the platform
layer around evidence durability, operator workflow, and claim discipline is
made explicit.

The SDK guard path is the right source of truth. The vNext work hardened the
platform surfaces around that path rather than rebuilding detection logic.

## Accepted Scope

The CEO review accepted six immediate production-platform must-fixes:

- Evidence API/storage/querying must become bounded and production-shaped.
- Canary registry must become durable across restarts.
- Dashboard must become operator-actionable, not only status-visible.
- CIFT counts must separate total count from latest visible rows.
- Evidence degradation must surface health warnings.
- Docs need a vNext production-platform section separating MVP from production claims.

The review accepted one explicit risk:

- Identity/RBAC/tenancy remains demo-grade Basic Auth for now.

## Target Architecture

```text
SDK guards
  |
  v
Redacted AegisEvent stream
  |
  v
Evidence Store vNext
  |--------------------|
  v                    v
Platform API       Durable canary registry
  |
  v
Operator console
  |
  v
Incidents, exports, stale-state, eval links
```

## What Already Exists

- `AegisClient` owns the guard path for requests, tool calls, and responses.
- The FastAPI gateway calls the same SDK instead of reimplementing security logic.
- Local JSONL traces provide an offline evidence fallback.
- CIFT certificates are persisted to JSONL.
- The platform overview aggregates traces, eval metrics, CIFT records, canary records,
  policy status, ML probe state, and Nimbus session risk.
- The dashboard renders a live cockpit and a static report from those artifacts.
- Existing tests cover redaction, corrupt artifacts, canary-safe metadata, CIFT storage,
  the overview endpoint, and dashboard rendering.

## Original Gaps and Current Resolution

### 1. Evidence Store

**Resolved in the shipped vNext slice.** The platform now uses a bounded SQLite evidence
store, import health, query metadata, truthful total-vs-latest windows, and cached
overview snapshots.

Implemented production shape:

- Bounded `limit` parameters with documented defaults and maximums.
- Separate `total_count` from `latest` records.
- Evidence source adapters for traces, eval metrics, CIFT, canaries, and session risk.
- Health metadata for stale, missing, corrupt, or partially unreadable evidence.

### 2. Durable Canaries

**Resolved in the shipped vNext slice.** Canary records can be persisted in an encrypted
vault, restored after restart with the configured key, and surfaced as degraded when the
key or vault cannot be used.

Implemented production shape:

- Safe-at-rest canary registry with raw-token protection.
- Startup load path into the detector registry.
- Lifecycle fields for planted, detected, expired, and revoked states.
- Tests proving a canary planted before restart is detected after restart.

### 3. Operator Console

**Resolved in the shipped vNext slice.** The dashboard is now an operator cockpit over the
platform contract, with evidence health, freshness, drilldowns, exports, Nimbus risk, and
demo walkthrough/Test Console surfaces.

Implemented production shape:

- Drilldowns for sessions, decisions, detectors, canaries, and CIFT certs.
- Evidence staleness and degraded-state warnings.
- Incident/status states for important findings.
- Export links for JSON/Markdown audit bundles.
- Filters by session, action, phase, detector, model, and time window.

### 4. Truthful Evidence Semantics

**Resolved in the shipped vNext slice.** Platform responses separate all matching records
from the bounded latest window, and drilldowns own filtered slices.

Implemented production shape:

- `total_count` means all matching records.
- `latest` means the bounded visible window.
- API and dashboard tests cover totals greater than the returned window.

### 5. Evidence Health

**Resolved in the shipped vNext slice.** Missing, unreadable, corrupt, partial, stale, and
degraded sources are represented as structured health warnings and rendered near affected
dashboard sections.

Implemented production shape:

- Structured warnings for skipped files, corrupt rows, stale reports, and store errors.
- Dashboard surfaces health warnings near affected sections.
- Tests assert degraded evidence is visible to API consumers.

### 6. Claim Discipline

**Maintained in the shipped docs.** The README, PRD, technical plan, and architecture now
separate the demo-grade capstone from the production-shaped platform layer and from future
enterprise SaaS work.

Implemented production shape:

- README separates "demo-grade MVP" from "production-platform roadmap."
- Architecture docs include `/api/platform/overview`, evidence store, canary registry,
  and operator console.
- Deployment docs state which protections are demo-only and which are production-ready.

## Out Of Scope

- Full enterprise SSO and RBAC are not accepted as immediate work in this review.
- Billing, hosted multi-tenant SaaS operations, and compliance workflows remain future work.
- Rewriting the detector pipeline is not part of vNext unless evidence-store changes expose
  a concrete integration gap.

## Review Status

Historical CEO review status at promotion: ISSUES_OPEN.
Current implementation status: accepted must-fixes delivered and covered by the offline
verify gate.
Accepted risks remaining: 1 — Basic Auth / identity remains demo-grade.
Unresolved review decisions: 0.

Canonical current docs: `README.md` and `architecture.md`.
