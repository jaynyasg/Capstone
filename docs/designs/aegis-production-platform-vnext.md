# Aegis Production Platform vNext

Status: PROMOTED
Source: /plan-ceo-review on 2026-06-25
Mode: Production Platform / Full Expansion

## Verdict

Aegis is a strong capstone MVP and a credible seed for a production security
platform. It should not claim production-platform readiness until the platform
layer around evidence durability, operator workflow, and claim discipline is
made explicit.

The SDK guard path is the right source of truth. The vNext work should harden
the platform surfaces around that path rather than rebuild detection logic.

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

## Production Gaps

### 1. Evidence Store

Current overview reads local artifacts synchronously and can scale with all historical
trace rows. Production vNext needs bounded API inputs, consistent counts, a stable
evidence contract, and either a queryable store or cached snapshots.

Minimum production shape:

- Bounded `limit` parameters with documented defaults and maximums.
- Separate `total_count` from `latest` records.
- Evidence source adapters for traces, eval metrics, CIFT, canaries, and session risk.
- Health metadata for stale, missing, corrupt, or partially unreadable evidence.

### 2. Durable Canaries

Current canary detection depends on an in-memory registry. Plant events are traced, but
the raw token needed for matching is not restored after process restart. Production vNext
needs a durable canary registry or a clearly documented ephemeral-canary boundary.

Minimum production shape:

- Safe-at-rest canary registry with raw-token protection.
- Startup load path into the detector registry.
- Lifecycle fields for planted, detected, expired, and revoked states.
- Tests proving a canary planted before restart is detected after restart.

### 3. Operator Console

The dashboard currently answers "what exists?" Production operators need "what happened,
what changed, who/what is affected, and what do I do next?"

Minimum production shape:

- Drilldowns for sessions, decisions, detectors, canaries, and CIFT certs.
- Evidence staleness and degraded-state warnings.
- Incident/status states for important findings.
- Export links for JSON/Markdown audit bundles.
- Filters by session, action, phase, detector, model, and time window.

### 4. Truthful Evidence Semantics

CIFT totals can currently mean "latest visible rows" on the live gateway path and "all
rows" on the static collector path. Production evidence APIs need stable semantics.

Minimum production shape:

- `total_count` means all matching records.
- `latest` means the bounded visible window.
- API and dashboard tests cover totals greater than the returned window.

### 5. Evidence Health

Current loaders intentionally degrade to empty output for corrupt or unreadable files.
That is acceptable for demo resilience, but production evidence cannot make missing
data look like no events occurred.

Minimum production shape:

- Structured warnings for skipped files, corrupt rows, stale reports, and store errors.
- Dashboard surfaces health warnings near affected sections.
- Tests assert degraded evidence is visible to API consumers.

### 6. Claim Discipline

The existing PRD and technical plan correctly describe the current system as a capstone
MVP, not a production security guarantee. Production vNext docs must preserve that
distinction while naming the work required to cross the line.

Minimum production shape:

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

CEO review status: ISSUES_OPEN.
Accepted must-fixes: 6.
Accepted risks: 1.
Unresolved review decisions: 0.

Recommended next review: /plan-eng-review.
