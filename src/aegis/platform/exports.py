"""Redacted audit export bundles (U4): JSON for tooling, Markdown for human review.

Both formats are built from the *same* bundle dict, so a JSON export and a Markdown export
of the same query describe the identical, already-redacted evidence scope (R16). The store
windows and the overview are redaction-safe by construction; exports never reach back to raw
artifacts, so they cannot reintroduce a secret or a raw canary token.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from aegis.platform.store import SCHEMA_VERSION, EvidenceQuery

if TYPE_CHECKING:
    from aegis.platform.evidence import PlatformOverview
    from aegis.platform.sqlite_store import SqliteEvidenceStore


def collect_audit_bundle(
    *,
    overview: PlatformOverview,
    store: SqliteEvidenceStore,
    query: EvidenceQuery,
) -> dict[str, Any]:
    """Assemble a machine-readable audit bundle for a query scope (already redacted)."""
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": overview.snapshot.generated_at,
        "query": query.model_dump(),
        "status": overview.status.model_dump(),
        "health": overview.health.model_dump(),
        "decisions": store.decisions(query).model_dump(),
        "detectors": store.detectors(query).model_dump(),
        "sessions": store.sessions(query).model_dump(),
        "canaries": store.canaries(query).model_dump(),
        "cift": store.cift(query).model_dump(),
        "evals": overview.evals,
    }


def render_markdown_bundle(bundle: dict[str, Any]) -> str:
    """Render the same bundle as a human-readable Markdown audit report."""
    query = bundle.get("query", {})
    health = bundle.get("health", {})
    scope = _scope_line(query)
    lines: list[str] = [
        "# Aegis audit bundle",
        "",
        f"- Schema version: `{bundle.get('schema_version', '?')}`",
        f"- Generated at: `{bundle.get('generated_at', 0)}`",
        f"- Scope: {scope}",
        f"- Health: **{health.get('status', 'unknown')}**",
        "",
    ]

    warnings = health.get("warnings", [])
    lines.append("## Evidence health")
    if warnings:
        for warning in warnings:
            lines.append(
                f"- `{warning.get('severity', '?')}` "
                f"{warning.get('source_kind', '?')}/{warning.get('warning_type', '?')}: "
                f"{warning.get('detail', '')}".rstrip()
            )
    else:
        lines.append("- No warnings — evidence is healthy.")
    lines.append("")

    decisions = bundle.get("decisions", {})
    lines.append(f"## Decisions (total {decisions.get('total', 0)})")
    rows = decisions.get("latest", [])
    if rows:
        lines.append("| time | session | phase | action | detectors | summary |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for row in rows:
            detectors = ", ".join(row.get("detectors", [])) or "—"
            lines.append(
                f"| {row.get('created_at', '')} | {_cell(row.get('session_id'))} "
                f"| {_cell(row.get('phase'))} | {_cell(row.get('action'))} "
                f"| {_cell(detectors)} | {_cell(row.get('summary'))} |"
            )
    else:
        lines.append("_No decisions in scope._")
    lines.append("")

    lines.extend(_count_section("Sessions", bundle.get("sessions", {}), ("session_id", "events")))
    lines.extend(
        _count_section("Canaries", bundle.get("canaries", {}), ("canary_id", "lifecycle_state"))
    )
    lines.extend(
        _count_section("CIFT certifications", bundle.get("cift", {}), ("model_id", "status"))
    )

    evals = bundle.get("evals", {})
    lines.append("## Eval context")
    if evals:
        for mode, metrics in evals.items():
            criteria = metrics.get("success_criteria", {}) if isinstance(metrics, dict) else {}
            passed = sum(1 for ok in criteria.values() if ok)
            lines.append(f"- `{mode}`: {passed}/{len(criteria)} success criteria passing")
    else:
        lines.append("- No eval metrics available.")
    lines.append("")
    return "\n".join(lines)


def _count_section(title: str, window: dict[str, Any], fields: tuple[str, str]) -> list[str]:
    lines = [f"## {title} (total {window.get('total', 0)})"]
    rows = window.get("latest", [])
    if not rows:
        lines.append(f"_No {title.lower()} in scope._")
    else:
        for row in rows:
            primary = _cell(row.get(fields[0]))
            secondary = _cell(row.get(fields[1]))
            lines.append(f"- `{primary}` — {secondary}")
    lines.append("")
    return lines


def _scope_line(query: dict[str, Any]) -> str:
    parts = [f"limit={query.get('limit')}", f"offset={query.get('offset')}"]
    for key in ("session_id", "action", "phase", "detector", "model_id", "since", "until"):
        value = query.get(key)
        if value is not None:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _cell(value: Any) -> str:
    """Make a value safe to drop into a Markdown table cell (pipes would break columns)."""
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")
