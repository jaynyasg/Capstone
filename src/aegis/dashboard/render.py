"""Operator console renderer — one self-contained HTML view of the platform contract.

The dashboard is an *investigation* surface, not a second evidence parser (R20): every
section is rendered from a single :class:`~aegis.platform.evidence.PlatformOverview` (the
platform contract), whether that overview came from the gateway's SQLite store or from a
static file-backed build. Health and freshness are shown next to the evidence they affect,
empty states distinguish "nothing happened" from "evidence is unreadable", and drilldowns
link back into the versioned platform API rather than re-parsing artifacts.

No server, no JS build: a single file styled to the Ship/Linear dark palette. All
trace/evidence content is HTML-escaped at the seam.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from aegis.config import Settings
from aegis.platform import collect_platform_overview
from aegis.platform.store import FreshnessState

DEFAULT_TRACES_DIR = Path(".aegis/traces")
DEFAULT_REPORTS_DIR = Path("evals/reports")
DEFAULT_OUT = Path("dashboard/index.html")

# Ship/Linear-inspired palette (WCAG-AA on #0d0d0d).
_CSS = """
:root{
  --bg:#0d0d0d; --surface:#1a1a1a; --fg:#f5f5f5; --muted:#8a8a8a;
  --border:#262626; --accent:#005ea2; --accent-hover:#0071bc;
  --allow:#3fb950; --warn:#d29922; --sanitize:#58a6ff; --block:#f85149; --escalate:#db61a2;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font-family:Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  -webkit-font-smoothing:antialiased;line-height:1.5;padding:32px;max-width:1100px;margin:0 auto}
a{color:var(--accent)}
header{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:8px}
h1{font-size:18px;font-weight:600;letter-spacing:-0.01em}
.sub{color:var(--muted);font-size:13px;margin-bottom:28px}
.label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;color:#8a8a8a99;margin:28px 0 12px}
.card{border:1px solid var(--border);background:var(--bg);border-radius:8px;padding:16px}
.card.degraded{border-color:var(--block)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.kpi .v{font-size:24px;font-weight:600;letter-spacing:-0.02em}
.kpi .k{font-size:12px;color:var(--muted);margin-top:2px}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:12px;padding:5px 10px;border-radius:6px;background:var(--surface);text-decoration:none;color:var(--fg)}
a.pill:hover{background:#262626}
.dot{height:7px;width:7px;border-radius:999px;flex:none}
.mode{font-size:12px;color:var(--muted);border:1px solid var(--border);border-radius:6px;padding:3px 10px;margin-left:8px}
.badge{font-size:11px;font-weight:600;border-radius:6px;padding:3px 9px;margin-left:8px}
.hr{height:1px;background:var(--border);margin:28px 0}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--muted);font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:0.06em;
  padding:8px 10px;border-bottom:1px solid var(--border)}
td{padding:10px;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:none}
.leaks{color:var(--block);font-weight:600}
.bar{height:6px;border-radius:999px;background:var(--accent)}
.barrow{display:grid;grid-template-columns:200px 1fr 36px;align-items:center;gap:12px;margin:7px 0;font-size:13px}
.decision{display:flex;gap:12px;align-items:center;padding:11px 0;border-bottom:1px solid var(--border)}
.decision:last-child{border-bottom:none}
.det{font-size:12px;color:var(--muted)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--muted)}
.crit{display:flex;flex-direction:column;gap:8px}
.split{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.kv{display:grid;grid-template-columns:120px 1fr;gap:8px;font-size:13px;margin:5px 0}
.kv span:first-child{color:var(--muted)}
.mini{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
.ok{color:var(--allow)} .bad{color:var(--block)}
.empty{color:var(--muted);font-size:13px}
.warn-row{display:flex;gap:8px;align-items:baseline;font-size:12px;padding:6px 0;border-bottom:1px solid var(--border)}
.warn-row:last-child{border-bottom:none}
.sev{font-size:10px;font-weight:700;text-transform:uppercase;padding:2px 6px;border-radius:4px;flex:none}
.sev.error{color:var(--block);background:#f8514922}
.sev.warning{color:var(--warn);background:#d2992222}
.sev.info{color:var(--muted);background:#8a8a8a22}
"""

_ACTION_COLOR = {
    "ALLOW": "var(--allow)",
    "WARN": "var(--warn)",
    "SANITIZE": "var(--sanitize)",
    "BLOCK": "var(--block)",
    "ESCALATE": "var(--escalate)",
}

_FRESHNESS_COLOR = {
    "live": "var(--allow)",
    "cached": "var(--sanitize)",
    "stale": "var(--warn)",
    "static": "var(--muted)",
}


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    return value.model_dump() if hasattr(value, "model_dump") else dict(value)


def load_recent_decisions(traces_dir: Path | str, limit: int = 25) -> list[dict[str, Any]]:
    directory = Path(traces_dir)
    if not directory.exists():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.jsonl")):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    # Order by event timestamp (true recency), not file/line order. Pre-timestamp
    # traces default to 0.0 and sort last.
    rows.sort(key=lambda r: r.get("created_at", 0.0), reverse=True)
    return rows[:limit]


def load_metrics(reports_dir: Path | str) -> dict[str, Any] | None:
    path = Path(reports_dir) / "metrics.json"
    if not path.exists():
        return None
    try:
        metrics = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return metrics if isinstance(metrics, dict) else None


def _action_pill(action: str) -> str:
    color = _ACTION_COLOR.get(action, "var(--muted)")
    return (
        f'<span class="pill"><span class="dot" style="background:{color}"></span>'
        f'<span style="color:{color};font-weight:600">{_esc(action)}</span></span>'
    )


def _kpis(m: dict[str, Any]) -> str:
    cells = [
        ("attack detection", f"{m.get('attack_detection_rate', 0):.0%}"),
        ("benign allowed", f"{m.get('benign_allow_rate', 0):.0%}"),
        ("false blocks", str(m.get("benign_false_blocks", 0))),
        ("evidence complete", f"{m.get('evidence_completeness', 0):.0%}"),
        ("avg latency", f"{m.get('avg_latency_ms', 0):.2f} ms"),
    ]
    items = "".join(
        f'<div class="card kpi"><div class="v">{_esc(v)}</div><div class="k">{_esc(k)}</div></div>'
        for k, v in cells
    )
    return f'<div class="kpis">{items}</div>'


def _criteria(m: dict[str, Any]) -> str:
    rows = []
    for name, ok in m.get("success_criteria", {}).items():
        mark = '<span class="ok">PASS</span>' if ok else '<span class="bad">FAIL</span>'
        rows.append(f"<div>{mark} &nbsp; {_esc(name)}</div>")
    return f'<div class="card crit">{"".join(rows)}</div>' if rows else _note("No success criteria.")


def _baseline_table(cases: list[dict[str, Any]]) -> str:
    attacks = [c for c in cases if c.get("baseline_leaked") is not None and c.get("worst_action")]
    body = []
    for c in attacks:
        baseline = '<span class="leaks">LEAKS</span>' if c["baseline_leaked"] else "—"
        body.append(
            f"<tr><td class='mono'>{_esc(c['id'])}</td><td>{_esc(c['category'])}</td>"
            f"<td>{baseline}</td><td>{_action_pill(c['worst_action'])}</td></tr>"
        )
    if not body:
        return '<div class="card empty">No eval cases — run <span class="mono">aegis-eval</span>.</div>'
    return (
        "<table><thead><tr><th>Case</th><th>Category</th><th>Baseline</th><th>Aegis</th></tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table>"
    )


def _distribution(m: dict[str, Any]) -> str:
    dist = m.get("detector_hit_distribution", {})
    if not dist:
        return '<div class="empty">No detector hits recorded.</div>'
    top = max(dist.values())
    rows = []
    for name, count in sorted(dist.items(), key=lambda kv: -kv[1]):
        pct = int(100 * count / top) if top else 0
        rows.append(
            f'<div class="barrow"><span class="det">{_esc(name)}</span>'
            f'<span class="bar" style="width:{pct}%"></span><span class="det">{count}</span></div>'
        )
    return "".join(rows)


def _note(text: str) -> str:
    return f'<div class="card empty">{_esc(text)}</div>'


def _freshness_badge(snapshot: dict[str, Any]) -> str:
    state = str(snapshot.get("freshness", "live"))
    color = _FRESHNESS_COLOR.get(state, "var(--muted)")
    age = snapshot.get("cache_age_seconds", 0.0) or 0.0
    label = state if state in ("live", "static") else f"{state} · {age:.0f}s"
    return (
        f'<span class="badge" style="color:{color};border:1px solid {color}55">'
        f"{_esc(label)}</span>"
    )


def _health_panel(health: dict[str, Any]) -> str:
    status = str(health.get("status", "healthy"))
    warnings = health.get("warnings", [])
    if status == "healthy" and not warnings:
        return '<div class="card"><span class="ok">healthy</span> &nbsp;'\
               '<span class="empty">all evidence sources readable and current.</span></div>'
    rows = "".join(
        f'<div class="warn-row"><span class="sev {_esc(w.get("severity", "warning"))}">'
        f'{_esc(w.get("severity", "warning"))}</span>'
        f'<span class="mono">{_esc(w.get("source_kind", "?"))} / '
        f'{_esc(w.get("warning_type", "?"))}</span>'
        f'<span class="det">{_esc(w.get("detail", ""))}</span></div>'
        for w in warnings
    )
    return f'<div class="card degraded"><div class="det">status: {_esc(status)}</div>{rows}</div>'


def _degraded_sources(health: dict[str, Any]) -> set[str]:
    return {str(w.get("source_kind")) for w in health.get("warnings", [])}


def _decisions(decisions: dict[str, Any], health: dict[str, Any]) -> str:
    rows = decisions.get("recent", [])
    if not rows:
        # Distinguish a genuinely empty (healthy) feed from one degraded by unreadable evidence.
        if "traces" in _degraded_sources(health) or health.get("status") == "degraded":
            return (
                '<div class="card empty">No <strong>readable</strong> decisions — trace '
                "evidence may be missing or unreadable (see evidence health above).</div>"
            )
        return (
            '<div class="card empty">No decisions recorded yet — run '
            '<span class="mono">python -m examples.demo_agent</span> or '
            '<span class="mono">aegis-eval</span>.</div>'
        )
    out = []
    for r in rows:
        action = r.get("action", "ALLOW")
        fired = [name for name in r.get("detectors", [])]
        phase = r.get("phase", "?")
        tool = f" · {_esc(r['tool_name'])}" if r.get("tool_name") else ""
        det = f'<span class="det">{_esc(", ".join(dict.fromkeys(fired)))}</span>' if fired else ""
        summary = _esc((r.get("summary") or "")[:90])
        out.append(
            f'<div class="decision">{_action_pill(action)}'
            f'<span class="mono">{_esc(phase)}{tool}</span>'
            f'<span style="flex:1;color:var(--muted);font-size:12px">{summary}</span>{det}</div>'
        )
    label = f'<div class="det">total matching: {_esc(decisions.get("total", len(rows)))} · '\
            f'showing latest {len(rows)}</div>'
    return f'<div class="card">{label}{"".join(out)}</div>'


def _drilldowns(data: dict[str, Any]) -> str:
    """Operator filters as links back into the versioned platform API (never a re-parse)."""
    sessions = data.get("sessions", [])
    decisions = data.get("decisions", {})
    by_action = decisions.get("by_action", {})
    by_phase = decisions.get("by_phase", {})
    detector_hits = decisions.get("detector_hits", {})
    cift = data.get("cift", {})

    def _links(items: list[tuple[str, Any]], param: str, endpoint: str = "decisions") -> str:
        cells = "".join(
            f'<a class="pill" href="/api/platform/{endpoint}?{param}={_esc(key)}">'
            f"{_esc(key)}{'' if value is None else f' · {_esc(value)}'}</a>"
            for key, value in items
        )
        return cells or '<span class="empty">none</span>'

    session_items = [(s.get("session_id"), s.get("latest_action")) for s in sessions[:8]]
    model_items = [
        (row.get("model_id"), row.get("status"))
        for row in cift.get("latest", [])
        if row.get("model_id")
    ]
    return f"""
<div class="split">
  <div class="card"><div class="det">By session</div><div class="mini">{_links(session_items, "session_id")}</div></div>
  <div class="card"><div class="det">By action</div><div class="mini">{_links(list(by_action.items()), "action")}</div></div>
  <div class="card"><div class="det">By phase</div><div class="mini">{_links(list(by_phase.items()), "phase")}</div></div>
  <div class="card"><div class="det">By detector</div><div class="mini">{_links(list(detector_hits.items()), "detector")}</div></div>
  <div class="card"><div class="det">By model / certificate</div><div class="mini">{_links(model_items, "model_id", "cift")}</div></div>
</div>
"""


def _platform(data: dict[str, Any]) -> str:
    status = data.get("status", {})
    canaries = data.get("canaries", {})
    cift = data.get("cift", {})
    sessions = data.get("sessions", [])

    status_rows = "".join(
        f'<div class="kv"><span>{_esc(k)}</span><strong>{_esc(v)}</strong></div>'
        for k, v in {
            "provider": status.get("provider", "unknown"),
            "policy": status.get("policy_mode", "unknown"),
            "ML probe": "on" if status.get("ml_probe") else "off",
            "Braintrust": "on" if status.get("braintrust") else "off",
        }.items()
    )
    canary_rows = (
        "".join(
            f'<span class="pill">{_esc(k)}: {_esc(v)}</span>'
            for k, v in (canaries.get("by_format") or {}).items()
        )
        or '<span class="empty">No canaries</span>'
    )
    cift_latest = (cift.get("latest") or [{}])[0] if cift.get("latest") else {}
    cift_label = (
        f"{cift_latest.get('model_id', 'none')} · {cift_latest.get('level', 'none')}"
        if cift_latest
        else "none"
    )
    session_rows = (
        "".join(
            f'<div class="kv"><span>{_esc(s.get("session_id"))}</span>'
            f"<strong>{_esc(s.get('nimbus_cumulative_score', 0.0))}</strong></div>"
            for s in sessions[:3]
        )
        or '<div class="empty">No session risk yet</div>'
    )
    return f"""
<div class="split">
  <div class="card"><div class="det">Runtime</div>{status_rows}</div>
  <div class="card"><div class="det">Honeytoken formats</div><div class="mini">{canary_rows}</div></div>
  <div class="card"><div class="det">CIFT certificates</div><div class="kv"><span>latest</span><strong>{_esc(cift_label)}</strong></div><div class="kv"><span>total</span><strong>{_esc(cift.get("total", 0))}</strong></div></div>
  <div class="card"><div class="det">Session risk</div>{session_rows}</div>
</div>
"""


def render_html(
    platform: Any | None,
    *,
    cases: list[dict[str, Any]] | None = None,
    headline: str = "balanced",
    nav_html: str = "",
    auto_refresh: int = 0,
) -> str:
    """Render the operator console from a single platform contract (overview)."""
    data = _as_dict(platform)
    snapshot = data.get("snapshot", {})
    health = data.get("health", {})
    decisions = data.get("decisions", {})
    evals = data.get("evals", {})
    cases = cases or []
    m = evals.get(headline) if isinstance(evals, dict) else None

    mode_badge = f'{nav_html}{_freshness_badge(snapshot)}<span class="mode">policy: {_esc(headline)}</span>'
    refresh_meta = f'<meta http-equiv="refresh" content="{auto_refresh}">' if auto_refresh else ""

    if m:
        kpis, criteria, distribution = _kpis(m), _criteria(m), _distribution(m)
    else:
        note = _note("Run aegis-eval to populate metrics.")
        kpis = criteria = distribution = note

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">{refresh_meta}
<title>Aegis — Credential Defense Console</title>
<style>{_CSS}</style></head>
<body>
<header><h1>Aegis</h1><div>{mode_badge}</div></header>
<div class="sub">Operator console — what happened, what changed, what evidence is degraded, what to export.</div>

<div class="label">Evidence health</div>
{_health_panel(health)}

<div class="label">Investigate (drilldowns → platform API)</div>
{_drilldowns(data)}

<div class="label">Platform cockpit</div>
{_platform(data)}

<div class="label">Recent decisions</div>
{_decisions(decisions, health)}

<div class="label">Eval summary ({_esc(headline)})</div>
{kpis}

<div class="label">Success criteria</div>
{criteria}

<div class="label">Baseline vs protected</div>
{_baseline_table(cases)}

<div class="label">Detector hit distribution</div>
<div class="card">{distribution}</div>

<div class="hr"></div>
<div class="empty">Generated by <span class="mono">aegis-dashboard</span> — export an audit bundle at <span class="mono">/api/platform/export?format=md</span>.</div>
</body></html>
"""


def load_cases(reports_dir: Path | str, headline: str = "balanced") -> list[dict[str, Any]]:
    path = Path(reports_dir) / "results.jsonl"
    if not path.exists():
        return []
    cases = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        if row.get("mode") == headline:
            cases.append(row)
    return cases


def generate(
    traces_dir: Path | str = DEFAULT_TRACES_DIR,
    reports_dir: Path | str = DEFAULT_REPORTS_DIR,
    out: Path | str = DEFAULT_OUT,
    headline: str = "balanced",
) -> Path:
    """Build a static snapshot of the operator console from local evidence.

    Static generation embeds a generated timestamp and the source health, and marks the
    snapshot ``static`` rather than promising a live refresh (KTD9).
    """
    traces_path = Path(traces_dir)
    reports_path = Path(reports_dir)
    cases = load_cases(reports_dir, headline)
    overview = collect_platform_overview(
        settings=Settings(traces_dir=traces_path),
        provider_name="static",
        braintrust_enabled=False,
        ml_probe_available=False,
        reports_dir=reports_path,
    )
    overview.snapshot.freshness = FreshnessState.STATIC
    overview.snapshot.refresh_source = "static"
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        render_html(overview.model_dump(), cases=cases, headline=headline),
        encoding="utf-8",
    )
    return out_path
