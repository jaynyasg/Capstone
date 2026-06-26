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
from aegis.platform import (
    collect_platform_overview,
    load_eval_metrics_with_health,
    load_trace_events,
)
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
.header-actions{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex-wrap:wrap}
.label{font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:0.08em;color:var(--fg);
  margin:30px 0 14px;padding-left:10px;border-left:3px solid var(--accent);line-height:1.1}
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
.rank{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}
.score{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;font-weight:600}
.walkthrough-btn{border:1px solid var(--accent);background:transparent;color:var(--fg);border-radius:6px;
  padding:5px 10px;font-size:12px;font-weight:700;cursor:pointer}
.walkthrough-btn:hover{background:#005ea222}
.walkthrough-btn:disabled{cursor:wait;color:var(--muted);border-color:var(--border)}
.walkthrough-btn:focus-visible{outline:2px solid var(--sanitize);outline-offset:2px}
.dashboard-section{border-radius:8px;padding:1px 0;margin:0 0 4px;scroll-margin:24px}
.dashboard-section.walkthrough-active{outline:3px solid var(--accent);outline-offset:6px;
  background:#005ea214;box-shadow:0 0 0 9999px #00000026,0 0 32px #005ea255;color:var(--fg)}
.dashboard-section.walkthrough-active .card,.dashboard-section.walkthrough-active table{background:#101820}
.walkthrough-status{position:fixed;right:18px;bottom:18px;z-index:20;display:none;
  max-width:min(360px,calc(100vw - 36px));border:1px solid var(--accent);border-radius:8px;
  background:#0d0d0df2;box-shadow:0 12px 40px #0008;padding:12px 14px}
.walkthrough-status.active{display:block}
.walkthrough-title{font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:0.08em}
.walkthrough-copy{font-size:13px;color:var(--fg);margin-top:4px}
.walkthrough-note{font-size:12px;color:var(--muted);margin-top:6px}
.walkthrough-steps{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px;margin-top:10px}
.walkthrough-step{border:1px solid var(--border);border-radius:6px;padding:5px 6px;
  color:var(--muted);font-size:11px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.walkthrough-step.active{border-color:var(--accent);background:#005ea222;color:var(--fg)}
.walkthrough-step.done{border-color:#2ea04366;color:var(--allow)}
.walkthrough-packet{margin-top:10px;border:1px solid #005ea266;border-radius:8px;background:#005ea214;
  padding:10px}
.walkthrough-packet-head{display:flex;justify-content:space-between;gap:10px;align-items:center;
  font-size:11px;font-weight:800;text-transform:uppercase;color:var(--fg)}
.walkthrough-source{font-size:11px;color:var(--sanitize);text-transform:none;text-align:right}
.walkthrough-flow{display:grid;grid-template-columns:14px 1fr auto;gap:8px;align-items:center;margin-top:8px}
.packet-dot{width:10px;height:10px;border-radius:999px;background:var(--sanitize);
  box-shadow:0 0 16px #58a6ff99;animation:packetPulse 1.2s ease-in-out infinite}
.packet-line{position:relative;height:2px;background:#58a6ff44;overflow:hidden}
.packet-line:after{content:"";position:absolute;inset:0;width:42%;background:linear-gradient(90deg,transparent,var(--sanitize),transparent);
  animation:packetTravel 1.4s linear infinite}
.walkthrough-target{font-size:11px;color:var(--muted);font-weight:700;white-space:nowrap}
.walkthrough-data{display:grid;gap:5px;margin-top:9px}
.walkthrough-data-row{display:grid;grid-template-columns:92px minmax(0,1fr);gap:8px;align-items:baseline;
  font-size:12px}
.walkthrough-data-row span:first-child{color:var(--muted);font-weight:700;text-transform:uppercase}
.walkthrough-data-row strong{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
  color:var(--fg);overflow-wrap:anywhere}
.walkthrough-data-empty{font-size:12px;color:var(--muted)}
@keyframes packetPulse{0%,100%{transform:scale(1);opacity:0.8}50%{transform:scale(1.28);opacity:1}}
@keyframes packetTravel{0%{transform:translateX(-110%)}100%{transform:translateX(240%)}}
@media (prefers-reduced-motion: reduce){.dashboard-section.walkthrough-active{outline-offset:4px}}
@media (max-width:640px){.walkthrough-steps{grid-template-columns:1fr}}
"""

_WALKTHROUGH_STEPS = [
    ("evidence-health", "Evidence health", "Check whether the evidence is healthy, stale, or degraded."),
    (
        "investigate",
        "Investigate",
        "Jump into sessions, actions, phases, detectors, and model evidence.",
    ),
    ("platform-cockpit", "Platform cockpit", "Review runtime, canary, CIFT, and session state."),
    ("nimbus-rankings", "Nimbus rankings", "Rank sessions by cumulative Nimbus leakage risk."),
    ("recent-decisions", "Recent decisions", "Inspect the latest guarded decisions and detectors."),
    ("eval-summary", "Eval summary", "Confirm current eval metrics for the selected policy view."),
    ("success-criteria", "Success criteria", "See which success checks are passing."),
    ("baseline-vs-protected", "Baseline vs protected", "Compare vulnerable baseline behavior to Aegis."),
    (
        "detector-hit-distribution",
        "Detector hit distribution",
        "Scan which detectors are carrying the evidence.",
    ),
]

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


def _num(value: Any, default: float = 0.0) -> float:
    """Coerce a metric value to float for formatting; malformed input -> default, never crash.

    ``metrics.json`` is operator-editable, so a non-numeric rate or count must degrade rather
    than 500 the console. ``bool`` is excluded (it is an ``int`` subclass but not a metric).
    """
    if isinstance(value, bool) or value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    return value.model_dump() if hasattr(value, "model_dump") else dict(value)


def load_recent_decisions(traces_dir: Path | str, limit: int = 25) -> list[dict[str, Any]]:
    """Recent trace rows, newest first. Thin wrapper over the shared platform JSONL reader."""
    return load_trace_events(traces_dir, limit)


def load_metrics(reports_dir: Path | str) -> dict[str, Any] | None:
    """Eval metrics if present; corrupt/absent → None. Shares the platform loader's logic."""
    metrics, _ = load_eval_metrics_with_health(reports_dir)
    return metrics


def _action_pill(action: str) -> str:
    color = _ACTION_COLOR.get(action, "var(--muted)")
    return (
        f'<span class="pill"><span class="dot" style="background:{color}"></span>'
        f'<span style="color:{color};font-weight:600">{_esc(action)}</span></span>'
    )


def _kpis(m: dict[str, Any]) -> str:
    cells = [
        ("attack detection", f"{_num(m.get('attack_detection_rate')):.0%}"),
        ("benign allowed", f"{_num(m.get('benign_allow_rate')):.0%}"),
        ("false blocks", str(m.get("benign_false_blocks", 0))),
        ("evidence complete", f"{_num(m.get('evidence_completeness')):.0%}"),
        ("avg latency", f"{_num(m.get('avg_latency_ms')):.2f} ms"),
    ]
    items = "".join(
        f'<div class="card kpi"><div class="v">{_esc(v)}</div><div class="k">{_esc(k)}</div></div>'
        for k, v in cells
    )
    return f'<div class="kpis">{items}</div>'


def _criteria(m: dict[str, Any]) -> str:
    criteria = m.get("success_criteria", {})
    rows = []
    # Only a {name: bool} mapping carries pass/fail; any other shape (e.g. a list) is malformed
    # and must not crash the render — fall through to the empty note.
    if isinstance(criteria, dict):
        for name, ok in criteria.items():
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
    if not isinstance(dist, dict) or not dist:
        return '<div class="empty">No detector hits recorded.</div>'
    # Coerce counts for the bar math; a malformed count degrades to 0 rather than 500. ``:g``
    # keeps whole numbers integer-formatted (4.0 -> "4"), so valid input renders unchanged.
    counts = {str(name): _num(count) for name, count in dist.items()}
    top = max(counts.values())
    rows = []
    for name, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        pct = int(100 * count / top) if top else 0
        rows.append(
            f'<div class="barrow"><span class="det">{_esc(name)}</span>'
            f'<span class="bar" style="width:{pct}%"></span>'
            f'<span class="det">{_esc(f"{count:g}")}</span></div>'
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
        fired = r.get("detectors", [])
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


def _nimbus_rankings(data: dict[str, Any]) -> str:
    sessions = sorted(
        (dict(s) for s in data.get("sessions", [])),
        key=lambda s: (
            _num(s.get("nimbus_cumulative_score")),
            _num(s.get("last_seen")),
        ),
        reverse=True,
    )
    if not sessions:
        return _note("No Nimbus session risk yet.")

    rows = []
    for idx, session in enumerate(sessions[:10], start=1):
        action = str(session.get("latest_action", "ALLOW"))
        score = f"{_num(session.get('nimbus_cumulative_score')):.2f}"
        rows.append(
            "<tr>"
            f"<td class='rank'>#{idx}</td>"
            f"<td class='mono'>{_esc(session.get('session_id', 'unknown'))}</td>"
            f"<td><span class='score'>{_esc(score)}</span></td>"
            f"<td>{_action_pill(action)}</td>"
            f"<td>{_esc(session.get('events', 0))}</td>"
            f"<td class='mono'>{_esc(session.get('last_seen', 0.0))}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Rank</th><th>Session</th><th>Nimbus</th>"
        "<th>Latest action</th><th>Events</th><th>Last seen</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _json_for_script(value: Any) -> str:
    return (
        json.dumps(value)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _packet_field(label: str, value: Any) -> dict[str, str]:
    return {"label": label, "value": str(value)}


def _top_mapping_item(values: Any) -> tuple[str, str]:
    if not isinstance(values, dict) or not values:
        return "none", "0"
    name, count = max(values.items(), key=lambda kv: _num(kv[1]))
    return str(name), f"{_num(count):g}"


def _walkthrough_steps(
    data: dict[str, Any],
    cases: list[dict[str, Any]],
    headline: str,
    metrics: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    snapshot = data.get("snapshot", {})
    health = data.get("health", {})
    status = data.get("status", {})
    decisions = data.get("decisions", {})
    cift = data.get("cift", {})
    canaries = data.get("canaries", {})
    sessions = [dict(s) for s in data.get("sessions", []) if isinstance(s, dict)]
    recent = [dict(r) for r in decisions.get("recent", []) if isinstance(r, dict)]
    metrics = metrics if isinstance(metrics, dict) else {}

    top_session = max(
        sessions,
        key=lambda s: (_num(s.get("nimbus_cumulative_score")), _num(s.get("last_seen"))),
        default={},
    )
    latest_decision = recent[0] if recent else {}
    action_name, action_count = _top_mapping_item(decisions.get("by_action"))
    detector_name, detector_count = _top_mapping_item(decisions.get("detector_hits"))
    eval_detector_name, eval_detector_count = _top_mapping_item(
        metrics.get("detector_hit_distribution")
    )
    cift_latest = (cift.get("latest") or [{}])[0] if cift.get("latest") else {}
    criteria = metrics.get("success_criteria") if isinstance(metrics, dict) else {}
    criteria = criteria if isinstance(criteria, dict) else {}
    passing_criteria = sum(1 for ok in criteria.values() if ok)
    attacks = [
        c for c in cases if c.get("baseline_leaked") is not None and c.get("worst_action")
    ]
    baseline_leaks = sum(1 for c in attacks if c.get("baseline_leaked"))
    protected_blocks = sum(1 for c in attacks if c.get("worst_action") == "BLOCK")
    freshness = str(snapshot.get("freshness", "live"))
    cache_age = _num(snapshot.get("cache_age_seconds"))
    freshness_value = freshness if freshness in ("live", "static") else f"{freshness} ({cache_age:.0f}s)"

    payloads = {
        "evidence-health": {
            "source": "snapshot + health",
            "fields": [
                _packet_field("status", health.get("status", "healthy")),
                _packet_field("freshness", freshness_value),
                _packet_field("warnings", len(health.get("warnings", []) or [])),
            ],
        },
        "investigate": {
            "source": "api drilldowns",
            "fields": [
                _packet_field("sessions", len(sessions)),
                _packet_field("top action", f"{action_name} ({action_count})"),
                _packet_field("detector", f"{detector_name} ({detector_count})"),
            ],
        },
        "platform-cockpit": {
            "source": "runtime + stores",
            "fields": [
                _packet_field("provider", status.get("provider", "unknown")),
                _packet_field("canaries", canaries.get("total", 0)),
                _packet_field(
                    "cift",
                    f"{cift_latest.get('model_id', 'none')} / {cift_latest.get('status', 'none')}",
                ),
            ],
        },
        "nimbus-rankings": {
            "source": "session risk",
            "fields": [
                _packet_field("top session", top_session.get("session_id", "none")),
                _packet_field("nimbus", f"{_num(top_session.get('nimbus_cumulative_score')):.2f}"),
                _packet_field("latest action", top_session.get("latest_action", "none")),
            ],
        },
        "recent-decisions": {
            "source": "trace events",
            "fields": [
                _packet_field("total", decisions.get("total", len(recent))),
                _packet_field("latest", latest_decision.get("action", "none")),
                _packet_field("summary", latest_decision.get("summary", "none")),
            ],
        },
        "eval-summary": {
            "source": f"evals.{headline}",
            "fields": [
                _packet_field(
                    "detection", f"{_num(metrics.get('attack_detection_rate')):.0%}"
                ),
                _packet_field("benign", f"{_num(metrics.get('benign_allow_rate')):.0%}"),
                _packet_field("latency", f"{_num(metrics.get('avg_latency_ms')):.2f} ms"),
            ],
        },
        "success-criteria": {
            "source": "eval gates",
            "fields": [
                _packet_field("passing", f"{passing_criteria}/{len(criteria)}"),
                _packet_field("mode", headline),
                _packet_field("complete", f"{_num(metrics.get('evidence_completeness')):.0%}"),
            ],
        },
        "baseline-vs-protected": {
            "source": "eval cases",
            "fields": [
                _packet_field("cases", len(attacks)),
                _packet_field("baseline", f"{baseline_leaks} leaks"),
                _packet_field("aegis", f"{protected_blocks} blocked"),
            ],
        },
        "detector-hit-distribution": {
            "source": "detector metrics",
            "fields": [
                _packet_field("top hit", eval_detector_name),
                _packet_field("count", eval_detector_count),
                _packet_field("detectors", len(metrics.get("detector_hit_distribution", {}) or {})),
            ],
        },
    }

    return [
        {
            "key": key,
            "title": title,
            "copy": copy,
            "source": payloads.get(key, {}).get("source", "platform.overview"),
            "fields": payloads.get(key, {}).get("fields", []),
        }
        for key, title, copy in _WALKTHROUGH_STEPS
    ]


def _walkthrough_script(
    data: dict[str, Any],
    cases: list[dict[str, Any]],
    headline: str,
    metrics: dict[str, Any] | None,
    auto_refresh: int = 0,
) -> str:
    steps = _json_for_script(_walkthrough_steps(data, cases, headline, metrics))
    refresh_ms = max(0, int(auto_refresh or 0)) * 1000
    return f"""
<script>
(() => {{
  const steps = {steps};
  const intervalMs = window.matchMedia("(prefers-reduced-motion: reduce)").matches ? 1200 : 2400;
  const autoRefreshMs = {refresh_ms};
  const button = document.getElementById("walkthrough-run");
  const panel = document.getElementById("walkthrough-status");
  const refreshMeta = document.getElementById("dashboard-auto-refresh");
  if (!button || !panel) return;
  const title = panel.querySelector(".walkthrough-title");
  const copy = panel.querySelector(".walkthrough-copy");
  const note = panel.querySelector(".walkthrough-note");
  const stepList = panel.querySelector(".walkthrough-steps");
  const packet = panel.querySelector(".walkthrough-packet");
  const packetSource = panel.querySelector(".walkthrough-source");
  const packetTarget = panel.querySelector(".walkthrough-target");
  const packetData = panel.querySelector(".walkthrough-data");
  let timer = null;
  let refreshTimer = null;

  function clearActive() {{
    document.querySelectorAll(".walkthrough-active").forEach((el) => {{
      el.classList.remove("walkthrough-active");
    }});
  }}

  function renderStepList(activeIndex = -1) {{
    if (!stepList) return;
    stepList.innerHTML = "";
    steps.forEach((step, index) => {{
      const item = document.createElement("div");
      item.className = "walkthrough-step";
      if (index < activeIndex) item.classList.add("done");
      if (index === activeIndex) item.classList.add("active");
      item.textContent = `${{index + 1}}. ${{step.title}}`;
      stepList.appendChild(item);
    }});
  }}

  function renderPacket(step = null) {{
    if (!packet) return;
    const fields = step && Array.isArray(step.fields) ? step.fields : [];
    if (packetSource) packetSource.textContent = step ? step.source : "platform.overview";
    if (packetTarget) packetTarget.textContent = step ? step.key : "ready";
    if (!packetData) return;
    packetData.innerHTML = "";
    if (!fields.length) {{
      const empty = document.createElement("div");
      empty.className = "walkthrough-data-empty";
      empty.textContent = "No payload rows for this step.";
      packetData.appendChild(empty);
      return;
    }}
    fields.forEach((field) => {{
      const row = document.createElement("div");
      const label = document.createElement("span");
      const value = document.createElement("strong");
      row.className = "walkthrough-data-row";
      label.textContent = field.label;
      value.textContent = field.value;
      row.append(label, value);
      packetData.appendChild(row);
    }});
  }}

  function scheduleRefresh() {{
    if (!autoRefreshMs || refreshTimer) return;
    if (refreshMeta) refreshMeta.setAttribute("data-state", "running");
    refreshTimer = window.setTimeout(() => {{
      window.location.reload();
    }}, autoRefreshMs);
  }}

  function pauseRefresh() {{
    if (refreshTimer) {{
      window.clearTimeout(refreshTimer);
      refreshTimer = null;
    }}
    if (refreshMeta) refreshMeta.setAttribute("data-state", "paused");
  }}

  function resumeRefresh() {{
    scheduleRefresh();
  }}

  function showStep(index) {{
    const step = steps[index];
    const section = document.querySelector(`[data-section="${{step.key}}"]`);
    if (!section) return;
    clearActive();
    section.classList.add("walkthrough-active");
    title.textContent = `${{index + 1}}/${{steps.length}} · ${{step.title}}`;
    copy.textContent = step.copy;
    if (note) note.textContent = "Live refresh is paused during this walkthrough.";
    renderStepList(index);
    renderPacket(step);
    panel.classList.add("active");
    button.textContent = `Running ${{index + 1}}/${{steps.length}}`;
    section.scrollIntoView({{ behavior: intervalMs < 1500 ? "auto" : "smooth", block: "center" }});
  }}

  function finish() {{
    window.clearInterval(timer);
    timer = null;
    resumeRefresh();
    button.disabled = false;
    button.textContent = "Run walkthrough";
    if (title) title.textContent = "Walkthrough complete";
    if (copy) copy.textContent = "All operator sections were shown.";
    if (note) note.textContent = "Live refresh has resumed.";
    renderStepList(steps.length);
    if (packetTarget) packetTarget.textContent = "complete";
    window.setTimeout(() => {{
      clearActive();
      panel.classList.remove("active");
    }}, 1800);
  }}

  button.addEventListener("click", () => {{
    if (timer) window.clearInterval(timer);
    pauseRefresh();
    button.disabled = true;
    button.textContent = "Running...";
    let index = 0;
    showStep(index);
    timer = window.setInterval(() => {{
      index += 1;
      if (index >= steps.length) {{
        finish();
        return;
      }}
      showStep(index);
    }}, intervalMs);
  }});
  renderStepList();
  renderPacket();
  scheduleRefresh();
}})();
</script>
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
    refresh_meta = (
        f'<meta id="dashboard-auto-refresh" name="aegis-auto-refresh" content="{auto_refresh}">'
        if auto_refresh
        else ""
    )

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
<header><h1>Aegis</h1><div class="header-actions"><button id="walkthrough-run" class="walkthrough-btn" type="button">Run walkthrough</button>{mode_badge}</div></header>
<div class="sub">Operator console — what happened, what changed, what evidence is degraded, what to export.</div>
<div id="walkthrough-status" class="walkthrough-status" aria-live="polite">
  <div class="walkthrough-title">Walkthrough</div>
  <div class="walkthrough-copy">Ready.</div>
  <div class="walkthrough-note">Click Run walkthrough to start.</div>
  <div class="walkthrough-packet" aria-label="Evidence packet">
    <div class="walkthrough-packet-head">
      <span>Evidence packet</span>
      <span class="walkthrough-source mono">platform.overview</span>
    </div>
    <div class="walkthrough-flow">
      <span class="packet-dot" aria-hidden="true"></span>
      <span class="packet-line" aria-hidden="true"></span>
      <span class="walkthrough-target">ready</span>
    </div>
    <div class="walkthrough-data"></div>
  </div>
  <div class="walkthrough-steps" aria-label="Walkthrough steps"></div>
</div>

<section class="dashboard-section" data-section="evidence-health">
<div class="label">Evidence health</div>
{_health_panel(health)}
</section>

<section class="dashboard-section" data-section="investigate">
<div class="label">Investigate (drilldowns → platform API)</div>
{_drilldowns(data)}
</section>

<section class="dashboard-section" data-section="platform-cockpit">
<div class="label">Platform cockpit</div>
{_platform(data)}
</section>

<section class="dashboard-section" data-section="nimbus-rankings">
<div class="label">Nimbus rankings</div>
{_nimbus_rankings(data)}
</section>

<section class="dashboard-section" data-section="recent-decisions">
<div class="label">Recent decisions</div>
{_decisions(decisions, health)}
</section>

<section class="dashboard-section" data-section="eval-summary">
<div class="label">Eval summary ({_esc(headline)})</div>
{kpis}
</section>

<section class="dashboard-section" data-section="success-criteria">
<div class="label">Success criteria</div>
{criteria}
</section>

<section class="dashboard-section" data-section="baseline-vs-protected">
<div class="label">Baseline vs protected</div>
{_baseline_table(cases)}
</section>

<section class="dashboard-section" data-section="detector-hit-distribution">
<div class="label">Detector hit distribution</div>
<div class="card">{distribution}</div>
</section>

<div class="hr"></div>
<div class="empty">Generated by <span class="mono">aegis-dashboard</span> — export an audit bundle at <span class="mono">/api/platform/export?format=md</span>.</div>
{_walkthrough_script(data, cases, headline, m, auto_refresh)}
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
