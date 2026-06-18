"""Static dashboard generator — reads traces + eval metrics, emits one self-contained HTML.

No server, no JS build: a single file styled to the Ship/Linear dark palette. Regenerate
to refresh. All user/trace content is HTML-escaped at the seam.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

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
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.kpi .v{font-size:24px;font-weight:600;letter-spacing:-0.02em}
.kpi .k{font-size:12px;color:var(--muted);margin-top:2px}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:12px;padding:5px 10px;border-radius:6px;background:var(--surface)}
.dot{height:7px;width:7px;border-radius:999px;flex:none}
.mode{font-size:12px;color:var(--muted);border:1px solid var(--border);border-radius:6px;padding:3px 10px}
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
.ok{color:var(--allow)} .bad{color:var(--block)}
.empty{color:var(--muted);font-size:13px}
"""

_ACTION_COLOR = {
    "ALLOW": "var(--allow)",
    "WARN": "var(--warn)",
    "SANITIZE": "var(--sanitize)",
    "BLOCK": "var(--block)",
    "ESCALATE": "var(--escalate)",
}


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def load_recent_decisions(traces_dir: Path | str, limit: int = 25) -> list[dict[str, Any]]:
    directory = Path(traces_dir)
    if not directory.exists():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    # Order by event timestamp (true recency), not file/line order. Pre-timestamp
    # traces default to 0.0 and sort last.
    rows.sort(key=lambda r: r.get("created_at", 0.0), reverse=True)
    return rows[:limit]


def load_metrics(reports_dir: Path | str) -> dict[str, Any] | None:
    path = Path(reports_dir) / "metrics.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _action_pill(action: str) -> str:
    color = _ACTION_COLOR.get(action, "var(--muted)")
    return (
        f'<span class="pill"><span class="dot" style="background:{color}"></span>'
        f'<span style="color:{color};font-weight:600">{_esc(action)}</span></span>'
    )


def _kpis(m: dict[str, Any]) -> str:
    cells = [
        ("attack detection", f"{m['attack_detection_rate']:.0%}"),
        ("benign allowed", f"{m['benign_allow_rate']:.0%}"),
        ("false blocks", str(m["benign_false_blocks"])),
        ("evidence complete", f"{m['evidence_completeness']:.0%}"),
        ("avg latency", f"{m['avg_latency_ms']:.2f} ms"),
    ]
    items = "".join(
        f'<div class="card kpi"><div class="v">{_esc(v)}</div><div class="k">{_esc(k)}</div></div>'
        for k, v in cells
    )
    return f'<div class="kpis">{items}</div>'


def _criteria(m: dict[str, Any]) -> str:
    rows = []
    for name, ok in m["success_criteria"].items():
        mark = '<span class="ok">PASS</span>' if ok else '<span class="bad">FAIL</span>'
        rows.append(f"<div>{mark} &nbsp; {_esc(name)}</div>")
    return f'<div class="card crit">{"".join(rows)}</div>'


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


def _decisions(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return (
            '<div class="card empty">No decisions yet — run '
            '<span class="mono">python -m examples.demo_agent</span> or '
            '<span class="mono">aegis-eval</span>.</div>'
        )
    out = []
    for r in rows:
        decision = r.get("policy_decision") or {}
        action = decision.get("action", "ALLOW")
        fired = [
            h["detector_name"]
            for h in decision.get("detector_hits", [])
            if h.get("recommended_action") not in (None, "ALLOW")
        ]
        phase = r.get("phase", "?")
        tool = f" · {_esc(r['tool_name'])}" if r.get("tool_name") else ""
        det = f'<span class="det">{_esc(", ".join(dict.fromkeys(fired)))}</span>' if fired else ""
        summary = _esc((r.get("input_summary") or "")[:90])
        out.append(
            f'<div class="decision">{_action_pill(action)}'
            f'<span class="mono">{_esc(phase)}{tool}</span>'
            f'<span style="flex:1;color:var(--muted);font-size:12px">{summary}</span>{det}</div>'
        )
    return f'<div class="card">{"".join(out)}</div>'


def render_html(
    metrics: dict[str, Any] | None,
    cases: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    headline: str = "balanced",
    nav_html: str = "",
    auto_refresh: int = 0,
) -> str:
    m = (metrics or {}).get(headline)
    mode_badge = f'{nav_html}<span class="mode">policy: {_esc(headline)}</span>'
    refresh_meta = (
        f'<meta http-equiv="refresh" content="{auto_refresh}">' if auto_refresh else ""
    )

    if m:
        kpis = _kpis(m)
        criteria = _criteria(m)
        distribution = _distribution(m)
    else:
        note = '<div class="card empty">Run <span class="mono">aegis-eval</span> to populate metrics.</div>'
        kpis = criteria = distribution = note

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">{refresh_meta}
<title>Aegis — Credential Defense Console</title>
<style>{_CSS}</style></head>
<body>
<header><h1>Aegis</h1>{mode_badge}</header>
<div class="sub">Runtime credential defense for LLM agents — decisions, evidence, and eval results.</div>

<div class="label">Eval summary ({_esc(headline)})</div>
{kpis}

<div class="label">Success criteria</div>
{criteria}

<div class="label">Baseline vs protected</div>
{_baseline_table(cases)}

<div class="label">Detector hit distribution</div>
<div class="card">{distribution}</div>

<div class="label">Recent decisions</div>
{_decisions(decisions)}

<div class="hr"></div>
<div class="empty">Generated by <span class="mono">aegis-dashboard</span> — static snapshot. Regenerate to refresh.</div>
</body></html>
"""


def load_cases(reports_dir: Path | str, headline: str = "balanced") -> list[dict[str, Any]]:
    path = Path(reports_dir) / "results.jsonl"
    if not path.exists():
        return []
    cases = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        if row.get("mode") == headline:
            cases.append(row)
    return cases


def generate(
    traces_dir: Path | str = DEFAULT_TRACES_DIR,
    reports_dir: Path | str = DEFAULT_REPORTS_DIR,
    out: Path | str = DEFAULT_OUT,
    headline: str = "balanced",
) -> Path:
    metrics = load_metrics(reports_dir)
    cases = load_cases(reports_dir, headline)
    decisions = load_recent_decisions(traces_dir)
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_html(metrics, cases, decisions, headline), encoding="utf-8")
    return out_path
