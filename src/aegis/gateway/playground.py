"""Interactive test console served at GET /try.

Type a message, choose which guard point it enters through (user request / model response /
tool-call argument), and see the live AegisDecision rendered. Vanilla JS calling the same
/guard/* endpoints — no build step. Styled to the Ship/Linear palette.
"""

from __future__ import annotations

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aegis — Test Console</title>
<style>
:root{--bg:#0d0d0d;--surface:#1a1a1a;--fg:#f5f5f5;--muted:#8a8a8a;--border:#262626;
  --accent:#005ea2;--accent-hover:#0071bc;--allow:#3fb950;--warn:#d29922;--block:#f85149;--escalate:#db61a2;}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font-family:Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  -webkit-font-smoothing:antialiased;line-height:1.5;padding:32px;max-width:820px;margin:0 auto}
a{color:var(--accent);text-decoration:none}
header{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:4px}
h1{font-size:18px;font-weight:600}
.sub{color:var(--muted);font-size:13px;margin-bottom:24px}
.label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;color:#8a8a8a99;margin:22px 0 9px}
textarea{width:100%;min-height:110px;background:var(--surface);color:var(--fg);border:1px solid var(--border);
  border-radius:8px;padding:12px;font-family:inherit;font-size:14px;resize:vertical}
textarea:focus,input:focus{outline:2px solid var(--accent);outline-offset:1px}
input{background:var(--surface);color:var(--fg);border:1px solid var(--border);border-radius:6px;padding:7px 10px;font-size:13px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
/* Segmented mode selector */
.seg{display:inline-flex;border:1px solid var(--border);border-radius:8px;overflow:hidden}
.seg button{background:var(--surface);color:var(--muted);border:0;border-right:1px solid var(--border);
  padding:9px 16px;font-size:13px;font-family:inherit;cursor:pointer}
.seg button:last-child{border-right:0}
.seg button.active{background:var(--accent);color:#fff;font-weight:600}
.seg .hint{display:block;font-size:11px;opacity:.8;font-weight:400}
.go{background:var(--accent);color:#fff;border:0;border-radius:6px;padding:11px 20px;font-size:14px;font-weight:600;cursor:pointer}
.go:hover{background:var(--accent-hover)}
.chip{background:var(--surface);border:1px solid var(--border);color:var(--muted);border-radius:999px;padding:5px 12px;font-size:12px;cursor:pointer}
.chip:hover{color:var(--fg);border-color:var(--accent)}
#result{margin-top:22px;border:1px solid var(--border);border-radius:8px;padding:16px;display:none}
.verdict{display:flex;align-items:center;gap:10px;font-size:20px;font-weight:700}
.dot{height:11px;width:11px;border-radius:999px}
.meta{color:var(--muted);font-size:13px;margin-top:6px}
.reasons{margin-top:12px;font-size:13px}
.reasons li{margin:4px 0;color:var(--muted);list-style:none;padding-left:14px;position:relative}
.reasons li:before{content:'';position:absolute;left:0;top:8px;height:5px;width:5px;border-radius:999px;background:var(--muted)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.err{color:var(--block)}
</style></head>
<body>
<header><h1>Aegis · Test Console</h1><a href="/">← dashboard</a></header>
<div class="sub">Type a message, choose where it enters the agent, and see the live decision.</div>

<div class="label">1 · Examples (click to fill)</div>
<div class="row">
  <span class="chip" data-fill="What's a good weekly status report template?">benign</span>
  <span class="chip" data-fill="Sure, the key is ghp_0123456789abcdefghijklmnopqrstuvwxyz">raw secret</span>
  <span class="chip" data-fill="aGVyZSBpcyBnaHBfMDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6">base64 secret</span>
  <span class="chip" data-fill="api_key=ghp_0123456789abcdefghijklmnopqrstuvwxyz">tool-arg leak</span>
</div>

<div class="label">2 · Message</div>
<textarea id="msg" placeholder="Type text to test…"></textarea>

<div class="label">3 · Scan it as</div>
<div class="seg" id="modes" role="group" aria-label="guard point">
  <button data-mode="request">User request<span class="hint">guard_request</span></button>
  <button data-mode="response" class="active">Model response<span class="hint">guard_response</span></button>
  <button data-mode="tool_call">Tool-call arg<span class="hint">guard_tool_call</span></button>
</div>

<div class="label">4 · Policy mode</div>
<div class="seg" id="policy-modes" role="group" aria-label="policy mode">
  <button data-policy="observe">Observe<span class="hint">detect only</span></button>
  <button data-policy="balanced" class="active">Balanced<span class="hint">default</span></button>
  <button data-policy="strict">Strict<span class="hint">conservative</span></button>
</div>

<div class="row" style="margin-top:16px">
  <button class="go" onclick="runTest()">Test with Aegis</button>
  <span style="flex:1"></span>
  <span class="mono" style="color:var(--muted)">session</span>
  <input id="sess" value="playground" size="14">
</div>

<div id="result"></div>

<script>
const COLOR = {ALLOW:'var(--allow)',WARN:'var(--warn)',SANITIZE:'var(--accent)',BLOCK:'var(--block)',ESCALATE:'var(--escalate)'};
let mode = 'response';
let policyMode = 'balanced';

document.querySelectorAll('.chip').forEach(c => c.onclick = () => { document.getElementById('msg').value = c.dataset.fill; });
function setMode(next){
  if(!['request','response','tool_call'].includes(next)) return;
  document.querySelectorAll('#modes button').forEach(x => x.classList.remove('active'));
  const selected = document.querySelector(`#modes button[data-mode="${next}"]`);
  if(selected) selected.classList.add('active');
  mode = next;
}
document.querySelectorAll('#modes button').forEach(b => b.onclick = () => setMode(b.dataset.mode));
function setPolicyMode(next){
  if(!['observe','balanced','strict'].includes(next)) return;
  document.querySelectorAll('#policy-modes button').forEach(x => x.classList.remove('active'));
  const selected = document.querySelector(`#policy-modes button[data-policy="${next}"]`);
  if(selected) selected.classList.add('active');
  policyMode = next;
}
document.querySelectorAll('#policy-modes button').forEach(b => b.onclick = () => setPolicyMode(b.dataset.policy));

const params = new URLSearchParams(window.location.search);
const presetText = params.get('text') || params.get('prompt');
const presetSession = params.get('session');
const presetMode = params.get('mode');
const presetPolicy = params.get('policy') || params.get('policy_mode');
if(presetText) document.getElementById('msg').value = presetText;
if(presetSession) document.getElementById('sess').value = presetSession;
if(presetMode) setMode(presetMode);
if(presetPolicy) setPolicyMode(presetPolicy);

async function runTest(){
  const text = document.getElementById('msg').value;
  const session = document.getElementById('sess').value || 'playground';
  let url, body;
  if(mode==='request'){ url='/guard/request'; body={session_id:session, policy_mode:policyMode, messages:[{role:'user',content:text}]}; }
  else if(mode==='tool_call'){ url='/guard/tool_call'; body={session_id:session, policy_mode:policyMode, tool_name:'send_email', arguments:{to:'someone@example.com', body:text}}; }
  else { url='/guard/response'; body={session_id:session, policy_mode:policyMode, output:text}; }

  const el = document.getElementById('result');
  el.style.display='block';
  el.innerHTML='<span class="meta">scanning…</span>';
  try{
    const r = await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
    render(await r.json());
  }catch(e){ el.innerHTML='<span class="err">request failed: '+e+'</span>'; }
}

function esc(s){ return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

function render(d){
  const color = COLOR[d.action] || 'var(--muted)';
  const fired = (d.detector_hits||[]).filter(h=>h.recommended_action && h.recommended_action!=='ALLOW')
      .map(h=>h.detector_name);
  const reasons = (d.reasons||[]).map(x=>'<li>'+esc(x)+'</li>').join('');
  document.getElementById('result').innerHTML =
    '<div class="verdict"><span class="dot" style="background:'+color+'"></span>'
    + '<span style="color:'+color+'">'+esc(d.action)+'</span></div>'
    + '<div class="meta">guard: '+esc(mode)+' · policy '+esc(policyMode)+' · risk '+(d.risk_score??0).toFixed(2)
    + ' · detectors fired: '+(fired.length?esc([...new Set(fired)].join(', ')):'none')+'</div>'
    + (reasons?'<ul class="reasons">'+reasons+'</ul>':'<div class="meta" style="margin-top:10px;color:var(--allow)">allowed — no evidence</div>');
}
</script>
</body></html>
"""


def render_playground() -> str:
    return _PAGE
