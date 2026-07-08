"""app.py (V3 §8 · PS-8 · H-K) — FastAPI 3-panel replay Viewer.

Three panels (V3 §8):
  - 동작 (action)       : the agent's decision timeline, from run.jsonl (decisions channel)
  - 통신 (communication): 14560 downlink telemetry + uav_ue lo:14550 cross-tap heartbeats
  - 검증 (verification) : the INDEPENDENT Verifier's per-tick truth, side-by-side with the
                          agent's decision — the *agent ≠ truth* comparison (H-K)

UI (2026-07): the alarming top banner is removed. The agent≠truth semantics survive as
compact header stat chips (신뢰근원 trust_root + ⚠ 불일치 count) — the Verifier (a separate
trust root) stays authoritative for link health without a red warning bar. The per-tick
timeline is grouped into collapsible batches of 10 ticks (newest auto-expanded, expand-state
preserved across the 3s refresh) and risk-colored (Red=위험 / Yellow=주의 / Green=평시;
agent≠truth divergence flagged red) for at-a-glance triage.

Security posture (locked):
  * the Verifier (a separate trust root) is authoritative for link health; the header shows
    its trust_root and the agent≠truth divergence count as stat chips (no alarm banner).
  * record-time redact ONLY (PS-3): the Viewer performs NO display-time redaction. Instead
    it runs a load-time secret scan and FAILS CLOSED (refuses to serve a tainted file) —
    honoring "record-time redact, viewer display-time redact 폐기" while staying safe.
  * read-only: every route is GET; there is no endpoint that mutates state or the testbed.
  * bearer-token auth (PS-8): constant-time compare; no token => every data route 401s.
  * loopback / management bind (PS-8): ``serve()`` refuses 0.0.0.0 (attacker UE 10.45.x
    must never reach the management plane).

FastAPI/uvicorn are imported lazily (like core.graph imports langgraph) so this module —
and its pure builders (load_panels / scan_secrets) — import and test with zero web deps.
This module does NOT import mdg.core (it consumes JSONL via replay.play + the standalone
Verifier), keeping the management plane off the decision path.
"""
from __future__ import annotations

import hmac
import json
from typing import Any, Optional

from mdg.redact_patterns import SECRET_PATTERNS as _SECRET_PATTERNS
from mdg.replay import play
from mdg.verifier import verifier as V

__all__ = ["load_panels", "scan_secrets", "SecretLeakError", "create_app", "serve"]

# Load-time secret scan (defense-in-depth over record-time redact). If any pattern matches,
# the file is tainted and the Viewer refuses to serve it (fail-closed) rather than redacting.
# The pattern list is the shared single source (mdg.redact_patterns) — the same list the
# record-time scrub uses — so the two boundaries cannot drift. mdg.redact_patterns is a pure,
# dependency-free module (NOT under mdg.core), so importing it keeps the decision path off
# the management plane (this module still imports no mdg.core.*).

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


class SecretLeakError(RuntimeError):
    """Raised when a run.jsonl still contains secret material (record-time redact failed)."""


def scan_secrets(text: str) -> list[str]:
    """Return the secret patterns found in ``text`` (empty => clean). Used at load time to
    fail-closed; the Viewer never redacts at display time (PS-3 contract)."""
    hits: list[str] = []
    for pat in _SECRET_PATTERNS:
        if pat.search(text):
            hits.append(pat.pattern)
    return hits


# --------------------------------------------------------------------------- #
# Pure panel builders (no web deps) — testable directly
# --------------------------------------------------------------------------- #
def _telemetry_rows(tick: play.TickView) -> list[dict]:
    """14560/14550 telemetry evidence rows for the communication panel."""
    rows = []
    for ev in tick.evidence or []:
        if not isinstance(ev, dict):
            continue
        if ev.get("channel") == "plaintext_mavlink_tap" and ev.get("domain") == "communication":
            rows.append({
                "metric": ev.get("metric"), "value": ev.get("value"),
                "band": ev.get("band"), "source_id": ev.get("source_id"),
                "verified": ev.get("verified"), "tamper": ev.get("tamper"),
            })
    return rows


def load_panels(run_path: str) -> dict:
    """Build the full 3-panel view model from ``run.jsonl`` (+ independent Verifier truth).

    Fail-closed on any residual secret (record-time redact contract). Pure: no web deps,
    no testbed, deterministic — the portability pillar (H-J)."""
    with open(run_path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    hits = scan_secrets(raw)
    if hits:
        raise SecretLeakError(
            f"run.jsonl contains residual secret material {hits} — refusing to serve "
            f"(record-time redact failed; the Viewer does NOT redact at display time, PS-3)"
        )

    ticks = play.load_timeline(run_path)
    verdicts = V.verify_run(run_path)               # independent trust root
    vmap = {v.tick: v for v in verdicts}

    action_panel, comm_panel, verify_panel = [], [], []
    for t in ticks:
        dec = t.last_decision()
        v = vmap.get(t.index)
        action_panel.append({
            "tick": t.index, "tick_i": t.tick_i,
            "impact_band": (t.impact or {}).get("band"),
            "decision": dec.get("decision") if dec else None,
            "enforcement": dec.get("enforcement") if dec else None,
            "incidents": len(t.incidents), "ledger": len(t.ledger),
            "nodes": t.nodes,
        })
        comm_panel.append({"tick": t.index, "telemetry": _telemetry_rows(t)})
        verify_panel.append({
            "tick": t.index,
            "agent_decision": v.agent_decision if v else (dec.get("decision") if dec else None),
            "truth_verdict": v.verdict if v else V.UNKNOWN,
            "telemetry_alive": v.telemetry_alive if v else None,
            "gcs_proxy_alive": v.gcs_proxy_alive if v else None,
            "cross_root_consistent": v.cross_root_consistent if v else None,
            "silence_streak": v.silence_streak if v else 0,
            "agent_truth_divergence": v.agent_truth_divergence if v else False,
            "reason": v.reason if v else "",
        })

    summary = V.summarize(verdicts)
    return {
        # 헤더 메타(경고 문구 없음). 신뢰근원·불일치 수만 콤팩트 칩으로 노출.
        "banner": {
            "divergences": summary["agent_truth_divergences"],
            "trust_root": "mdg.verifier (out-of-graph, replay-only, deterministic)",
        },
        "summary": summary,
        "panels": {"action": action_panel, "communication": comm_panel, "verification": verify_panel},
        "record_time_redact": True,        # display-time redaction is intentionally OFF (PS-3)
        "read_only": True,
    }


# --------------------------------------------------------------------------- #
# HTML shell (inline; no external assets)
# --------------------------------------------------------------------------- #
_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>MDG 방어 로그 뷰어</title>
<style>
 body{font-family:ui-monospace,Menlo,Consolas,monospace;background:#0a0e15;color:#c7d3e0;margin:0;padding:16px}
 header{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:14px}
 h1{font-size:15px;color:#9fe7f2;margin:0 12px 0 0}
 .chip{font-size:12px;padding:3px 10px;border-radius:20px;background:#141c2b;border:1px solid #23324a;white-space:nowrap}
 .chip b{color:#eaf2ff}
 .chip.red{background:#2a1218;border-color:#7a2b3e;color:#ffb3c0}
 .chip.amber{background:#241d10;border-color:#7a5a2b;color:#ffd79a}
 .chip.green{background:#10241b;border-color:#2e7d5b;color:#8fe6bf}
 .muted{font-size:11px;color:#6f8296}
 .legend{margin:0 0 12px;font-size:11px;color:#7f92a8;display:flex;gap:14px;flex-wrap:wrap}
 .sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:middle}
 details{margin:0}
 summary{cursor:pointer;list-style:none;user-select:none}
 summary::-webkit-details-marker{display:none}
 .arrow{display:inline-block;transition:transform .12s;color:#5f7690}
 details[open]>summary .arrow{transform:rotate(90deg)}
 .batch{margin-bottom:8px;border:1px solid #1f2c3e;border-radius:10px;overflow:hidden;background:#0e1420}
 .batch>summary{padding:9px 12px;font-size:13px;color:#bcd0e4;background:#111a28;display:flex;align-items:center;gap:9px}
 .batch>summary:hover{background:#15202f}
 .brows{padding:6px}
 .trow{border-radius:8px;margin:3px 0;background:#0f1622;border-left:4px solid #26364c}
 .trow>summary{padding:7px 10px;display:flex;align-items:center;gap:10px;font-size:12px;white-space:nowrap;overflow-x:auto}
 .trow.risk-danger{border-left-color:#ff5470;background:#1e1015}
 .trow.risk-warn{border-left-color:#ffb454;background:#1c1710}
 .trow.risk-ok{border-left-color:#2c6b4f}
 .tk{color:#7f8ea3;min-width:46px}
 .badge{font-size:11px;padding:2px 8px;border-radius:6px;font-weight:bold;white-space:nowrap}
 .b-Red{background:#ff5470;color:#1a0a0e}
 .b-Yellow{background:#ffb454;color:#1a1204}
 .b-Green{background:#3ecf8e;color:#06130d}
 .b-unknown{background:#33425c;color:#cdd}
 .dec{color:#e3ebf5;flex:1;min-width:130px;overflow:hidden;text-overflow:ellipsis}
 .enf{color:#9fb4cc}
 .inc{color:#c9a0ff}
 .led{color:#6f8296}
 .ver.ok{color:#7fe0a8}
 .ver.div{color:#ff8ea3;font-weight:bold}
 .tdetail{padding:8px 12px;font-size:11px;color:#9fb0c4;border-top:1px solid #17222f;line-height:1.8}
 .tdetail b{color:#7fb4d0}
 .tamper{color:#ff8ea3;font-weight:bold}
</style></head><body>
<header id="hdr"></header>
<div class="legend">
 <span><span class="sw" style="background:#ff5470"></span>위험(Red)</span>
 <span><span class="sw" style="background:#ffb454"></span>주의(Yellow)</span>
 <span><span class="sw" style="background:#3ecf8e"></span>평시(Green)</span>
 <span><span class="sw" style="background:#ff8ea3"></span>에이전트≠진실 불일치</span>
 <span class="muted">· 묶음/행 클릭 시 펼침 · 3초 실시간 자동갱신</span>
</div>
<div id="body"></div>
<script>
const TOKEN=new URLSearchParams(location.search).get('token')||'';
const H={headers:{'Authorization':'Bearer '+TOKEN}};
const openBatches=new Set(), openTicks=new Set(), seenBatch=new Set();
let firstLoad=true;
const BANDLBL={Red:'🔴 위험',Yellow:'🟡 주의',Green:'🟢 평시'};
function esc(s){return String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function riskOf(a,v){
 if(a.impact_band==='Red'||(v&&v.agent_truth_divergence))return 'danger';
 if(a.impact_band==='Yellow')return 'warn';
 return 'ok';
}
function tickRow(t){
 const a=t.a, v=t.v||{}, c=t.c||{telemetry:[]};
 const band=a.impact_band||'unknown';
 const open=openTicks.has(a.tick)?' open':'';
 const ver=v.agent_truth_divergence?'<span class="ver div">⚠ 불일치</span>':'<span class="ver ok">✓ 일치</span>';
 const tele=(c.telemetry||[]);
 const teleHtml=tele.length?tele.map(e=>esc(e.metric)+'=<b>'+esc(e.value)+'</b> ['+esc(e.band)+'] ('+esc(e.source_id)+')'+(e.tamper?' <span class="tamper">TAMPER</span>':'')).join(' · '):'없음';
 const det='<div class="tdetail">'
   +'<div><b>노드</b> '+((a.nodes||[]).map(esc).join(' → ')||'—')+'</div>'
   +'<div><b>검증</b> 진실판정='+esc(v.truth_verdict)+' · 텔레메트리생존='+esc(v.telemetry_alive)+' · GCS프록시='+esc(v.gcs_proxy_alive)+' · 교차루트='+esc(v.cross_root_consistent)+' · 침묵연속='+esc(v.silence_streak)+(v.reason?(' · 사유: '+esc(v.reason)):'')+'</div>'
   +'<div><b>통신</b> '+teleHtml+'</div></div>';
 return '<details class="trow risk-'+riskOf(a,v)+'" data-tick="'+a.tick+'"'+open+'>'
   +'<summary><span class="arrow">▸</span><span class="tk">#'+a.tick+'</span>'
   +'<span class="badge b-'+band+'">'+(BANDLBL[band]||'⚪ ?')+'</span>'
   +'<span class="dec">'+(esc(a.decision)||'<span class="muted">결정 없음</span>')+'</span>'
   +'<span class="enf">집행:'+(esc(a.enforcement)||'—')+'</span>'
   +'<span class="inc">사건 '+esc(a.incidents)+'</span>'
   +'<span class="led">원장 '+esc(a.ledger)+'</span>'
   +ver+'</summary>'+det+'</details>';
}
function batchBlock(id,list){
 const reds=list.filter(t=>t.a.impact_band==='Red').length;
 const ambs=list.filter(t=>t.a.impact_band==='Yellow').length;
 const divs=list.filter(t=>t.v&&t.v.agent_truth_divergence).length;
 let ind='';
 if(reds)ind+='<span class="chip red">🔴 위험 '+reds+'</span>';
 if(ambs)ind+='<span class="chip amber">🟡 주의 '+ambs+'</span>';
 if(divs)ind+='<span class="chip red">⚠ 불일치 '+divs+'</span>';
 if(!ind)ind='<span class="chip green">🟢 평시</span>';
 const open=openBatches.has(id)?' open':'';
 return '<details class="batch" data-batch="'+id+'"'+open+'>'
  +'<summary><span class="arrow">▸</span><b>틱 '+(id*10)+'–'+(id*10+9)+'</b>'
  +'<span class="muted">('+list.length+'개)</span>'+ind+'</summary>'
  +'<div class="brows">'+list.map(tickRow).join('')+'</div></details>';
}
function render(d){
 const A=d.panels.action||[], C=d.panels.communication||[], Vv=d.panels.verification||[];
 const cmap={},vmap={}; C.forEach(c=>cmap[c.tick]=c); Vv.forEach(x=>vmap[x.tick]=x);
 const ticks=A.map(a=>({a:a,c:cmap[a.tick],v:vmap[a.tick]}));
 const total=A.length, reds=A.filter(a=>a.impact_band==='Red').length;
 const divs=(d.banner&&d.banner.divergences!=null)?d.banner.divergences:Vv.filter(v=>v.agent_truth_divergence).length;
 const last=A.length?A[A.length-1]:null;
 const byBatch=new Map();
 ticks.forEach(t=>{const id=Math.floor(t.a.tick/10); if(!byBatch.has(id))byBatch.set(id,[]); byBatch.get(id).push(t);});
 const ids=[...byBatch.keys()].sort((x,y)=>y-x);      // 최신 묶음 위로
 const maxId=ids.length?ids[0]:0;
 ids.forEach(id=>{ if(!seenBatch.has(id)){ seenBatch.add(id); if(id===maxId) openBatches.add(id);} });  // 새 최신묶음 자동펼침
 if(firstLoad){ if(ids.length) openBatches.add(maxId); firstLoad=false; }
 ids.forEach(id=>byBatch.get(id).sort((p,q)=>q.a.tick-p.a.tick));   // 묶음 내부도 최신 위로
 document.getElementById('hdr').innerHTML=
   '<h1>MDG 방어 로그 뷰어 · 실시간</h1>'
  +'<span class="chip"><b>총 틱</b> '+total+'</span>'
  +'<span class="chip '+(reds?'red':'green')+'">🔴 위험(Red) <b>'+reds+'</b></span>'
  +'<span class="chip '+(divs?'red':'green')+'">⚠ 불일치 <b>'+divs+'</b></span>'
  +'<span class="chip"><b>최종</b> '+(last?(esc(last.decision||'—')+' / '+esc(last.impact_band)):'—')+'</span>'
  +'<span class="muted">갱신 '+new Date().toLocaleTimeString('ko-KR')+' · 읽기전용 · 기록시점 마스킹 on · 신뢰근원 '+esc((d.banner&&d.banner.trust_root)||'mdg.verifier')+'</span>';
 document.getElementById('body').innerHTML= ids.length? ids.map(id=>batchBlock(id,byBatch.get(id))).join('') : '<div class="muted">로그 없음 — 감시(monitor) 실행을 확인하세요.</div>';
 document.querySelectorAll('details.batch').forEach(el=>el.addEventListener('toggle',()=>{const id=+el.dataset.batch; el.open?openBatches.add(id):openBatches.delete(id);}));
 document.querySelectorAll('details.trow').forEach(el=>el.addEventListener('toggle',()=>{const tk=+el.dataset.tick; el.open?openTicks.add(tk):openTicks.delete(tk);}));
}
function load(){
 fetch('api/panels',H).then(r=>r.json()).then(d=>{
  if(d.detail){document.getElementById('hdr').innerHTML='<h1>오류</h1>';document.getElementById('body').innerHTML='<div class="chip red">'+esc(d.detail)+'</div>';return;}
  render(d);
 }).catch(e=>{document.getElementById('hdr').innerHTML='<h1>연결 오류</h1>';document.getElementById('body').innerHTML='<div class="muted">'+esc(e)+' — 감시/뷰어 실행을 확인하세요.</div>';});
}
load(); setInterval(load, 3000);   // ★ 3초마다 실시간 자동 갱신 (run.jsonl 성장 반영, 펼침 상태 유지)
</script></body></html>"""


# --------------------------------------------------------------------------- #
# FastAPI app (lazy import) — read-only, bearer-auth, loopback bind
# --------------------------------------------------------------------------- #
def create_app(run_path: str, *, token: Optional[str] = None):
    """Build the read-only FastAPI app. ``token`` (bearer) is required for data routes;
    if None, a token is read from env ``MDG_VIEWER_TOKEN`` (no token => all data routes 401).

    Panels are recomputed per request from ``run_path`` (offline, deterministic). Requires
    fastapi (python:3.12-slim image). Raises ImportError otherwise; the pure builders
    (load_panels / scan_secrets) work without it."""
    try:
        import os
        from fastapi import FastAPI, Header, HTTPException
        from fastapi.responses import HTMLResponse, JSONResponse
    except Exception as exc:  # pragma: no cover
        raise ImportError(
            "fastapi/uvicorn required to serve the Viewer (pip install -r requirements.txt). "
            "Pure builders load_panels()/scan_secrets() work without a web stack."
        ) from exc

    tok = token if token is not None else os.environ.get("MDG_VIEWER_TOKEN", "")

    def _auth(authorization: Optional[str]) -> None:
        # constant-time bearer compare (PS-8). Empty configured token => deny all (no anon).
        presented = ""
        if authorization and authorization.lower().startswith("bearer "):
            presented = authorization[7:].strip()
        if not tok or not hmac.compare_digest(presented, tok):
            raise HTTPException(status_code=401, detail="unauthorized (bearer token required)")

    app = FastAPI(title="MDG Replay Viewer", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    def index() -> Any:  # the shell itself carries no data (data routes are authed)
        return HTMLResponse(_HTML)

    @app.get("/api/panels")
    def api_panels(authorization: Optional[str] = Header(default=None)) -> Any:
        _auth(authorization)
        try:
            return JSONResponse(load_panels(run_path))
        except SecretLeakError as exc:
            # fail-closed: never serve a tainted file, never silently redact at display time
            raise HTTPException(status_code=409, detail=str(exc))
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"no run.jsonl at {run_path}")

    @app.get("/api/health")
    def api_health(authorization: Optional[str] = Header(default=None)) -> Any:
        _auth(authorization)
        return {"ok": True, "read_only": True, "trust_root": "mdg.verifier"}

    return app


def serve(run_path: str, *, host: str = "127.0.0.1", port: int = 8787,
          token: Optional[str] = None) -> None:
    """Run the Viewer under uvicorn, bound to loopback/management ONLY (PS-8). Refuses to
    bind 0.0.0.0 / a wildcard so an attacker UE (10.45.x) can never reach the mgmt plane."""
    h = (host or "").strip()
    if h in ("0.0.0.0", "::", "") or h.endswith(".0.0.0.0"):
        raise ValueError(f"refusing non-loopback bind '{host}' (PS-8: loopback/mgmt only)")
    if h not in _LOOPBACK_HOSTS and not (h.startswith("10.") or h.startswith("172.") or h.startswith("192.168.")):
        # allow a private management-net address; reject public binds
        raise ValueError(f"refusing public bind '{host}' (PS-8: loopback/mgmt-net only)")
    try:
        import uvicorn
    except Exception as exc:  # pragma: no cover
        raise ImportError("uvicorn required to serve (pip install -r requirements.txt)") from exc
    uvicorn.run(create_app(run_path, token=token), host=h, port=port, log_level="warning")


def main(argv: Optional[list[str]] = None) -> int:
    import sys
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: python -m mdg.viewer.app <run.jsonl> [--host 127.0.0.1] [--port 8787]")
        return 2
    run_path = argv[0]
    host, port = "127.0.0.1", 8787
    if "--host" in argv:
        host = argv[argv.index("--host") + 1]
    if "--port" in argv:
        port = int(argv[argv.index("--port") + 1])
    serve(run_path, host=host, port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
