"""app.py (V3 §8 · PS-8 · H-K) — FastAPI 3-panel replay Viewer.

Three panels (V3 §8):
  - 동작 (action)       : the agent's decision timeline, from run.jsonl (decisions channel)
  - 통신 (communication): 14560 downlink telemetry + uav_ue lo:14550 cross-tap heartbeats
  - 검증 (verification) : the INDEPENDENT Verifier's per-tick truth, side-by-side with the
                          agent's decision — the *agent ≠ truth* comparison (H-K)

Security posture (locked):
  * agent ≠ truth banner pinned at the top — the agent's decisions are NOT ground truth;
    the Verifier (a separate trust root) is authoritative for link health.
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
        "banner": {
            "text": "AGENT ≠ TRUTH — the agent's decisions are NOT ground truth; the "
                    "independent Verifier (separate trust root) is authoritative for link health.",
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
_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>MDG Replay Viewer</title>
<style>
 body{font-family:ui-monospace,Menlo,monospace;background:#0a0e15;color:#c7d3e0;margin:0;padding:18px}
 h1{font-size:15px;color:#9fe7f2;margin:0 0 8px}
 .banner{background:#3a1420;border:1px solid #7a2b3e;border-left:4px solid #ff5470;border-radius:8px;
   padding:12px 16px;margin-bottom:14px;color:#ffd0d8;font-size:13px}
 .banner b{color:#ff8ea3}
 .root{font-size:11px;color:#8fb8c9;margin-top:4px}
 .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
 .panel{background:#111826;border:1px solid #1f2c3e;border-radius:10px;padding:12px;overflow-x:auto}
 .panel h2{font-size:12px;color:#9fd7e6;margin:0 0 8px;border-bottom:1px solid #1f2c3e;padding-bottom:6px}
 table{border-collapse:collapse;width:100%;font-size:11px}
 td,th{border-bottom:1px solid #16202e;padding:4px 6px;text-align:left;white-space:nowrap}
 th{color:#6f8296}
 .div{color:#ff8ea3;font-weight:bold}
 .ok{color:#7fe0a8}.warn{color:#ffcf6f}.bad{color:#ff8ea3}
 @media(max-width:900px){.grid{grid-template-columns:1fr}}
</style></head><body>
<h1>MDG Replay Viewer — 3패널 (동작 · 통신 · 검증)</h1>
<div id="banner"></div>
<div class="grid">
 <div class="panel"><h2>① 동작 (decision JSONL)</h2><div id="p-action"></div></div>
 <div class="panel"><h2>② 통신 (14560/14550 telemetry)</h2><div id="p-comm"></div></div>
 <div class="panel"><h2>③ 검증 (Verifier 대조 · agent≠truth)</h2><div id="p-verify"></div></div>
</div>
<script>
const TOKEN=new URLSearchParams(location.search).get('token')||'';
const H={headers:{'Authorization':'Bearer '+TOKEN}};
function esc(s){return String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function tbl(rows,cols){let h='<table><tr>'+cols.map(c=>'<th>'+c+'</th>').join('')+'</tr>';
 for(const r of rows){h+='<tr>'+cols.map(c=>'<td>'+esc(r[c])+'</td>').join('')+'</tr>';}return h+'</table>';}
fetch('api/panels',H).then(r=>r.json()).then(d=>{
 if(d.detail){document.getElementById('banner').innerHTML='<div class="banner"><b>ERROR:</b> '+esc(d.detail)+'</div>';return;}
 document.getElementById('banner').innerHTML='<div class="banner"><b>⚠ '+esc(d.banner.text)+'</b>'
  +'<div class="root">trust root: '+esc(d.banner.trust_root)+' · agent≠truth divergences: '
  +'<span class="'+(d.banner.divergences?'bad':'ok')+'">'+d.banner.divergences+'</span>'
  +' · record-time redact: on · read-only</div></div>';
 document.getElementById('p-action').innerHTML=tbl(d.panels.action,['tick','impact_band','decision','enforcement','incidents','ledger']);
 const comm=[];for(const t of d.panels.communication){for(const e of t.telemetry){comm.push({tick:t.tick,metric:e.metric,value:e.value,band:e.band,src:e.source_id});}}
 document.getElementById('p-comm').innerHTML=comm.length?tbl(comm,['tick','metric','value','band','src']):'<i>no telemetry rows</i>';
 const vr=d.panels.verification.map(v=>({tick:v.tick,agent:v.agent_decision,truth:v.truth_verdict,'≠':v.agent_truth_divergence?'⚠':'',reason:v.reason}));
 document.getElementById('p-verify').innerHTML=tbl(vr,['tick','agent','truth','≠','reason']);
});
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
