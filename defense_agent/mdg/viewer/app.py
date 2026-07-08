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
# 상시(구조적) 취약점 분류 — PRESENTATION ONLY (탐지 엔진·run.jsonl·Verifier 불변)
# --------------------------------------------------------------------------- #
# 테스트베드 환경 자체의 조건(고치지 않으면 상존): 로그/위험밴드 산정에서 분리하고
# 우측 "취약 노드 상태"로만 표시한다. 이건 순수 표현계층 필터이며 코어 탐지 출력은 그대로다
# (run.jsonl 원본에는 모든 incident 가 기록되고, Verifier 진실판정도 무관하게 동작).
STANDING_SIGNALS = {
    "Unauthorized_Command": {
        "node": "업링크 서명 (uav_proxy)", "kind": "unsigned_uplink",
        "detail": "signing=unknown — 미서명 MAVLink 명령이 통과(§9-B 서명 미확정). "
                  "테스트베드에서 서명 강제(드롭로그 생성)해야 해소.",
    },
    "Port_5762_State": {
        "node": "SITL 5762 백도어", "kind": "sitl_backdoor",
        "detail": "5762 시리얼 노출(LISTEN 0.0.0.0:5762) — ARIA/서명 우회 직결 가능. "
                  "테스트베드에서 포트 차단해야 해소.",
    },
    "BACKDOOR_5762": {
        "node": "SITL 5762 백도어", "kind": "sitl_backdoor",
        "detail": "5762 백도어 프로브 탐지 — 노출 상태 지속.",
    },
    "Port_5762_Probe": {
        "node": "SITL 5762 백도어", "kind": "sitl_backdoor",
        "detail": "5762 백도어 프로브 탐지 — 노출 상태 지속.",
    },
}
# 주의(Yellow)로 볼 저심각(정찰/열화) 공격 시그니처. 그 외 비-상시 시그니처는 위험(Red).
WARN_SIGNALS = {"Recon", "Port_Scan", "Telemetry_Degraded", "GPS_Jitter", "Rogue_Probe"}


def _classify_view(signals: list[str]) -> tuple[list[str], str]:
    """표현계층 재분류: 상시 시그니처를 제외한 '공격 시그니처'와 로그용 밴드(위험/주의/평시).

    상시(구조적) 조건만 있는 틱 → 평시(Green): 로그 타임라인이 신규 공격만 부각하도록.
    비-상시 시그니처가 있으면 → 저심각(WARN)만이면 주의(Yellow), 그 외/미지 → 위험(Red, fail-alert)."""
    attack = [s for s in signals if s not in STANDING_SIGNALS]
    if not attack:
        return attack, "Green"
    if all(s in WARN_SIGNALS for s in attack):
        return attack, "Yellow"
    return attack, "Red"


def _detect_band(signals: list[str]) -> str:
    """복구(recovery) lifecycle 전용 '탐지 밴드'. `_classify_view`(로그용)와 달리 상시(구조적)
    시그니처를 제외하지 **않는다**.

    이유: command-hijack / 5762-LAND 의 실제 공격 서명은 config 지표(Unauthorized_Command,
    Port_5762_State)이며 이는 STANDING_SIGNALS 에 속한다. view_band 는 이들을 걷어내 Green 으로
    보이므로, 그 값으로 복구 카드를 그리면 실제 비행 하이재킹 틱이 '밴드 Green→Green'(공격 없음)
    으로 렌더된다. 복구 서사(탐지→…→회복)는 상시 시그니처를 포함한 밴드로 판정해야 한다.
    상시/일반 구분 없이: 시그니처 없음→평시, 저심각(WARN)만→주의, 그 외→위험."""
    if not signals:
        return "Green"
    if all(s in WARN_SIGNALS for s in signals):
        return "Yellow"
    return "Red"


def _recovery_band(row: dict) -> str:
    """복구 lifecycle 밴드: 엔진의 권위있는 per-tick `impact_band`(Green/Yellow/Red)를 우선 사용하고,
    미기록/비정상 값이면 상시 시그니처를 포함한 `_detect_band`(사건 존재 기반)로 폴백한다.
    view_band(상시 제외, 로그 전용)는 여기서 쓰지 않는다."""
    ib = row.get("impact_band")
    if ib in ("Red", "Yellow", "Green"):
        return ib
    return _detect_band(row.get("signals") or [])


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


# --------------------------------------------------------------------------- #
# Phase 7 — 복구 타임라인 + 비행상태 (recovery lifecycle / flight state) builders
# --------------------------------------------------------------------------- #
# PRESENTATION ONLY: derived purely from the already-recorded ledger(Intent)/worldstate.applied/
# view_band transitions + 14560 rel_alt/flight_mode telemetry rows. No re-execution, no testbed,
# deterministic — reuses the same run.jsonl the 3-panel view consumes (H-J portability pillar).
_FLIGHT_TARGET_ALT = 30.0                       # S2 복귀 목표 고도(m) — 스파크라인 기준선
_RECOVERY_STEPS = (("detect", "탐지"), ("respond", "대응"),
                   ("enforce", "집행"), ("confirm", "확인"), ("recover", "회복"))
# send_signed_mode(S2 물리 복귀)만의 메커니즘 주석: 자율 랭킹은 가역 봉쇄를 항상 위로 두어 서명복귀를
# 선택하지 않으므로 respond=운영자 명시선택(operator-select), enforce=키 보유 gcs_c2 위임 발행,
# confirm=하강중 30m 대역 통과가 아닌 rel_alt 30m 정착 관측. PRESENTATION ONLY(밴드/집행 판정 불변).
_SIGNED_TOOLS = {"send_signed_mode"}
_SIGNED_STEP_NOTES = {"respond": "operator-select", "enforce": "gcs_c2 위임", "confirm": "rel_alt 30m"}


def _is_signed_recovery(tool: str, rule: str) -> bool:
    """True for the S2 signed-mode physical-return recovery (send_signed_mode / signed_* rule)."""
    return tool in _SIGNED_TOOLS or str(rule or "").startswith("signed")


def _flight_series(comm_panel: list[dict]) -> list[dict]:
    """Per-tick flight state (rel_alt/flight_mode) from the 14560 telemetry rows already
    folded into the communication panel. Ticks with neither metric are omitted."""
    series: list[dict] = []
    for c in comm_panel:
        alt = None
        mode = None
        for row in (c.get("telemetry") or []):
            m = row.get("metric")
            if m == "rel_alt":
                v = row.get("value")
                try:
                    alt = float(v)
                except (TypeError, ValueError):
                    alt = v
            elif m == "flight_mode":
                mode = row.get("value")
        if alt is not None or mode is not None:
            series.append({"tick": c.get("tick"), "rel_alt": alt, "flight_mode": mode})
    return series


def _recovery_events(ticks: list, band_by_tick: dict, flight: list[dict]) -> list[dict]:
    """Group ledger(Intent) + worldstate.applied[rule].confirmed + detection-band transitions into
    per-incident recovery lifecycles: 탐지→대응→집행→확인→회복. One event per recovery ``rule``.

    ``band_by_tick`` here is the recovery detection band (engine impact_band / incident presence,
    built by ``_recovery_band``), NOT the standing-filtered view_band — so a command-hijack /
    5762-LAND whose incident members are STANDING config metrics still shows an attack band.

    detect = first non-Green tick (attack visible); respond = first ledger Intent for the rule;
    enforce = first EXECUTED Intent (operator_gate falsy — an operator_auto-widened OPER tool
    executes here); confirm = first tick worldstate.applied[rule].confirmed; recover = first Green
    tick after enforcement (band returned to 평시). Pure/deterministic."""
    alt_by_tick = {f["tick"]: f["rel_alt"] for f in flight if f.get("rel_alt") is not None}
    detect_global = None
    for t in ticks:
        if band_by_tick.get(t.index, "Green") != "Green":
            detect_global = t.index
            break

    events: dict[str, dict] = {}
    order: list[str] = []

    def _ev(rule: str) -> dict:
        ev = events.get(rule)
        if ev is None:
            ev = {"rule": rule, "tool": rule, "revert_cmd": "", "first_tick": None,
                  "enforce_tick": None, "confirm_tick": None,
                  "operator_auto_confirmed": False, "deferred": False,
                  "provenance_relaxed": False}
            events[rule] = ev
            order.append(rule)
        return ev

    for t in ticks:
        for intent in (t.ledger or []):
            if not isinstance(intent, dict):
                continue
            rule = intent.get("rule") or intent.get("recovery_type") or intent.get("tool_id")
            if not rule:
                continue
            ev = _ev(rule)
            if ev["first_tick"] is None:
                ev["first_tick"] = t.index
            if intent.get("tool_id"):
                ev["tool"] = intent.get("tool_id")
            if intent.get("revert_cmd"):
                ev["revert_cmd"] = intent.get("revert_cmd")
            if intent.get("operator_auto_confirmed"):
                ev["operator_auto_confirmed"] = True
            if intent.get("provenance_relaxed"):
                ev["provenance_relaxed"] = True
            if not bool(intent.get("operator_gate")):
                if ev["enforce_tick"] is None:
                    ev["enforce_tick"] = t.index
            else:
                ev["deferred"] = True
        ws = t.worldstate if isinstance(t.worldstate, dict) else {}
        for rule, ap in (ws.get("applied") or {}).items():
            if not isinstance(ap, dict):
                continue
            ev = _ev(rule)
            if not ev["revert_cmd"] and ap.get("revert_cmd"):
                ev["revert_cmd"] = ap.get("revert_cmd")
            if ap.get("confirmed") and ev["confirm_tick"] is None:
                ev["confirm_tick"] = t.index

    last_tick = ticks[-1].index if ticks else None
    out: list[dict] = []
    for rule in order:
        ev = events[rule]
        first_tick = ev["first_tick"]
        enforce_tick = ev["enforce_tick"]
        confirm_tick = ev["confirm_tick"]
        enforced = enforce_tick is not None
        confirmed = confirm_tick is not None
        # detection = earliest visible attack tick, but never after this event first appeared
        detect_tick = detect_global
        if detect_tick is None or (first_tick is not None and detect_tick > first_tick):
            detect_tick = first_tick
        # recovery = first Green tick after enforcement (band returned to 평시)
        recover_tick = None
        base = enforce_tick if enforce_tick is not None else first_tick
        if base is not None:
            for t in ticks:
                if t.index > base and band_by_tick.get(t.index, "Green") == "Green":
                    recover_tick = t.index
                    break
        b_ref = detect_tick if detect_tick is not None else first_tick
        band_before = band_by_tick.get(b_ref, "Green")
        band_after = band_by_tick.get(
            recover_tick if recover_tick is not None else last_tick, band_before)
        alt_before = alt_by_tick.get(b_ref)
        alt_after = (alt_by_tick.get(recover_tick) if recover_tick is not None
                     else alt_by_tick.get(last_tick))
        if ev["operator_auto_confirmed"]:
            tier = "OPER→AUTO(sandbox)"
        elif enforced:
            tier = "AUTO"
        else:
            tier = "OPER(대기)"
        done = {"detect": detect_tick is not None, "respond": first_tick is not None,
                "enforce": enforced, "confirm": confirmed,
                "recover": (recover_tick is not None) or confirmed}
        tickmap = {"detect": detect_tick, "respond": first_tick, "enforce": enforce_tick,
                   "confirm": confirm_tick, "recover": recover_tick}
        signed = _is_signed_recovery(ev["tool"], rule)
        steps = []
        for k, lbl in _RECOVERY_STEPS:
            step = {"key": k, "label": lbl, "done": done[k], "tick": tickmap[k]}
            if k == "enforce":
                step["auto"] = ev["operator_auto_confirmed"]
            # S2 서명복귀 메커니즘 주석(대응=operator-select · 집행=gcs_c2 위임 · 확인=rel_alt 30m)
            if signed and k in _SIGNED_STEP_NOTES:
                step["note"] = _SIGNED_STEP_NOTES[k]
            steps.append(step)
        out.append({
            "rule": rule, "tool": ev["tool"], "tier": tier, "signed": signed,
            "revert_cmd": ev["revert_cmd"],
            "operator_auto_confirmed": ev["operator_auto_confirmed"],
            "provenance_relaxed": ev["provenance_relaxed"],
            "enforced": enforced, "confirmed": confirmed,
            "detect_tick": detect_tick, "enforce_tick": enforce_tick,
            "confirm_tick": confirm_tick, "recover_tick": recover_tick,
            "band_before": band_before, "band_after": band_after,
            "alt_before": alt_before, "alt_after": alt_after,
            "steps": steps,
        })
    return out


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
        # 이 틱을 위험으로 만든 실제 시그니처(distinct) — 뷰어가 "무엇이 위험한지" 전면 표시하도록 노출.
        # (중복 제거: correlate 가 동일 시그니처를 다수 누적해도 원인 종류만 보여준다.)
        signals = sorted({m for inc in (t.incidents or []) for m in (inc.get("members") or [])})
        attack_signals, view_band = _classify_view(signals)     # 상시조건 제외한 공격밴드(표현계층)
        action_panel.append({
            "tick": t.index, "tick_i": t.tick_i,
            "impact_band": (t.impact or {}).get("band"),        # 엔진 원출력(불변, 상세용)
            "impact_score": (t.impact or {}).get("score"),
            "view_band": view_band,                             # 로그 타임라인 색: 위험/주의/평시
            "decision": dec.get("decision") if dec else None,
            "enforcement": dec.get("enforcement") if dec else None,
            "incidents": len(t.incidents), "ledger": len(t.ledger),
            "signals": signals,                                 # 원본 시그니처 전체
            "attack_signals": attack_signals,                   # 상시조건 제외(로그에 표시)
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

    # 상시(구조적) 취약 노드 상태 — 우측 패널용. run 전체에서 관측된 상시 시그니처를 노드로 묶어
    # 활성/틱수/최근틱을 집계(로그가 아닌 '상태'). recent = 마지막 tick 에 존재하면 현재 활성.
    last_tick = action_panel[-1]["tick"] if action_panel else None
    nodes: dict[str, dict] = {}
    for row in action_panel:
        is_last = row["tick"] == last_tick
        for s in row["signals"]:
            meta = STANDING_SIGNALS.get(s)
            if not meta:
                continue
            n = nodes.setdefault(meta["node"], {
                "node": meta["node"], "kind": meta["kind"], "detail": meta["detail"],
                "signatures": set(), "ticks": 0, "active": False,
            })
            n["signatures"].add(s)
            n["ticks"] += 1
            if is_last:
                n["active"] = True
    standing = [
        {"node": n["node"], "kind": n["kind"], "detail": n["detail"],
         "signatures": sorted(n["signatures"]), "ticks": n["ticks"],
         # 마지막 틱에 없더라도 최근 관측이면 노출 유지(구조적 조건은 상존): active=마지막틱 존재
         "state": "노출/활성" if n["active"] else "관측됨(최근)"}
        for n in nodes.values()
    ]

    # Phase 7 — 복구 lifecycle + 비행상태(고도/모드) 시계열. 순수 파생(재실행 없음): 좌측 '복구 진행'
    # 카드 + 고도 스파크라인의 뷰모델. 기존 상시패널/view_band 와 공존(표현계층 추가일 뿐).
    flight = _flight_series(comm_panel)
    # 복구 lifecycle 밴드는 view_band(상시조건 제외, 로그 전용)가 아니라 엔진 impact_band(권위)
    # /사건 기반 탐지밴드를 쓴다 — 실제 공격 서명이 상시 시그니처(Unauthorized_Command/
    # Port_5762_State)인 command-hijack/5762-LAND 틱도 '탐지→회복' 서사가 성립하도록.
    band_by_tick = {row["tick"]: _recovery_band(row) for row in action_panel}
    recovery = {
        "events": _recovery_events(ticks, band_by_tick, flight),
        "flight": flight,
        "flight_target": _FLIGHT_TARGET_ALT,
    }

    return {
        # 헤더 메타(경고 문구 없음). 신뢰근원·불일치 수만 콤팩트 칩으로 노출.
        "banner": {
            "divergences": summary["agent_truth_divergences"],
            "trust_root": "mdg.verifier (out-of-graph, replay-only, deterministic)",
        },
        "summary": summary,
        "standing": standing,              # 우측 취약 노드 상태(상시조건 — 로그 아님)
        "recovery": recovery,              # 좌측 복구 진행 카드 + 고도 스파크라인(Phase 7)
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
 .dec{color:#e3ebf5;min-width:130px}
 .sigs{flex:1;display:flex;flex-wrap:wrap;gap:4px;align-items:center}
 .sig{background:#3a1420;border:1px solid #7a2b3e;color:#ffc0cc;font-size:10px;padding:1px 7px;border-radius:5px;white-space:nowrap}
 .sig b{color:#fff}
 .sig.calm{background:#10241b;border-color:#2e7d5b;color:#8fe6bf}
 .causes{flex-basis:100%;font-size:11px;color:#9fb0c4;margin-top:6px;display:flex;flex-wrap:wrap;gap:6px;align-items:center}
 .causes .lbl{color:#ff9fb0;font-weight:bold}
 .enf{color:#9fb4cc}
 .inc{color:#c9a0ff}
 .led{color:#6f8296}
 .ver.ok{color:#7fe0a8}
 .ver.div{color:#ff8ea3;font-weight:bold}
 .tdetail{padding:8px 12px;font-size:11px;color:#9fb0c4;border-top:1px solid #17222f;line-height:1.8}
 .tdetail b{color:#7fb4d0}
 .tamper{color:#ff8ea3;font-weight:bold}
 /* Phase 7 — 복구 진행 카드 + 비행 고도 스파크라인 */
 .recovery{margin-bottom:14px}
 .rgrid{display:flex;gap:12px;flex-wrap:wrap;align-items:stretch}
 .rcard{flex:1;min-width:260px;border:1px solid #23324a;border-radius:10px;background:#0e1420;padding:11px 13px}
 .rcard.flight{flex:0 0 300px}
 .rtitle{font-size:13px;color:#9fe7f2;margin-bottom:9px;font-weight:bold;display:flex;align-items:center;gap:7px;flex-wrap:wrap}
 .rtier{font-size:10px;color:#8fb0c8;border:1px solid #2b3a52;border-radius:5px;padding:1px 6px}
 .rsteps{display:flex;flex-wrap:wrap;align-items:center;gap:3px;font-size:12px}
 .rstep{padding:2px 9px;border-radius:6px;white-space:nowrap}
 .rstep.done{background:#10241b;border:1px solid #2e7d5b;color:#8fe6bf}
 .rstep.pending{background:#141c2b;border:1px solid #26364c;color:#6f8296}
 .rsep{color:#3f5168}
 .rtk{color:#7f8ea3;font-size:10px}
 .rauto{background:#1a2740;border:1px solid #3a5a8a;color:#9fc4f0;font-size:10px;padding:0 5px;border-radius:4px}
 .rnote{background:#14202e;border:1px solid #2b4a5e;color:#8fd0e0;font-size:9px;padding:0 5px;border-radius:4px;margin-left:2px}
 .ralt{background:#0f2a1e;border:1px solid #2f6b4a;color:#8fe7b8;font-size:10px;padding:0 5px;border-radius:4px}
 .rmeta{font-size:11px;color:#9fb0c4;margin-top:9px;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
 .spark{display:block;width:100%;height:66px;background:#0b111c;border-radius:6px;margin-bottom:5px}
 /* 2단 레이아웃: 좌=공격 로그 · 우=상시 취약 노드 상태 */
 .wrap{display:flex;gap:14px;align-items:flex-start}
 .main{flex:1;min-width:0}
 .aside{width:330px;flex-shrink:0;position:sticky;top:16px}
 .aside h3{font-size:12px;color:#9fd7e6;margin:0 0 8px;border-bottom:1px solid #1f2c3e;padding-bottom:6px}
 .vnode{border:1px solid #7a2b3e;border-left:4px solid #ff5470;background:#1b1013;border-radius:9px;padding:10px 12px;margin-bottom:9px}
 .vnode.calm{border-color:#2e7d5b;border-left-color:#3ecf8e;background:#0f1a17}
 .vnode .vt{font-size:13px;color:#ffd0d8;font-weight:bold;display:flex;justify-content:space-between;gap:8px}
 .vnode.calm .vt{color:#bfe9d4}
 .vnode .vstate{font-size:11px;color:#ff9fb0;margin-top:3px}
 .vnode.calm .vstate{color:#8fe6bf}
 .vnode .vdetail{font-size:11px;color:#9fb0c4;margin-top:6px;line-height:1.6}
 .vnode .vsig{font-size:10px;color:#c98fa0;margin-top:5px}
 @media(max-width:820px){.wrap{flex-direction:column}.aside{width:auto;position:static}}
</style></head><body>
<header id="hdr"></header>
<div class="legend">
 <span><span class="sw" style="background:#ff5470"></span>위험(Red)</span>
 <span><span class="sw" style="background:#ffb454"></span>주의(Yellow)</span>
 <span><span class="sw" style="background:#3ecf8e"></span>평시(Green)</span>
 <span><span class="sw" style="background:#ff8ea3"></span>에이전트≠진실 불일치</span>
 <span class="muted">· 좌=공격 트래픽 로그(상시조건 제외) · 우=상시 취약 노드 상태 · 묶음/행 클릭 시 펼침 · 3초 자동갱신</span>
</div>
<div id="recovery" class="recovery"></div>
<div class="wrap"><div id="body" class="main"></div><aside id="aside" class="aside"></aside></div>
<script>
const TOKEN=new URLSearchParams(location.search).get('token')||'';
const H={headers:{'Authorization':'Bearer '+TOKEN}};
const openBatches=new Set(), openTicks=new Set(), seenBatch=new Set();
let firstLoad=true;
const BANDLBL={Red:'🔴 위험',Yellow:'🟡 주의',Green:'🟢 평시'};
const RISK={Red:'danger',Yellow:'warn',Green:'ok'};
function esc(s){return String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function tickRow(t){
 const a=t.a, v=t.v||{}, c=t.c||{telemetry:[]};
 const vb=a.view_band||'Green';                          // 로그 밴드 = 상시조건 제외한 공격밴드
 const open=openTicks.has(a.tick)?' open':'';
 const ver=v.agent_truth_divergence?'<span class="ver div">⚠ 불일치</span>':'<span class="ver ok">✓ 일치</span>';
 const atk=(a.attack_signals||[]);
 const sigHtml=atk.length?('<span class="sigs">'+atk.map(s=>'<span class="sig">'+esc(s)+'</span>').join('')+'</span>')
                         :'<span class="sigs"><span class="sig calm">공격 시그니처 없음 · 평시</span></span>';
 const standingHere=(a.signals||[]).filter(s=>!atk.includes(s));
 const tele=(c.telemetry||[]);
 const teleHtml=tele.length?tele.map(e=>esc(e.metric)+'=<b>'+esc(e.value)+'</b> ['+esc(e.band)+'] ('+esc(e.source_id)+')'+(e.tamper?' <span class="tamper">TAMPER</span>':'')).join(' · '):'없음';
 const det='<div class="tdetail">'
   +'<div><b>결정</b> '+(esc(a.decision)||'—')+' · 집행:'+(esc(a.enforcement)||'—')+' · 사건 '+esc(a.incidents)+' · 원장 '+esc(a.ledger)+'</div>'
   +'<div><b>엔진 원출력</b> impact_band='+esc(a.impact_band)+' · score='+esc(a.impact_score)+' <span class="muted">(상시조건 포함 원값 — 로그밴드는 상시 제외)</span></div>'
   +(standingHere.length?('<div><b>상시조건</b> '+standingHere.map(esc).join(', ')+' <span class="muted">→ 우측 취약노드 상태로 분류</span></div>'):'')
   +'<div><b>노드</b> '+((a.nodes||[]).map(esc).join(' → ')||'—')+'</div>'
   +'<div><b>검증</b> 진실판정='+esc(v.truth_verdict)+' · 텔레메트리생존='+esc(v.telemetry_alive)+' · GCS프록시='+esc(v.gcs_proxy_alive)+' · 교차루트='+esc(v.cross_root_consistent)+' · 침묵연속='+esc(v.silence_streak)+(v.reason?(' · 사유: '+esc(v.reason)):'')+'</div>'
   +'<div><b>통신</b> '+teleHtml+'</div></div>';
 const risk=(v.agent_truth_divergence&&vb==='Green')?'warn':(RISK[vb]||'ok');
 return '<details class="trow risk-'+risk+'" data-tick="'+a.tick+'"'+open+'>'
   +'<summary><span class="arrow">▸</span><span class="tk">#'+a.tick+'</span>'
   +'<span class="badge b-'+vb+'">'+(BANDLBL[vb]||'⚪ ?')+'</span>'
   +sigHtml
   +'<span class="dec muted">'+(esc(a.decision)||'—')+'</span>'
   +ver+'</summary>'+det+'</details>';
}
function batchBlock(id,list){
 const reds=list.filter(t=>t.a.view_band==='Red').length;
 const ambs=list.filter(t=>t.a.view_band==='Yellow').length;
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
function renderStanding(standing){
 const el=document.getElementById('aside');
 let h='<h3>상시 취약 노드 상태</h3>';
 if(!standing||!standing.length){
  el.innerHTML=h+'<div class="vnode calm"><div class="vt"><span>🟢 취약 노드 없음</span></div><div class="vstate">관측된 상시 취약점 없음</div></div>';
  return;
 }
 for(const n of standing){
  h+='<div class="vnode"><div class="vt"><span>🔴 '+esc(n.node)+'</span><span class="muted">'+esc(n.ticks)+'틱</span></div>'
    +'<div class="vstate">상태: '+esc(n.state)+'</div>'
    +'<div class="vdetail">'+esc(n.detail)+'</div>'
    +'<div class="vsig">시그니처: '+((n.signatures||[]).map(esc).join(', ')||'—')+'</div></div>';
 }
 h+='<div class="muted" style="margin-top:6px">테스트베드 환경 자체의 상시 취약점 — 환경을 고쳐야 해소되며 좌측 공격 로그의 위험/주의/평시 산정에서는 제외됩니다.</div>';
 el.innerHTML=h;
}
function altSpark(flight,target){
 const pts=(flight||[]).filter(f=>f.rel_alt!=null);
 if(!pts.length)return '<div class="muted">비행 고도 데이터 없음(rel_alt 미관측)</div>';
 const w=280,h=66,pad=7;
 const xs=pts.map(p=>p.tick),ys=pts.map(p=>+p.rel_alt);
 const minT=Math.min.apply(null,xs),maxT=Math.max.apply(null,xs);
 let maxY=Math.max(target,Math.max.apply(null,ys)),minY=Math.min(0,Math.min.apply(null,ys));
 if(maxY<=minY)maxY=minY+1;
 const sx=t=>pad+(maxT===minT?0:(t-minT)/(maxT-minT))*(w-2*pad);
 const sy=y=>h-pad-(y-minY)/(maxY-minY)*(h-2*pad);
 const poly=pts.map(p=>sx(p.tick).toFixed(1)+','+sy(+p.rel_alt).toFixed(1)).join(' ');
 const ty=sy(target).toFixed(1);
 const last=pts[pts.length-1];
 return '<svg class="spark" viewBox="0 0 '+w+' '+h+'" preserveAspectRatio="none">'
   +'<line x1="'+pad+'" y1="'+ty+'" x2="'+(w-pad)+'" y2="'+ty+'" stroke="#3ecf8e" stroke-dasharray="3,3" stroke-width="1"/>'
   +'<polyline fill="none" stroke="#9fe7f2" stroke-width="1.7" points="'+poly+'"/>'
   +'<circle cx="'+sx(last.tick).toFixed(1)+'" cy="'+sy(+last.rel_alt).toFixed(1)+'" r="2.7" fill="#9fe7f2"/></svg>'
   +'<div class="muted">목표 '+target+'m · 최근 <b>'+(+last.rel_alt).toFixed(1)+'m</b>'
   +(last.flight_mode!=null?(' · 모드 '+esc(last.flight_mode)):'')+'</div>';
}
function renderRecovery(rec){
 const el=document.getElementById('recovery');
 if(!el)return;
 const evs=(rec&&rec.events)||[],flight=(rec&&rec.flight)||[];
 if(!evs.length&&!flight.length){el.innerHTML='';return;}
 let cards='';
 if(!evs.length){
  cards='<div class="rcard"><div class="rtitle">복구 진행</div>'
    +'<div class="muted">집행된 복구 없음 — 공격 집행(ledger) 대기 중</div></div>';
 }else{
  for(const e of evs){
   const steps=(e.steps||[]).map(s=>{
     const tk=(s.tick!=null)?(' <span class="rtk">#'+s.tick+'</span>'):'';
     const au=(s.key==='enforce'&&s.auto)?' <span class="rauto">auto</span>':'';
     const nt=s.note?(' <span class="rnote">'+esc(s.note)+'</span>'):'';   // 서명복귀 메커니즘 주석
     return '<span class="rstep '+(s.done?'done':'pending')+'">'+(s.done?'✓':'○')+' '+esc(s.label)+nt+au+tk+'</span>';
   }).join('<span class="rsep">→</span>');
   const band='<span class="badge b-'+(e.band_after||'Green')+'">'+(BANDLBL[e.band_after]||'⚪ ?')+'</span>';
   cards+='<div class="rcard"><div class="rtitle">복구 진행 · '+esc(e.tool)
     +' <span class="rtier">'+esc(e.tier)+'</span>'
     +(e.signed?' <span class="ralt">S2 물리 복귀 30m</span>':'')+'</div>'
     +'<div class="rsteps">'+steps+'</div>'
     +'<div class="rmeta">'+(e.band_before?('밴드 '+esc(e.band_before)+' → '):'')+band
     +((e.alt_after!=null)?(' · <span class="ralt">고도 '+((e.alt_before!=null)?(esc((+e.alt_before).toFixed(1))+'→'):'')+esc((+e.alt_after).toFixed(1))+'m'+((Math.abs((+e.alt_after)-30)<=5)?' ✓30m':'')+'</span>'):'')
     +(e.revert_cmd?(' · <span class="muted">revert: '+esc(e.revert_cmd)+'</span>'):'')
     +(e.provenance_relaxed?' · <span class="rauto">provenance_relaxed</span>':'')+'</div></div>';
  }
 }
 const alt='<div class="rcard flight"><div class="rtitle">비행 고도(30m 복귀)</div>'
   +altSpark(flight,(rec&&rec.flight_target)||30)+'</div>';
 el.innerHTML='<div class="rgrid">'+cards+alt+'</div>';
}
function render(d){
 const A=d.panels.action||[], C=d.panels.communication||[], Vv=d.panels.verification||[];
 const cmap={},vmap={}; C.forEach(c=>cmap[c.tick]=c); Vv.forEach(x=>vmap[x.tick]=x);
 const ticks=A.map(a=>({a:a,c:cmap[a.tick],v:vmap[a.tick]}));
 const total=A.length;
 const reds=A.filter(a=>a.view_band==='Red').length;
 const ambs=A.filter(a=>a.view_band==='Yellow').length;
 const calm=A.filter(a=>a.view_band==='Green').length;
 const divs=(d.banner&&d.banner.divergences!=null)?d.banner.divergences:Vv.filter(v=>v.agent_truth_divergence).length;
 const last=A.length?A[A.length-1]:null;
 // 공격 원인 집계(상시조건 제외한 attack_signals 만)
 const sigCount={};
 A.forEach(a=>(a.attack_signals||[]).forEach(s=>{sigCount[s]=(sigCount[s]||0)+1;}));
 const causes=Object.entries(sigCount).sort((x,y)=>y[1]-x[1]);
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
  +'<span class="chip '+(reds?'red':'green')+'">🔴 위험 <b>'+reds+'</b></span>'
  +'<span class="chip '+(ambs?'amber':'green')+'">🟡 주의 <b>'+ambs+'</b></span>'
  +'<span class="chip green">🟢 평시 <b>'+calm+'</b></span>'
  +'<span class="chip '+(divs?'red':'green')+'">⚠ 불일치 <b>'+divs+'</b></span>'
  +'<span class="chip"><b>최종</b> '+(last?(esc(last.decision||'—')+' / '+esc(last.view_band||last.impact_band)):'—')+'</span>'
  +'<span class="muted">갱신 '+new Date().toLocaleTimeString('ko-KR')+' · 읽기전용 · 신뢰근원 '+esc((d.banner&&d.banner.trust_root)||'mdg.verifier')+'</span>'
  +(causes.length?('<div class="causes"><span class="lbl">공격 원인</span>'+causes.map(c=>'<span class="sig">'+esc(c[0])+' <b>'+c[1]+'틱</b></span>').join('')+'</div>'):'<div class="causes"><span class="sig calm">공격 시그니처 없음 · 상시조건만(우측 상태 참조)</span></div>');
 document.getElementById('body').innerHTML= ids.length? ids.map(id=>batchBlock(id,byBatch.get(id))).join('') : '<div class="muted">로그 없음 — 감시(monitor) 실행을 확인하세요.</div>';
 renderRecovery(d.recovery);
 renderStanding(d.standing);
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
