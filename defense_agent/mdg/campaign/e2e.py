"""e2e.py (P6) — the 6-attack E2E campaign harness: replay -> detect -> respond -> verify.

Replays SIX demonstrated attacks through the REAL deterministic pipeline (the 11 node
functions + edges.py routing), records the canonical ``run.jsonl``, and folds each into an
``AttackOutcome`` (detection + response + independent Verifier truth).

LIVE EXECUTION IS operator-go RESERVED. Every actuation runs through ``Backend(allow_live=
False)`` -> DRY-RUN, and mis-targeted / unverified selectors are fail-closed inert-DRY
(PS-7). The harness performs NO testbed state change; it is code + scenarios + dry only.

Two invariants preserved:
  1. deterministic control flow — routing is edges.route_after_impact / route_after_decide
     (numeric/bool only); LLM nodes get None -> deterministic fallback (no network).
  2. leak-0 — the only actuation path is Backend.run (DRY here); the harness spawns nothing.

LANGGRAPH-FREE by design: the canonical graph is core/graph.py (langgraph), but the portable
replay pillar (H-J) is run.jsonl. This harness drives the SAME node functions through the SAME
edges in a langgraph-free ``_TickExecutor`` and records via the SAME canonical recorder
(replay.record.canonical_line) so the emitted run.jsonl is byte-identical in schema to the
production driver and is consumed unchanged by the Verifier / Viewer / artifacts. When langgraph
IS installed the production driver (core.driver.run_driver over core.graph.build_graph) produces
the identical record stream; this executor is the operator-go-safe, dependency-light path used
for the campaign and local self-verify.

Baseline note: each scenario seeds a small post-recon WorldState (role_verified / reach /
signing) standing in for what live recon + collectors would establish (operator-go). This
seeding never enables live actuation (Backend stays DRY); it only lets the legality gate admit
a candidate so the response SELECTION path is exercised. The dispatch stays inert-DRY because
the untrusted target selector never resolves to a verified two-endpoint binding.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional

from ..collector.ingest import (Keyring, SensorEnvelope, compute_hmac,
                                 envelope_to_ev, verify_envelope)
from ..config import defaults as D
from ..core import edges, topology
from ..core import gate as gate_mod
from ..core.nodes import NODES
from ..core.state import Intent, MDGState, initial_state
from ..core.worldstate import RoleBinding, SigningObs, WorldState
from ..ledger.intent_ledger import SeqWatermark
from ..replay import record
from ..safe_exec.backend import Backend
from ..safe_exec.response import ResponseController
from ..verifier import verifier as V
from . import honest as H
from .artifacts import AttackOutcome, CampaignResult, build_verifier_truth

__all__ = [
    "AttackScenario", "ATTACKS", "run_scenario", "run_campaign",
    "DeterministicClock", "queue_from_batch",
]

_KID = "campaign-kid"
_KEY = b"campaign-hmac-key-not-a-secret-32byte!!"   # harness-local; NOT a real ingest key (dev/replay)


# --------------------------------------------------------------------------- #
# Deterministic clock (replay determinism; no time.* — PA-7)
# --------------------------------------------------------------------------- #
class DeterministicClock:
    """A fixed-base, step-incrementing clock. now() advances by ``step`` each call so a
    replayed campaign is byte-stable (no wall clock). sleep() is a no-op advance."""
    def __init__(self, base: float = 1_800_000_000.0, step: float = 0.001):
        self._t = float(base)
        self._step = float(step)

    def now(self) -> float:
        t = self._t
        self._t += self._step
        return t

    def sleep(self, seconds: float) -> None:
        self._t += float(seconds)


# --------------------------------------------------------------------------- #
# Envelope building (PS-2 ingest path exercised: HMAC + seq verified at drain)
# --------------------------------------------------------------------------- #
def _make_envelope(source_id: str, seq: int, ts: float, ev: dict) -> SensorEnvelope:
    """Build a signed SensorEnvelope carrying one evidence payload (metric/value/band/
    domain/channel/confidence). HMAC computed over the canonical body so ``sense``'s
    drain-time ``verify_envelope`` accepts it (PS-2)."""
    payload = {
        "metric": ev["metric"], "value": ev.get("value"),
        "band": ev.get("band", "normal"), "domain": ev.get("domain"),
        "channel": ev.get("channel", ""), "confidence": ev.get("confidence", 0.9),
    }
    env = SensorEnvelope(payload=payload, source_id=source_id, kid=_KID,
                         seq=seq, ts=ts, nonce=f"n{seq}")
    env.hmac = compute_hmac(env, _KEY)
    return env


def queue_from_batch(batch: list[dict], seq0: int, ts: float):
    """Turn one tick's evidence specs into a queue of signed envelopes for ``sense`` to
    drain. Returns (queue, next_seq)."""
    import queue as _q
    q: "_q.Queue" = _q.Queue()
    seq = seq0
    for ev in batch:
        sid = ev.get("source_id", "campaign_src")
        q.put(_make_envelope(sid, seq, ts, ev))
        seq += 1
    return q, seq


def _verify_fn(keyring: Keyring, seqwm: SeqWatermark):
    """Closure sense uses at drain: verify HMAC+seq, then project to a verified SensorEv."""
    def verify(env: SensorEnvelope):
        ok, reason = verify_envelope(env, keyring, seqwm)
        ev = envelope_to_ev(env, verified=ok)
        return ok, reason, ev
    return verify


# --------------------------------------------------------------------------- #
# Attack scenario definition
# --------------------------------------------------------------------------- #
@dataclass
class AttackScenario:
    id: str
    title: str
    description: str
    ticks: list[list[dict]]                 # per-tick list of evidence specs (drained by sense)
    verified_detection: bool = False        # live-grounded observation (D-1 telemetry / B-1 PFCP)
    seed_target_verified: bool = True       # seed role_verified["target"] so a candidate is legal
    seed_gcs_alive: bool = False            # seed role_verified["gcs_proxy"] (cross-root / silence)
    honest_keys: list[str] = field(default_factory=list)


def _baseline_world(scn: AttackScenario, cfg: str) -> WorldState:
    """Post-recon baseline standing in for live recon + collectors (operator-go).

    Seeds only closed predicates. Seeding the REAL enforcement-container keys admits the AUTO
    candidate through the legality gate WITHOUT enabling live actuation (Backend stays DRY;
    dispatch stays inert-DRY because the untrusted target selector never resolves to a verified
    two-endpoint binding — PS-7/P4-Q1). role_verified["gcs_proxy"] lets the Verifier evaluate the
    command root for cross-root / telemetry-silence scenarios."""
    reach = {t: True for t in D.INPUT_SPEC["reach_targets"]}   # collectors observed reach
    role_verified: dict[str, bool] = {}
    if scn.seed_target_verified:
        # legality now dynamically verifies role_verified[<action.enforce_at container>] (step 10),
        # so a fictional "target" alias no longer admits a candidate. Seed the actual enforcement
        # CONTAINER keys the recovery candidates resolve to (RECOVERY_PRIORS.enforce_at + default),
        # derived from config so no testbed literal is pinned here.
        for _spec in D.RECOVERY_PRIORS.values():
            _ea = str(_spec.get("enforce_at") or "")
            if _ea:
                role_verified[_ea] = True
        _dflt = str(D.RECOVERY_DEFAULT_ENFORCE_AT or "")
        if _dflt:
            role_verified[_dflt] = True
    if scn.seed_gcs_alive:
        role_verified["gcs_proxy"] = True
    return WorldState(
        config_version=cfg,
        reach=reach,
        signing=SigningObs.UNKNOWN,             # tri-state boot posture (P2-Q2; never judged OFF)
        threat={d: "none" for d in D.DOMAINS},
        role_verified=role_verified,
    )


# --------------------------------------------------------------------------- #
# The langgraph-free DRY tick interpreter (consumes the SINGLE core/topology spec)
# --------------------------------------------------------------------------- #
_ACCUMULATORS = ("ledger", "decisions", "incidents")

# name -> branch function (topology holds only the NAME; resolved here, same registry as graph.py)
_BRANCH = {
    "route_after_impact": edges.route_after_impact,
    "route_after_decide": edges.route_after_decide,
}


def _apply(state: MDGState, patch: dict) -> None:
    """Apply a node patch to ``state`` with LangGraph channel semantics: accumulator
    channels (ledger/decisions/incidents) extend (operator.add), everything else replaces."""
    for k, v in patch.items():
        if k in _ACCUMULATORS and isinstance(v, list):
            state[k] = list(state.get(k, [])) + v            # operator.add
        else:
            state[k] = v


class _TickExecutor:
    """A minimal deterministic interpreter of ``core.topology``: walk ENTRY -> (LINEAR |
    COND branch) -> END, calling the REAL node functions with deps bound from the ONE recipe
    (topology.BIND) and recording each patch via the canonical recorder. Because the node
    order, the branch points, and the DI binding all come from the same datum ``core.graph``
    compiles, this executor cannot drift from the production graph (PA-9). Actuation is DRY
    (Backend.allow_live=False); the interpreter spawns no subprocess (leak-0, 불변식2.)."""

    def __init__(self, deps: dict[str, Any]):
        self.deps = deps

    def _emit(self, fh, seq: int, state: MDGState, node: str, patch: dict) -> int:
        """Record the node patch (canonical, redacted) then merge it into state."""
        if fh is not None and isinstance(patch, dict):
            try:
                fh.write(record.canonical_line(seq, node, patch) + "\n")
            except Exception:
                pass
        _apply(state, patch)
        return seq + 1

    def _call(self, node: str, state: MDGState) -> dict:
        """Invoke one node with deps bound from topology.BIND (the ONE binding recipe)."""
        return NODES[node](state, **topology.kwargs_for(node, self.deps))

    def run_tick(self, state: MDGState, fh, seq: int) -> int:
        node = topology.ENTRY
        while node != topology.END:
            seq = self._emit(fh, seq, state, node, self._call(node, state))
            if node in topology.COND_EDGES:                  # numeric/bool routing only (불변식1.)
                fn_name, mapping = topology.COND_EDGES[node]
                node = mapping[_BRANCH[fn_name](state)]      # edges.route_* picks next node
            else:
                node = topology.LINEAR_EDGES[node]           # static successor (END-terminated)
        return seq


# --------------------------------------------------------------------------- #
# Response classification (pure re-plan for reporting — no side effect)
# --------------------------------------------------------------------------- #
def _classify_response(chosen: Optional[Intent], world: WorldState, risk: str,
                       reversible: bool, tick_i: int, route: str) -> dict:
    """Label the response outcome for the report (pure; re-plans with a DRY controller)."""
    if chosen is None:
        return {"rule": "", "tool": "", "tier": "NONE", "dispatch": "none", "revert_cmd": ""}
    if route == "escalate":
        return {"rule": chosen.rule, "tool": chosen.tool_id, "tier": "OPER",
                "dispatch": "escalated", "revert_cmd": chosen.revert_cmd}
    gd = gate_mod.gate_for(chosen.tool_id, risk, reversible)
    if gd.operator_required:
        return {"rule": chosen.rule, "tool": chosen.tool_id, "tier": "OPER",
                "dispatch": "operator_gate", "revert_cmd": chosen.revert_cmd}
    ctrl = ResponseController(backend=Backend(allow_live=False))
    plan = ctrl.plan(chosen, world, tick_i, risk=risk, reversible=reversible)
    if plan.skip:
        dispatch = "skip"
    elif plan.exec_request is None:
        dispatch = "inert_dry"                # target unresolved / not verified -> fail-closed
    else:
        dispatch = "dry_argv"                 # argv built but Backend DRY (operator-go for live)
    return {"rule": chosen.rule, "tool": chosen.tool_id, "tier": "AUTO",
            "dispatch": dispatch, "revert_cmd": plan.revert_cmd or chosen.revert_cmd}


# --------------------------------------------------------------------------- #
# Run one scenario
# --------------------------------------------------------------------------- #
def run_scenario(scn: AttackScenario, out_dir: str) -> AttackOutcome:
    """Replay one attack, record run.jsonl, and fold the outcome (detect/respond/verify)."""
    cfg = str(D.MISSION_PROFILE["config_version"])
    state: MDGState = initial_state(cfg)
    state["worldstate"] = _baseline_world(scn, cfg)

    keyring = Keyring(keys={_KID: _KEY})
    seqwm = SeqWatermark()                                   # in-memory (campaign is offline)
    clock = DeterministicClock()
    deps = {
        "verify": _verify_fn(keyring, seqwm),
        "clock": clock,
        "backend": Backend(allow_live=False),               # operator-go 유보 -> DRY
        "ledger": None,                                     # inline ledger channel (offline)
        "observe": None, "gate": None,
        "llm_orient": None, "llm_decide": None,             # deterministic fallback (no network)
        "source_domains": None,
    }
    execu = _TickExecutor(deps)

    run_dir = os.path.join(out_dir, scn.id)
    os.makedirs(run_dir, exist_ok=True)
    run_path = os.path.join(run_dir, "run.jsonl")

    seq = 0
    response_events: list[dict] = []
    env_seq = 0
    with open(run_path, "w", encoding="utf-8") as fh:
        for batch in scn.ticks:
            # enqueue this tick's signed envelopes, then drive exactly one tick
            ts = clock.now()
            q, env_seq = queue_from_batch(batch, env_seq, ts)
            deps["inbox"] = q
            tick_i_before = int(state.get("tick_i", 0))
            # Snapshot the PRE-tick world. act() applies its bundle to state["worldstate"]
            # in-tick (world.with_applied, even for an inert-DRY AUTO plan whose exec_request is
            # None), so re-planning the report label against the POST-tick world would find the
            # rule already-applied (applied_tick == this tick) and mislabel a genuine fail-closed
            # inert-DRY as a debounce 'skip', erasing the blast-radius/self-DoS meaning. The report
            # must reflect the decision THIS tick actually made against the world it saw; classify
            # on the pre-tick snapshot. Prior-tick applications persist in the snapshot, so a real
            # steady-state idempotent/debounce skip still labels 'skip'.
            world_before = state.get("worldstate")
            seq = execu.run_tick(state, fh, seq)

            # classify the response taken this tick (pure, for the report)
            chosen = state.get("chosen_action")
            route = "act"
            if chosen is None:
                route = "__end__"
            elif state.get("chosen_action_risk") == "HIGH":
                route = "escalate"
            evt = _classify_response(
                chosen, world_before or WorldState(),
                state.get("chosen_action_risk", "LOW"),
                state.get("chosen_action_reversible", True),
                int(state.get("tick_i", tick_i_before + 1)), route)
            evt["tick"] = tick_i_before
            response_events.append(evt)

    # ---- fold detection ---------------------------------------------------
    incidents = [i.model_dump() for i in state.get("incidents", [])]
    detected = bool(incidents)
    impact = state.get("impact")
    top_band = getattr(impact, "band", "Green")
    domains = sorted({str(e.get("domain")) for b in scn.ticks for e in b if e.get("domain")})

    # ---- fold response (first real response event) ------------------------
    responded_evt = next((e for e in response_events
                          if e["dispatch"] not in ("none", "skip")), None)
    if responded_evt is None:
        responded_evt = next((e for e in response_events if e["tier"] != "NONE"), None)
    resp = responded_evt or {"rule": "", "tool": "", "tier": "NONE",
                             "dispatch": "none", "revert_cmd": ""}
    responded = resp["dispatch"] not in ("none",)

    # ---- fold independent verification ------------------------------------
    vtruth = build_verifier_truth(run_path)
    truth_summary = vtruth.get("summary", {})
    divergences = int(truth_summary.get("agent_truth_divergences", 0))

    keys = scn.honest_keys or H.attack_honest_keys(scn.id)
    return AttackOutcome(
        attack_id=scn.id, title=scn.title, description=scn.description, run_path=run_path,
        detected=detected, verified_detection=scn.verified_detection,
        incidents=incidents, top_impact_band=top_band, domains_hit=domains,
        responded=responded, response_rule=resp["rule"], response_tool=resp["tool"],
        response_tier=resp["tier"], response_dispatch=resp["dispatch"],
        revert_cmd=resp["revert_cmd"], live_execution=False,        # operator-go 유보
        truth_summary=truth_summary, agent_truth_divergences=divergences,
        honest_keys=keys,
        notes=[H.LIMITATION_INDEX[k].title for k in keys if k in H.LIMITATION_INDEX],
    )


# --------------------------------------------------------------------------- #
# The 6 demonstrated attacks
# --------------------------------------------------------------------------- #
# evidence spec fields: metric / value / band / domain / channel / confidence / source_id
def _pfcp(band="danger", value=9):
    return {"metric": "PFCP_Delete_Attempt", "value": value, "band": band,
            "domain": "session_network", "channel": "prometheus_9090",
            "confidence": 0.90, "source_id": "col_net"}


def _unauth_cmd(band="danger", value=2):
    return {"metric": "Unauthorized_Command", "value": value, "band": band,
            "domain": "command", "channel": "plaintext_mavlink_tap",
            "confidence": 0.95, "source_id": "air_command_tap"}


def _port5762(band="danger"):
    return {"metric": "Port_5762_State", "value": "ESTAB_PRESENT", "band": band,
            "domain": "command", "channel": "port_5762_read",
            "confidence": 0.90, "source_id": "col_web"}


def _db_access(band="danger", value=3):
    return {"metric": "DB_Access", "value": value, "band": band,
            "domain": "identity_access", "channel": "mongo_conn_log",
            "confidence": 0.60, "source_id": "col_mongo"}


def _heartbeat():
    return {"metric": "Link_Heartbeat", "value": 1, "band": "normal",
            "domain": "communication", "channel": "plaintext_mavlink_tap",
            "confidence": 0.95, "source_id": "air_telemetry_tap"}


def _packet_loss(band="danger", value=100, confidence=0.95):
    return {"metric": "Packet_Loss", "value": value, "band": band,
            "domain": "communication", "channel": "plaintext_mavlink_tap",
            "confidence": confidence, "source_id": "air_telemetry_tap"}


ATTACKS: list[AttackScenario] = [
    AttackScenario(
        id="A1_command_hijack_cr01",
        title="명령채널 하이재킹 (CR01: PFCP 세션삭제 + 무인증 명령 + 5762 ESTAB)",
        description=(
            "공격자가 PFCP 세션을 강제해제하며 동시에 무인증 MAVLink 명령을 주입하고 5762 "
            "백도어 소켓이 ESTAB 된다. PFCP+Unauthorized_Command 시간창 상관 -> CR01 incident. "
            "command distrust≥71 -> criticality_floor 71 -> Red. 대응 pfcp_firewall/command_override "
            "선택(가역 AUTO는 DRY, 미검증 셀렉터는 inert-DRY)."
        ),
        ticks=[[_pfcp(), _unauth_cmd(), _port5762()],
               [_pfcp(), _unauth_cmd(), _port5762()]],
        verified_detection=False,               # command-plane(14556/5762) detection is unverified
        seed_target_verified=True,
    ),
    AttackScenario(
        id="A2_pfcp_teardown",
        title="PFCP 세션 강제해제 storm (s5c_rx_deletesession 카운터 diff)",
        description=(
            "SMF s5c_rx_deletesession 단조 카운터의 틱당 양의 diff로 다수 세션의 강제해제를 "
            "관측한다(음수 게이지 회피, B-1). 세션 전면 강제해제 -> session_network distrust≥71 "
            "-> criticality_floor 71 -> Red. 단일신호 -> backdoor_pause 후보. PFCP 카운터 diff는 "
            "라이브 read-only로 지상진실이 확보된 2개 관측 중 하나(verified detection)."
        ),
        ticks=[[_pfcp(value=9), _pfcp(value=17)],
               [_pfcp(value=25), _pfcp(value=33)]],
        verified_detection=True,                # PFCP counter diff (B-1) live-grounded
        seed_target_verified=True,
    ),
    AttackScenario(
        id="A3_unauth_command",
        title="무인증 MAVLink 명령 반복 주입 (gcs_proxy:14556)",
        description=(
            "gcs_proxy eth0 UDP:14556 진입 명령을 tcpdump 스니핑으로만 관측(2차 recvfrom 불가, "
            "idle baseline=0, B-3). 무인증 명령 반복 -> command distrust 40-70(floor 45, Yellow) "
            "— 단순 의심은 Red 자동확정 금지(P3-Q4). 14556 관측 정확성은 unit-test로 닫지 못하며"
            "(미검증), 유효서명 위조 명령(V4)은 아예 탐지 불가."
        ),
        ticks=[[_unauth_cmd(), _unauth_cmd(value=3)],
               [_unauth_cmd(value=4), _unauth_cmd(value=5)]],
        verified_detection=False,
        seed_target_verified=True,
    ),
    AttackScenario(
        id="A4_5762_backdoor",
        title="5762 백도어 명령경로 (ESTAB 관측·actuation blind)",
        description=(
            "web_backend 5762 LISTEN 소켓에 세션이 ESTAB 된다(Port_5762_State). WebProbe는 ss-only·"
            "pool=1이라 소켓 상태만 관측하고 그 위로 흐르는 무인증 명령은 blind(D-2 미배선). "
            "command Yellow -> backdoor_pause(web_backend) 후보. 실 actuation·차단 효력 미검증."
        ),
        ticks=[[_port5762()], [_port5762()]],
        verified_detection=False,
        seed_target_verified=True,
    ),
    AttackScenario(
        id="A5_mongo_dbaccess",
        title="Mongo subscriber-DB 무인증 접속 (id 22943, RAN CIDR)",
        description=(
            "epc_mongo stdout JSON id==22943(accepted) + attr.remote 10.44.x(RAN측=이상)로 "
            "무인증 DB 접속을 관측(mongo 로그파일 부재, docker logs stdout). identity_access "
            "distrust 상승 -> Yellow. 접속 로그 confidence 낮음(0.60), 대응 효력 미검증."
        ),
        ticks=[[_db_access(), _db_access(value=4)],
               [_db_access(), _db_access(value=5)]],
        verified_detection=False,
        seed_target_verified=True,
    ),
    AttackScenario(
        id="A6_telemetry_silence",
        title="텔레메트리 침묵/링크 상실 (agent≠truth 발산)",
        description=(
            "tick0 평문 HEARTBEAT(uav_ue lo:14550, D-1) 정상 -> 이후 탭은 돌지만 HEARTBEAT 소멸 "
            "(Packet_Loss, 링크 열화로 측정 신뢰도<0.5). E8 저신뢰 보수마진이 band를 Yellow로 1단 "
            "상향(단독 상향, PS-7)하나 legal 대응 부재로 agent는 Continue+Monitoring(nominal)에 "
            "머문다. 독립 Verifier는 SILENCE_TICKS 연속 무heartbeat -> TELEMETRY_SILENCE로 판정 -> "
            "agent≠truth 발산(H-K). telemetry 교차탭은 라이브 지상진실 2개 중 하나(verified). "
            "주: mission_weight(communication=30, floor 없음) 때문에 순수 링크손실은 impact 산식만"
            "으로는 Green을 넘지 못한다 — MISSION_WEIGHTED_DILUTION 한계의 실증."
        ),
        ticks=[[_heartbeat()],
               [_packet_loss(confidence=0.45)],
               [_packet_loss(confidence=0.45)]],
        verified_detection=True,                # telemetry cross-tap (D-1) live-grounded
        seed_target_verified=False,             # no legal response -> nominal decision -> divergence
        seed_gcs_alive=True,                    # command root present -> cross-root evaluable
    ),
]


# --------------------------------------------------------------------------- #
# Run the whole campaign
# --------------------------------------------------------------------------- #
def run_campaign(out_dir: str, scenarios: Optional[list[AttackScenario]] = None) -> CampaignResult:
    """Replay all 6 attacks into ``out_dir`` and return the CampaignResult (DRY, operator-go).

    Every attack writes ``<out_dir>/<attack_id>/run.jsonl``; artifacts.to_report rebuilds the
    6-chapter report purely from those records."""
    os.makedirs(out_dir, exist_ok=True)
    scns = scenarios if scenarios is not None else ATTACKS
    outcomes = [run_scenario(scn, out_dir) for scn in scns]
    return CampaignResult(outcomes=outcomes, out_dir=out_dir)


def main(argv: Optional[list[str]] = None) -> int:
    import json
    import sys
    from .artifacts import write_report_json
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass
    argv = list(sys.argv[1:] if argv is None else argv)
    out_dir = argv[0] if argv else os.path.join(os.getcwd(), "campaign_out")
    campaign = run_campaign(out_dir)
    report_path = os.path.join(out_dir, "report.json")
    write_report_json(campaign, report_path)

    roll = campaign.to_dict()["rollup"]
    print(H.campaign_disclaimer())
    print(json.dumps(roll, ensure_ascii=False))
    for o in campaign.outcomes:
        print(f"  {o.attack_id}: detected={o.detected} verified={o.verified_detection} "
              f"band={o.top_impact_band} resp={o.response_rule or '-'}/{o.response_tier}"
              f"({o.response_dispatch}) live={o.live_execution} "
              f"agent≠truth={o.agent_truth_divergences}")
    print(f"report -> {report_path}")
    # non-zero if any live execution slipped through (must be 0) — a hard invariant guard
    return 1 if campaign.live_execution_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
