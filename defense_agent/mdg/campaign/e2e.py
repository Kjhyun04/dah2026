"""e2e.py (P6) — 6개 공격 E2E 캠페인 하네스: replay -> detect -> respond -> verify.

시연된 6개 공격을 REAL 결정론 파이프라인(11개 노드 함수 + edges.py 라우팅)으로 재생하고,
정규 run.jsonl을 기록하며, 각각을 AttackOutcome(탐지 + 대응 + 독립 Verifier 진실)으로
접는다.

라이브 실행은 operator-go 유보다. 모든 actuation은 Backend(allow_live=
False) -> DRY-RUN으로 흐르고, 오조준/미검증 셀렉터는 fail-closed inert-DRY다
(PS-7). 하네스는 testbed 상태변경을 전혀 하지 않는다; 코드 + 시나리오 + dry뿐이다.

보존되는 2대 불변식:
  1. 결정론 제어흐름 — 라우팅은 edges.route_after_impact / route_after_decide
     (수치/불린만); LLM 노드는 None -> 결정론 폴백(네트워크 없음).
  2. 누수-0 — 유일한 actuation 경로는 Backend.run(여기선 DRY); 하네스는 아무것도 spawn하지 않는다.

설계상 LANGGRAPH-FREE: 정규 그래프는 core/graph.py(langgraph)이나, 이식 가능한 replay
기둥(H-J)은 run.jsonl이다. 이 하네스는 langgraph-free _TickExecutor에서 동일한 edges를 통해
동일한 노드 함수를 구동하고 동일한 정규 recorder(replay.record.canonical_line)로 기록하므로,
방출된 run.jsonl은 스키마상 프로덕션 드라이버와 바이트 동일하며 Verifier / Viewer / artifacts가
변경 없이 소비한다. langgraph가 설치된 경우 프로덕션 드라이버(core.graph.build_graph 위의
core.driver.run_driver)가 동일한 기록 스트림을 생성한다; 이 executor는 캠페인과 로컬 self-verify에
쓰이는 operator-go-safe·의존성 경량 경로다.

Baseline 주: 각 시나리오는 라이브 recon + collector가 확립할 것(operator-go)을 대신하는 작은
post-recon WorldState(role_verified / reach / signing)를 시드한다. 이 시딩은 라이브 actuation을
결코 활성화하지 않으며(Backend는 DRY 유지) 합법성 게이트가 후보를 admit해 대응 SELECTION 경로가
행사되게만 한다. 미신뢰 타깃 셀렉터가 검증된 두-엔드포인트 바인딩으로 풀리지 않으므로 dispatch는
inert-DRY로 유지된다.
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
_KEY = b"campaign-hmac-key-not-a-secret-32byte!!"   # 하네스 로컬; 실제 ingest 키 아님 (dev/replay)


# --------------------------------------------------------------------------- #
# 결정론 클록 (replay 결정성; time.* 미사용 — PA-7)
# --------------------------------------------------------------------------- #
class DeterministicClock:
    """고정 베이스·스텝 증가 클록. now()는 호출마다 step만큼 전진하므로 재생된
    캠페인이 바이트 안정적이다(월클록 없음). sleep()은 no-op 전진이다."""
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
# 봉투 생성 (PS-2 ingest 경로 행사: drain 시 HMAC + seq 검증)
# --------------------------------------------------------------------------- #
def _make_envelope(source_id: str, seq: int, ts: float, ev: dict) -> SensorEnvelope:
    """근거 payload 하나(metric/value/band/domain/channel/confidence)를 담은 서명된
    SensorEnvelope를 만든다. HMAC은 정규 body 위에서 계산되어 sense의 drain 시점
    verify_envelope가 이를 accept한다(PS-2)."""
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
    """한 틱의 근거 스펙을 sense가 drain할 서명된 봉투 큐로 변환한다.
    (queue, next_seq)를 반환한다."""
    import queue as _q
    q: "_q.Queue" = _q.Queue()
    seq = seq0
    for ev in batch:
        sid = ev.get("source_id", "campaign_src")
        q.put(_make_envelope(sid, seq, ts, ev))
        seq += 1
    return q, seq


def _verify_fn(keyring: Keyring, seqwm: SeqWatermark):
    """sense가 drain에서 쓰는 클로저: HMAC+seq 검증 후 검증된 SensorEv로 투영한다."""
    def verify(env: SensorEnvelope):
        ok, reason = verify_envelope(env, keyring, seqwm)
        ev = envelope_to_ev(env, verified=ok)
        return ok, reason, ev
    return verify


# --------------------------------------------------------------------------- #
# 공격 시나리오 정의
# --------------------------------------------------------------------------- #
@dataclass
class AttackScenario:
    id: str
    title: str
    description: str
    ticks: list[list[dict]]                 # 틱별 근거 스펙 리스트 (sense가 drain)
    verified_detection: bool = False        # 라이브 지상근거 관측 (D-1 telemetry / B-1 PFCP)
    seed_target_verified: bool = True       # role_verified["target"]를 시드해 후보가 합법이 되게
    seed_gcs_alive: bool = False            # role_verified["gcs_proxy"] 시드 (cross-root / silence)
    honest_keys: list[str] = field(default_factory=list)


def _baseline_world(scn: AttackScenario, cfg: str) -> WorldState:
    """라이브 recon + collector(operator-go)를 대신하는 post-recon 베이스라인.

    닫힌 술어만 시드한다. REAL enforcement-container 키를 시드하면 라이브 actuation을
    활성화하지 않고도 AUTO 후보가 합법성 게이트를 통과해 admit된다(Backend는 DRY 유지;
    미신뢰 타깃 셀렉터가 검증된 두-엔드포인트 바인딩으로 결코 풀리지 않아 dispatch는
    inert-DRY 유지 — PS-7/P4-Q1). role_verified["gcs_proxy"]는 Verifier가 cross-root /
    telemetry-silence 시나리오에서 명령 루트를 평가하게 한다."""
    reach = {t: True for t in D.INPUT_SPEC["reach_targets"]}   # collector가 관측한 reach
    role_verified: dict[str, bool] = {}
    if scn.seed_target_verified:
        # 합법성은 이제 role_verified[<action.enforce_at container>]를 동적으로 검증하므로(step 10),
        # 가상의 "target" 별칭은 더 이상 후보를 admit하지 않는다. recovery 후보가 풀리는 실제
        # enforcement CONTAINER 키(RECOVERY_PRIORS.enforce_at + default)를 시드한다.
        # config에서 파생하므로 여기에 testbed 리터럴을 고정하지 않는다.
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
        signing=SigningObs.UNKNOWN,             # tri-state 부팅 posture (P2-Q2; 결코 OFF로 판정 안 함)
        threat={d: "none" for d in D.DOMAINS},
        role_verified=role_verified,
    )


# --------------------------------------------------------------------------- #
# langgraph-free DRY 틱 인터프리터 (단일 core/topology 스펙을 소비)
# --------------------------------------------------------------------------- #
_ACCUMULATORS = ("ledger", "decisions", "incidents")

# name -> 분기 함수 (topology는 NAME만 보유; 여기서 해소, graph.py와 동일 레지스트리)
_BRANCH = {
    "route_after_impact": edges.route_after_impact,
    "route_after_decide": edges.route_after_decide,
}


def _apply(state: MDGState, patch: dict) -> None:
    """노드 patch를 LangGraph 채널 시맨틱으로 state에 적용한다: 누산 채널
    (ledger/decisions/incidents)은 extend(operator.add), 나머지는 모두 replace."""
    for k, v in patch.items():
        if k in _ACCUMULATORS and isinstance(v, list):
            state[k] = list(state.get(k, [])) + v            # operator.add
        else:
            state[k] = v


class _TickExecutor:
    """core.topology의 최소 결정론 인터프리터: ENTRY -> (LINEAR | COND 분기) -> END를
    걸으며, 단일 레시피(topology.BIND)에서 바인딩된 deps로 REAL 노드 함수를 호출하고 각
    patch를 정규 recorder로 기록한다. 노드 순서·분기점·DI 바인딩이 모두 core.graph가
    컴파일하는 동일 데이텀에서 오므로, 이 executor는 프로덕션 그래프에서 드리프트할 수
    없다(PA-9). Actuation은 DRY(Backend.allow_live=False); 인터프리터는 subprocess를
    spawn하지 않는다(누수-0, 불변식2.)."""

    def __init__(self, deps: dict[str, Any]):
        self.deps = deps

    def _emit(self, fh, seq: int, state: MDGState, node: str, patch: dict) -> int:
        """노드 patch를 기록(정규·편집)한 뒤 state에 병합한다."""
        if fh is not None and isinstance(patch, dict):
            try:
                fh.write(record.canonical_line(seq, node, patch) + "\n")
            except Exception:
                pass
        _apply(state, patch)
        return seq + 1

    def _call(self, node: str, state: MDGState) -> dict:
        """topology.BIND(단일 바인딩 레시피)에서 바인딩된 deps로 노드 하나를 호출한다."""
        return NODES[node](state, **topology.kwargs_for(node, self.deps))

    def run_tick(self, state: MDGState, fh, seq: int) -> int:
        node = topology.ENTRY
        while node != topology.END:
            seq = self._emit(fh, seq, state, node, self._call(node, state))
            if node in topology.COND_EDGES:                  # 수치/불린 라우팅만 (불변식1.)
                fn_name, mapping = topology.COND_EDGES[node]
                node = mapping[_BRANCH[fn_name](state)]      # edges.route_*가 다음 노드 선택
            else:
                node = topology.LINEAR_EDGES[node]           # 정적 후속자 (END로 종료)
        return seq


# --------------------------------------------------------------------------- #
# 대응 분류 (보고용 순수 re-plan — 부작용 없음)
# --------------------------------------------------------------------------- #
def _classify_response(chosen: Optional[Intent], world: WorldState, risk: str,
                       reversible: bool, tick_i: int, route: str) -> dict:
    """보고서용 대응 결과에 라벨을 붙인다(순수; DRY 컨트롤러로 re-plan)."""
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
        dispatch = "inert_dry"                # 타깃 미해소 / 미검증 -> fail-closed
    else:
        dispatch = "dry_argv"                 # argv 생성되나 Backend DRY (라이브는 operator-go)
    return {"rule": chosen.rule, "tool": chosen.tool_id, "tier": "AUTO",
            "dispatch": dispatch, "revert_cmd": plan.revert_cmd or chosen.revert_cmd}


# --------------------------------------------------------------------------- #
# 단일 시나리오 실행
# --------------------------------------------------------------------------- #
def run_scenario(scn: AttackScenario, out_dir: str) -> AttackOutcome:
    """공격 하나를 재생하고 run.jsonl을 기록해 결과(detect/respond/verify)를 접는다."""
    cfg = str(D.MISSION_PROFILE["config_version"])
    state: MDGState = initial_state(cfg)
    state["worldstate"] = _baseline_world(scn, cfg)

    keyring = Keyring(keys={_KID: _KEY})
    seqwm = SeqWatermark()                                   # 인메모리 (캠페인은 오프라인)
    clock = DeterministicClock()
    deps = {
        "verify": _verify_fn(keyring, seqwm),
        "clock": clock,
        "backend": Backend(allow_live=False),               # operator-go 유보 -> DRY
        "ledger": None,                                     # 인라인 ledger 채널 (오프라인)
        "observe": None, "gate": None,
        "llm_orient": None, "llm_decide": None,             # 결정론 폴백 (네트워크 없음)
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
            # 이 틱의 서명 봉투를 enqueue한 뒤 정확히 한 틱만 구동
            ts = clock.now()
            q, env_seq = queue_from_batch(batch, env_seq, ts)
            deps["inbox"] = q
            tick_i_before = int(state.get("tick_i", 0))
            # PRE-tick 월드를 스냅샷한다. act()는 틱 내에서 자신의 번들을 state["worldstate"]에
            # 적용하므로(world.with_applied, exec_request가 None인 inert-DRY AUTO 계획이라도),
            # POST-tick 월드에 대해 보고서 라벨을 re-plan하면 rule이 이미 적용된 것으로
            # (applied_tick == 이번 틱) 나타나 진짜 fail-closed inert-DRY를 debounce 'skip'으로
            # 오라벨해 blast-radius/self-DoS 의미를 지워버린다. 보고서는 이번 틱이 본 월드에
            # 대해 실제로 내린 결정을 반영해야 하므로 pre-tick 스냅샷으로 분류한다. 이전 틱의
            # 적용은 스냅샷에 남으므로, 진짜 정상상태 idempotent/debounce skip은 여전히 'skip'으로 라벨된다.
            world_before = state.get("worldstate")
            seq = execu.run_tick(state, fh, seq)

            # 이번 틱에 취한 대응을 분류(순수, 보고서용)
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

    # ---- 탐지 접기 ---------------------------------------------------
    incidents = [i.model_dump() for i in state.get("incidents", [])]
    detected = bool(incidents)
    impact = state.get("impact")
    top_band = getattr(impact, "band", "Green")
    domains = sorted({str(e.get("domain")) for b in scn.ticks for e in b if e.get("domain")})

    # ---- 대응 접기 (첫 실제 대응 이벤트) ------------------------
    responded_evt = next((e for e in response_events
                          if e["dispatch"] not in ("none", "skip")), None)
    if responded_evt is None:
        responded_evt = next((e for e in response_events if e["tier"] != "NONE"), None)
    resp = responded_evt or {"rule": "", "tool": "", "tier": "NONE",
                             "dispatch": "none", "revert_cmd": ""}
    responded = resp["dispatch"] not in ("none",)

    # ---- 독립 검증 접기 ------------------------------------
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
# 시연된 6개 공격
# --------------------------------------------------------------------------- #
# 근거 스펙 필드: metric / value / band / domain / channel / confidence / source_id
def _pfcp(band="danger", value=9):
    return {"metric": "PFCP_Delete_Attempt", "value": value, "band": band,
            "domain": "session_network", "channel": "prometheus_9090",
            "confidence": 0.90, "source_id": "col_net"}


def _unauth_cmd(band="danger", value=2):
    return {"metric": "Unauthorized_Command", "value": value, "band": band,
            "domain": "command", "channel": "plaintext_mavlink_tap",
            "confidence": 0.95, "source_id": "air_command_tap"}


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
        title="명령채널 하이재킹 (CR01: PFCP 세션삭제 + 무인증 명령)",
        description=(
            "공격자가 PFCP 세션을 강제해제하며 동시에 무인증 MAVLink 명령을 주입한다. "
            "PFCP+Unauthorized_Command 시간창 상관 -> CR01 incident. 대응 pfcp_firewall/"
            "command_override 선택(가역 AUTO는 DRY, 미검증 셀렉터는 inert-DRY)."
        ),
        ticks=[[_pfcp(), _unauth_cmd()],
               [_pfcp(), _unauth_cmd()]],
        verified_detection=False,               # command-plane(14556) 탐지는 미검증
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
        verified_detection=True,                # PFCP counter diff (B-1) 라이브 지상근거
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
        verified_detection=True,                # telemetry cross-tap (D-1) 라이브 지상근거
        seed_target_verified=False,             # 합법 대응 없음 -> nominal 결정 -> 발산
        seed_gcs_alive=True,                    # 명령 루트 존재 -> cross-root 평가 가능
    ),
]


# --------------------------------------------------------------------------- #
# 캠페인 전체 실행
# --------------------------------------------------------------------------- #
def run_campaign(out_dir: str, scenarios: Optional[list[AttackScenario]] = None) -> CampaignResult:
    """6개 공격을 모두 out_dir로 재생하고 CampaignResult를 반환한다(DRY, operator-go).

    각 공격은 <out_dir>/<attack_id>/run.jsonl을 기록한다; artifacts.to_report는 그
    기록들만으로 6장 보고서를 재구성한다."""
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
    # 라이브 실행이 하나라도 빠져나가면 non-zero(반드시 0) — 강한 불변식 가드
    return 1 if campaign.live_execution_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
