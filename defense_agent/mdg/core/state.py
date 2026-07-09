"""MDGState 채널 스키마 + 모든 pydantic v2 모델 (DESIGN_DECISIONS PA-3/PA-5).

MDGState 는 LangGraph 채널 reducer 를 가진 TypedDict:
  - accumulator 채널 (ledger/decisions/incidents) 은 operator.add 사용
  - 그 외 전부 LastValue (replace).

비밀값 (LLM key / operator token / HMAC key) 은 이 스키마에서 구조적으로 부재한다
(PS-3). verifier verdict 채널은 의도적으로 부재 (PA-2) — core 는 verdict 저장소를
import 할 수 없다. to_record() 는 recording hook 이 쓰는 allow-field 투영이다.
"""
from __future__ import annotations

import operator
from typing import Annotated, Literal, Optional, TypedDict

from pydantic import BaseModel, ConfigDict, Field, constr

from .worldstate import WorldState  # re-export: mdg.core.state.WorldState resolves

__all__ = [
    "MDGState", "WorldState", "TrustObj", "ImpactObj", "Intent", "Incident",
    "Decision", "SensorEv", "OrientNote", "DecideNote", "Action",
    "initial_state", "to_record",
]

Risk = Literal["LOW", "MED", "HIGH"]
Domain = Literal["communication", "identity_access", "session_network", "command", "mission"]


# --------------------------------------------------------------------------- #
# Evidence envelope 페이로드 (secret-free; hmac/kid 는 drain 시 검증, PS-2)
# --------------------------------------------------------------------------- #
class SensorEv(BaseModel):
    source_id: str
    kid: str = ""
    seq: int = 0
    ts: float = 0.0
    nonce: str = ""
    metric: str = ""                       # thresholds metric 이름 (또는 log 신호)
    value: object = None                   # numeric/enum 파생값 전용 (PS-7)
    band: str = "normal"                   # normal|warning|critical|danger
    domain: Optional[Domain] = None
    channel: str = ""                      # channel_quality 키
    source: str = ""                       # opaque attribution selector (ip/imsi/remote); DATA 전용, edge-invisible
    confidence: float = 0.9                # channel 사전값 (verdict 아님)
    verified: bool = False                 # HMAC/seq 는 drain 시 검증
    tamper: bool = False                   # provenance 게이트: merge/trust 에서 제외


# --------------------------------------------------------------------------- #
# Trust / Impact
# --------------------------------------------------------------------------- #
class TrustObj(BaseModel):
    domain: Domain
    trust_score: float = 100.0             # E5 idle -> 100
    trust_level: str = "very_high"
    confidence: float = 1.0                # 별도 필드 (E5/E8; impact 가 한 번 사용)
    reason: str = ""
    supporting: list[str] = Field(default_factory=list)
    conflicting: list[str] = Field(default_factory=list)


class ImpactObj(BaseModel):
    score: int = 0                         # 0-100, 높을수록 나쁨 (M5/M7)
    band: Literal["Green", "Yellow", "Red"] = "Green"
    confidence_margin: float = 0.0         # 한 번 적용되는 보수적 shift 크기 (E8)
    availability: int = 0
    integrity: int = 0
    safety: int = 0
    continuity: int = 0


# --------------------------------------------------------------------------- #
# Incident / Decision / Intent / Action
# --------------------------------------------------------------------------- #
class Incident(BaseModel):
    id: str
    kind: str                              # 예: CR01, tamper, single-signal
    score: float = 0.0
    containment_only_flag: bool = False    # V4 key-forgery = containment 전용
    members: list[str] = Field(default_factory=list)
    ts: float = 0.0
    target: str = ""                       # pivot target (imsi/ip/role)


class Action(BaseModel):
    """적법한 후보 응답 (closed registry tool + bound params)."""
    tool_id: str
    params: dict[str, object] = Field(default_factory=dict)
    risk: Risk = "LOW"
    reversible: bool = True
    recovery_type: str = ""


class Intent(BaseModel):
    """side effect 이전에 기록됨 (guard 밖) 하여 recover_on_boot 이 revert 가능 (G3)."""
    rule: str
    revert_cmd: str = ""
    ts: float = 0.0
    decision_id: str = ""
    config_version: str = ""
    tool_id: str = ""
    operator_gate: bool = False            # escalate 가 이들을 기록 (side-effect 0)
    # Phase 1 (sandbox demo) 감사 필드: operator_auto 로 실행된 OPER tool 은
    # operator_auto_confirmed=True + authority="sandbox-auto" 를 기록하여 감사자가
    # auto-confirmed OPER enforcement 를 native AUTO 와 구별할 수 있게 한다. 기본값은 다른 모든 경로를 온전히 유지.
    operator_auto_confirmed: bool = False
    authority: str = ""                    # "" | "sandbox-auto" | "operator-select" (누가 승인)
    # Phase 2 (PS-7/B3, sandbox demo): injected-high-severity provenance/debounce 게이트가
    # operator_auto 하에서 RELAX (record-then-pass) 되면, rank_recovery 가 provenance_relaxed=True 를 찍어
    # ledger/trace 가 엄격한 trusted-source hold 이 demo 를 위해 면제되었음을 투명하게
    # 기록한다. Production (operator_auto off) 에선 False 유지 — 엄격 자세는 relax 되지 않았으므로
    # 기록되지 않음. 기본값이므로, 모든 non-demo Intent 생성은 영향 없음.
    provenance_relaxed: bool = False       # demo record-then-pass 마커 (audit/trace)
    # P4-Q1 — pivot target 은 OPAQUE VALIDATED SELECTOR (라이브 IP 아님). 순수 데이터 운반:
    # target 은 UNTRUSTED 값 (telemetry/correlation 출처) 이며 raw iptables -s 인자로
    # 절대 쓰이면 안 된다. 오직 dispatch (response.py) 시 verified WorldState binding 맵에 대해
    # 해석되는 KEY 일 뿐; 위조된 selector (operator IP / out-of-pool / unknown
    # role) 는 verified 게이트에서 실패 -> inert DRY (self-DoS 차단, PS-7). 어떤 조건부 edge 도
    # 이 두 필드를 읽으면 안 됨 (불변식1. — verify_routing FORBIDDEN_KEYS 로 강제).
    target: str = ""                       # opaque selector (untrusted; raw -s 인자로 절대 안 씀)
    target_kind: Literal["role", "imsi", "ip", ""] = ""  # selector KEY 를 어떻게 해석할지
    # Two-endpoint containment (finding P4-2): 일관된 netns DROP 은 두 개의 서로 다른 endpoint 필요 —
    # ENFORCEMENT netns (공격자를 INPUT 으로 필터하는 chokepoint/victim) 와 SOURCE
    # (공격자). 위의 target/target_kind 는 SOURCE selector (drop_src); enforce_at 은
    # ENFORCEMENT-netns role KEY. 단일 selector 를 nsenter pid 와 -s source 양쪽에
    # 접으면 DROP 이 공격자 자신의 netns 에 들어가 자기 inbound ip 를 드롭 — 공격자의 악성
    # OUTBOUND 을 절대 막지 못하는 near no-op 이 된다. dispatch (response.py) 는 이제
    # enforce_at 과 source 가 두 개의 서로 다른 verified binding 으로 해석될 때만 DROP 을 구성, 아니면
    # inert DRY (self-DoS 차단, PS-7). enforce_at 도 opaque KEY (untrusted; raw
    # 인자로 절대 안 씀) 이며 edge-invisible (불변식1. — verify_routing FORBIDDEN_KEYS).
    enforce_at: str = ""                   # enforcement-netns role KEY (chokepoint/victim; ≠ source)
    # PS-9 command-bound OperatorRequest 필드 (NON-secret: binding 이며 HMAC key 나
    # signed token 이 아님 — 그것들은 signer_shim.OperatorGate / MDGState secret-free 를 절대 벗어나지 않음).
    # 캡처된 승인은 다른 command 를 인가할 수 없다, token 이 command_digest 에 대해
    # HMAC 되기 때문 (verify_operator_binding).
    command_digest: str = ""               # sha256 over (decision_id|rule|tool_id|config_version|params)
    nonce: str = ""                        # 단회용 nonce
    expiry: float = 0.0                    # TTL 절대 마감 (0 = unbound / 미발행)


class Decision(BaseModel):
    id: str
    decision: Literal[
        "Continue", "Continue+Monitoring", "Mission Reconfiguration",
        "Graceful Degradation", "Operator Confirmation", "Mission Abort",
    ] = "Continue"
    enforcement: Literal["auto", "operator_confirm"] = "auto"
    config_version: str = ""
    ts: float = 0.0
    debounce_ticks: int = 0
    trust_summary: dict[str, float] = Field(default_factory=dict)
    mission_impact: int = 0
    confidence: float = 1.0


# --------------------------------------------------------------------------- #
# LLM 조언 노트 (PA-5) — tighten 전용, edge-invisible
# --------------------------------------------------------------------------- #
class OrientNote(BaseModel):
    # extra='forbid' (P3-Q6): LLM 응답은 untrusted (PS-7). parse 경계에서 밀반입된 키를
    # 거부하여, 적대적이지만 유효해 보이는 페이로드가 아래의 bounded 필드
    # (전부 constr/Literal bounded) 를 통해서만 tighten 할 수 있게 — 새 surface 를 절대 주입 못 하게.
    model_config = ConfigDict(extra="forbid")
    rationale: constr(max_length=800) = ""            # type: ignore[valid-type]
    novelty_flag: bool = False
    ambiguity: bool = False
    severity_bump: Literal[0, 1] = 0                  # raise 전용, 크기 <= 1
    suggested_focus: list[constr(max_length=64)] = Field(default_factory=list, max_length=8)  # type: ignore[valid-type]


class DecideNote(BaseModel):
    model_config = ConfigDict(extra="forbid")         # P3-Q6: 밀반입된 키 거부 (untrusted LLM 출력)
    rationale: constr(max_length=800) = ""            # type: ignore[valid-type]
    escalate_recommended: bool = False
    caveats: list[constr(max_length=200)] = Field(default_factory=list, max_length=8)  # type: ignore[valid-type]


# --------------------------------------------------------------------------- #
# MDGState — LangGraph channels
# --------------------------------------------------------------------------- #
class MDGState(TypedDict, total=False):
    config_version: str
    worldstate: WorldState
    evidence: list[SensorEv]                                   # sense 가 drain + replace
    trust: dict[str, TrustObj]
    impact: ImpactObj
    # accumulator (operator.add reducer) — LastValue 아님 (PA-3)
    ledger: Annotated[list[Intent], operator.add]
    decisions: Annotated[list[Decision], operator.add]
    incidents: Annotated[list[Incident], operator.add]
    # LLM 조언 (비권위, edge-invisible)
    orient_note: Optional[OrientNote]
    decide_note: Optional[DecideNote]
    # action 선택 필드 (PA-4) — LLM 이 건드리지 않는 유일한 라우팅 입력
    chosen_action: Optional[Intent]
    chosen_action_risk: Risk
    chosen_action_reversible: bool
    legal_actions: list[Action]
    # counter (int LastValue; 노드 read-modify-return) — PA-1
    tick_i: int
    pivots: int
    dry_streak: int
    goal_reached: bool
    # Phase 1 (sandbox demo) 라우팅 입력: env 출처 bool. True 면 decide-edge 가
    # 원래 escalate 될 OPER 응답을 act 로 라우팅 (결정론적 — bool 이며 LLM 필드 아님, 불변식1.)
    # 하고 act 가 enforcement 를 operator-auto-confirmed 로 기록. 부재/False -> 자세 불변.
    operator_auto: bool
    operator_auto_confirmed: bool
    # 1. operator-select 라우팅 입력: env 출처 문자열 (recovery_type 또는 tool_id) 로 operator 가
    # legal 후보 집합에서 명시적으로 고른다. legal Action 과 일치하면, rank_recovery 가
    # 그 action 을 chosen_action 으로 승격 (자율 ranking 을 덮어씀) 하고
    # authority="operator-select" 로 표시; 공백/불일치 -> 자율 ranking 유지 (fail-safe).
    # live_autorun 이 state0 에 시드 (operator_auto 처럼) 하고 매 틱 운반 (LastValue).
    # 결정론적 (문자열이며 LLM 필드 아님, 불변식1.).
    operator_pick: str


def initial_state(config_version: str) -> MDGState:
    """recon_boot 이 tick-0 상태를 구성한다 (PA-3 에 따른 기본값)."""
    return MDGState(
        config_version=config_version,
        worldstate=WorldState(config_version=config_version),
        evidence=[],
        trust={},
        impact=ImpactObj(),
        ledger=[],
        decisions=[],
        incidents=[],
        orient_note=None,
        decide_note=None,
        chosen_action=None,
        chosen_action_risk="LOW",
        chosen_action_reversible=True,
        legal_actions=[],
        tick_i=0,
        pivots=0,
        dry_streak=0,
        goal_reached=False,
    )


# PS-3: allow-field 투영. 비밀값은 여기 필드가 없고 (구조적), 이 투영은
# 추가로 recording 전에 선언되지 않은 키를 전부 드롭한다.
_RECORD_ALLOW = {
    "config_version", "tick_i", "pivots", "dry_streak", "goal_reached",
    "impact", "trust", "incidents", "decisions", "ledger", "evidence",
    "chosen_action_risk", "chosen_action_reversible", "worldstate",
}


def _json_safe(v: object) -> object:
    if isinstance(v, BaseModel):
        return v.model_dump()
    if isinstance(v, dict):
        return {k: _json_safe(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_json_safe(x) for x in v]
    return v


def to_record(state: MDGState) -> dict:
    """recording hook 을 위한 allow-field 투영 (PS-3). MDGState 에는 비밀 필드가
    존재하지 않으며, 선언되지 않은 키는 여기서 드롭된다."""
    return {k: _json_safe(state[k]) for k in _RECORD_ALLOW if k in state}
