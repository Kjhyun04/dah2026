"""WorldState — closed 술어 / artifact (H-E). sense 가 매 틱 병합하는
단일 권위 객체. closed 어휘만; free-form 상태 없음.

DESIGN_DECISIONS PA-3 이 WorldState 를 필수 모델로 지명; 여기 존재하며
state.py 에서 re-export 되어 mdg.core.state.WorldState 가 해석된다.
"""
from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

# Closed reach 집합 (V3 §3): 누가/무엇이 어느 plane 에서 reachable 한지.
ReachTarget = Literal[
    "gcs14556", "web8080", "mongo27017", "pfcp8805", "net_core", "net_sgi"
]
Domain = Literal["communication", "identity_access", "session_network", "command", "mission"]
ThreatLevel = Literal["none", "low", "medium", "high", "critical"]
Provenance = Literal["config", "inspect", "verified"]


class SigningObs(str, Enum):
    """관측된 uplink-signing enforcement 자세 (P2-Q2 panel, 3상태).

    맨 bool 은 "confirmed OFF" 를 "아직 미관측" 과 혼동했다 — 보안 결함,
    §9-B signing 이 TOGGLE 기반 (실제 OFF 가능) 이고 관측이
    ASYMMETRIC (drop-log 라인은 양성 ON 증거; drop 의 부재는 OFF 증거가
    아님) 이기 때문. 3상태는 그 비대칭을 인코딩하여 부트 기본값 (UNKNOWN) 이
    confirmed-OFF 자세로 오인될 수 없게 한다 (오인 시 과잉 대응 유발,
    PS-7 self-DoS).

    전이 권한 (locked): enforcement 는 P3+ 에서 수집된 uav_proxy 권위
    신호에만 변경됨 (drop-log 라인 서명검증 실패 -> SITL 차단 (누적 N) 또는
    서명 강제 ON boot banner / /api/signing enforced). gcs_proxy env, uav env,
    docker inspect, drop 의 부재는 절대 전이시키지 않음 (MEMORY 오판 가드 코드화).
    """
    UNKNOWN = "unknown"            # boot 기본값; off 아님 — 아직 권위 신호 없음
    CONFIRMED_ON = "confirmed_on"  # uav_proxy drop-log / ON-banner / /api/signing enforced
    CONFIRMED_OFF = "confirmed_off"  # uav_proxy OFF-banner / unsigned cmd 가 SITL 도달


def signing_enforced(obs: "SigningObs") -> bool:
    """is_enforced 술어: CONFIRMED_ON 만 enforced 로 간주 (적법성 게이트).

    UNKNOWN (미확인) 은 보수적으로 NOT enforced 로 취급 — signed command
    tool 은 미확인 인증 제어에 의존해선 안 된다.
    """
    return obs is SigningObs.CONFIRMED_ON


class AppliedRule(BaseModel):
    """revert + effect-confirm 을 위해 추적되는 enforced (또는 시도된) 응답 rule."""
    rule: str
    revert_cmd: str = ""
    ts: float = 0.0
    applied_tick: int = 0             # act 가 적용한 시점의 tick_i (bundle N-tick debounce, X5)
    decision_id: str = ""
    config_version: str = ""
    confirmed: bool = False           # effect_confirm 이 설정 (PA-2). exec 게이트 아님.
    reverted: bool = False            # de-escalation revert 마커 (bundle, X5/E15)
    provenance: Provenance = "config"
    confirm_note: str = ""            # confirm 시 effect_confirm delta 노트 (Phase 4; audit/viewer 전용)


class RoleBinding(BaseModel):
    """recon boot 에서 해석된 role -> container -> IP (H-I). tun IP 는 exec-scan 으로 (A-1).

    두 개의 서로 다른 술어 (finding P2-1, GATE2 resolve+verify):
      - verified  = RESOLUTION/PRESENCE: 컨테이너가 존재 (inspect .State.Pid) 하고,
        UE-pool role 의 경우 live tun IP 가 ue_pool_cidr 안에 있음. 이는 토폴로지
        체크 — role 이 정상 동작함을 증명하지 않음. 적법성 (role_verified) 이 이를 읽음.
      - behaviorally_verified = live behavioural anchor (RoleSpec.verify_anchor) 가
        관측됨 (예: uav_ue lo:14550 의 HEARTBEAT sysid=1; signing
        drop-log). live collector 증거로부터 targets/behavioral.apply_behavioral_verification 가
        설정. 존재하지만 anchor 를 방출하지 않거나 불리한 컨테이너는
        verified=True, behaviorally_verified=False — presence 를 behavioural
        verify 로 과장하지 않음. boot 기본값 False (live 관측은 operator-go)."""
    role: str
    container: str = ""
    ip: str = ""
    verified: bool = False            # RESOLVED/PRESENT (topology + pool membership) — 적법성이 이를 읽음
    behaviorally_verified: bool = False  # live verify_anchor 관측 (P2-1); 적법성 술어 아님
    provenance: Provenance = "config"


class Baseline(BaseModel):
    """신호별 baseline (RTT EWMA/mdev, counter high-water) — P4-6/P4-3."""
    rtt_baseline_ms: float = 27.7
    rtt_mdev_ms: float = 11.0
    counters: dict[str, int] = Field(default_factory=dict)   # 마지막으로 본 monotonic counter


class WorldState(BaseModel):
    """Closed-predicate testbed 자세. reach/signing/role_verified/threat/applied
    + ip_map/pid/baseline."""
    # 자세 술어
    reach: dict[str, bool] = Field(default_factory=dict)          # reach(X) -> bool
    signing: SigningObs = SigningObs.UNKNOWN                       # 관측된 signing 자세 (tri-state, P2-Q2)
    role_verified: dict[str, bool] = Field(default_factory=dict)  # container -> RESOLVED/PRESENT (적법성 술어)
    behaviorally_verified: dict[str, bool] = Field(default_factory=dict)  # container -> live anchor 관측 (P2-1)
    threat: dict[str, ThreatLevel] = Field(default_factory=dict)  # domain -> level
    applied: dict[str, AppliedRule] = Field(default_factory=dict) # rule -> AppliedRule
    # artifact
    ip_map: dict[str, str] = Field(default_factory=dict)          # role/imsi/ip -> ip/container
    roles: dict[str, RoleBinding] = Field(default_factory=dict)
    # static IMSI -> container boot 맵 (spec.imsi_container_map, resolve.ResolveResult.imsi_container).
    # boot CONSTANT (ue*.conf), 동적 아님 — response controller 가 live
    # SMF-table IMSI 를 컨테이너로 재귀속시켜 P4 stale-binding 교차검증에 쓴다 (재할당 IP self-DoS 차단).
    imsi_container: dict[str, str] = Field(default_factory=dict)  # static IMSI -> container (P4-1/P2-Q1)
    pid: dict[str, int] = Field(default_factory=dict)             # role -> pid (nsenter target)
    baseline: Baseline = Field(default_factory=Baseline)
    # 도메인별 liveness verdict (P3-Q5). 여기 있는 도메인은 watchdog-dead collector
    # (silence-gap -> signed sensor_loss, PS-2) 를 가지며 trust/impact
    # present-set 에서 DROP 됨. collector HEARTBEAT 을 통한 Watchdog sensor_loss (진짜
    # liveness SOURCE) 로 구동, evidence.fresh_domains (조용한 event-driven
    # collector 를 dead 인 것과 혼동) 가 아님. 기본값은 비어있음 -> 전부-present (fail-safe fallback).
    dead_domains: list[Domain] = Field(default_factory=list)      # watchdog-dead 도메인 (present-set 제외)
    config_version: str = ""

    def with_applied(self, rule: AppliedRule) -> "WorldState":
        """act 의 post world_update 가 쓰는 순수 merge 헬퍼."""
        nxt = self.model_copy(deep=True)
        nxt.applied[rule.rule] = rule
        return nxt
