"""behavioral — RoleSpec.verify_anchor 를 behaviorally_verified 술어로
소비한다(발견 P2-1, GATE2 resolve+verify 항목 A-1).

이 모듈이 존재하는 이유: resolve.py 는 RoleBinding.verified 를 PRESENCE(존재)로만
설정한다(inspect .State.Pid 로 컨테이너 존재; UE-pool 역할은 추가로 라이브 tun IP 가
ue_pool_cidr 안에 있어야 함). 존재는 TOPOLOGY(위상) 검사다 — 컨테이너는 존재하나
HEARTBEAT 미방출 / 잘못된 sysid 여도 여전히
verified=True 가 되어 GATE2 확신을 과대 표현한다. 선언된 RoleSpec.verify_anchor
(lo_14550_heartbeat_sys1 등)는 어떤 코드도 읽지 않는 DEAD 필드였다.

이 모듈은 verify_anchor 를 LIVE 로 만든다: 각 anchor 토큰을 관측된 행위 증거에 대한
술어로 매핑하고, GATE2 행위 프로브가 읽는 별개의(DISTINCT) behaviorally_verified 비트를
생성한다 — verified(따라서 적법성의 role_verified)는 순수 존재/해석 술어로 남긴다.

operator-go 주의: 기저 라이브 관측(air 측 tcpdump HEARTBEAT 디코드,
uav_proxy signing drop-log)은 그래프 밖에서 수집되며 상태변경-0 read-only 이나,
샌드박스 테스트베드에서 라이브 탭은 operator-go 유보다. 증거 부재 => 모든 anchor 는
미확인(False) — 정직한 boot 자세. recon_boot 은 behaviorally_verified 를 전부
False 로 시딩하고, 런타임은 관측이 도착하는 대로 collector/effect-confirm 단계
(apply_behavioral_verification)에서 라이브 AnchorEvidence 를 공급한다.

경계: 평범한 dataclass 위의 순수 함수; subprocess 없음, docker/sock 리터럴 없음,
resolve 단계 import 없음. 미지/빈 anchor => False(fail-closed, 절대 크래시 안 함).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from .inputspec import RoleSpec


@dataclass
class AnchorEvidence:
    """하나의(ONE) 역할에 대해 관측된 행위 신호, 라이브 collector 출력에서 정제됨.

    모든 필드는 '관측 안 됨' 값으로 기본 설정되어 빈 AnchorEvidence(boot /
    operator-go 자세)는 아무것도 확인하지 않는다. 런타임은 sense 를 공급하는 동일한
    collector 페이로드(air 측 HEARTBEAT 디코드,
    uav_proxy signing drop-log)로부터 이를 채운다 — 이 모듈은 스스로 아무것도 관측하지 않는다.
    """
    heartbeat_sys: Optional[int] = None   # uav_ue lo:14550 에서 디코드된 MAVLink system id (None = 미관측)
    command_entry_seen: bool = False      # gcs_proxy command-entry UDP:14556 탭에서 패킷 관측됨
    signing_drop_seen: bool = False       # uav_proxy signing-verify-fail drop 라인 관측됨(§9-B ON)


# anchor 토큰 -> AnchorEvidence 위의 술어. 역할의 anchor 를 여기에 추가하는 것이
# 라이브 소비되게 하는 유일한(ONLY) 배선이다(config anchor 와 그 검사를 한 곳에 둔다).
_ANCHOR_CHECKS: dict[str, Callable[[AnchorEvidence], bool]] = {
    # uav: uav_ue lo:14550 교차 탭에서 system id == 1 인 HEARTBEAT(D-1).
    "lo_14550_heartbeat_sys1": lambda e: e.heartbeat_sys == 1,
    # gcs_proxy: command-entry 평면이 UDP:14556 에서 라이브(업링크 command entry, §P).
    "command_entry_udp_14556": lambda e: e.command_entry_seen,
    # uav_proxy: §9-B signing-verify-fail drop 라인(권위 있는 강제 신호).
    "signing_drop_log_uav_proxy": lambda e: e.signing_drop_seen,
}


def confirm_behavioral_anchor(anchor: str, evidence: Optional[AnchorEvidence]) -> bool:
    """역할의 선언된 verify_anchor 가 evidence 로 만족되면 True.

    Fail-closed: 미지/빈 anchor 또는 증거 부재 -> False. 이것이 RoleSpec.verify_anchor
    의 유일한 소비처다(더 이상 dead 필드가 아님)."""
    if not anchor or evidence is None:
        return False
    check = _ANCHOR_CHECKS.get(anchor)
    return bool(check(evidence)) if check is not None else False


def apply_behavioral_verification(
    roles: list[RoleSpec],
    evidence: Optional[dict[str, AnchorEvidence]] = None,
) -> dict[str, bool]:
    """container -> behaviorally_verified, 각 역할의 verify_anchor + 라이브 증거로부터.

    evidence 는 container 로 키잉된다(world.role_verified / world.roles 와 일치);
    맵에 없는 container => 증거 없음 => False(operator-go / 아직 미관측).
    선언된 모든(EVERY) 역할에 대해 비트를 반환하여 GATE2 프로브가 존재 판정과 별개인
    행위 판정으로 전체 역할 집합을 보게 한다."""
    ev_map = evidence or {}
    return {
        r.container: confirm_behavioral_anchor(r.verify_anchor, ev_map.get(r.container))
        for r in roles
    }
