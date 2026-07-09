"""select_policy (H-F) — Legality 게이트가 legal 후보 집합을 구성한다.

트립된 incidents/impact 를 닫힌 레지스트리의 후보 대응 Actions 로 매핑한 뒤,
legality(registered ∧ preconds ∧ config pin)로 필터링한다. 물리
액션은 N-tick debounce(X5)가 필요하며 하류에서 처리된다. SDN/재계획 없음(닫힌 집합).
"""
from __future__ import annotations

import re

from ...config import defaults as D
from ...config import loader
from ..legality import legal_actions
from ..state import Action, MDGState
from ..worldstate import WorldState

# incident kind -> 후보 recovery type (닫힌 매핑)
_INCIDENT_RECOVERY = {
    "CR01": ["pfcp_firewall", "command_override"],
    # PFCP delete flood(단일 메트릭, 상관 없음) — pfcp_firewall 로 라우팅
    # (nsenter_input_drop, MED, reversible). correlate 는 target 을 ""로 남기므로(귀속 가능한
    # 공격자 소스 없음) 집행은 inert/DRY 로 유지되고 피해자를 -s DROP 할 수 없다.
    "PFCP_DELETE": ["pfcp_firewall"],
    # Phase 3 (B2, S2) — single-signal 은 이제 컨테이너 격리 recovery
    # (backdoor_pause, docker_pause)와 비행 복구 후보(signed_guided,
    # send_signed_mode)를 모두 제공한다. 이는 후보 배선일 뿐이다 — legality 게이트(send_signed_mode
    # 는 "signing" == CONFIRMED_ON ∧ role_verified.gcs 요구)가 signing 이 UNKNOWN(라이브/production
    # 태세)일 때마다 signed_guided 를 이중 게이트로 제외하므로 S1 과 리플레이가
    # 바이트 동일하게 유지된다: UNKNOWN signing 하에서는 backdoor_pause 만 select_policy 를 통과한다.
    # signing 이 CONFIRMED(Phase 6, testbed 측)이면 signed_guided 가
    # OPER/HIGH 후보로 legal_actions 에 진입한다; 랭킹은 recovery_priors 에 맡긴다(core _sort_key
    # 부스트 없음) — 동등 후보 하에서 backdoor_pause(succ 0.95, MED)가 여전히 signed_guided(0.90, HIGH)를
    # 앞서므로, signed_guided 를 허용해도 S1 선택은 절대 교란되지 않는다. recovery_priors.yaml 참조.
    "single-signal": ["backdoor_pause", "signed_guided"],
}

# Phase 3 패널 수정 — flight-actuator 도메인 가드. correlate 는 트립 메트릭
# (RTT/mongo/NAS/telemetry/PFCP)에 대해 일반적인
# "single-signal" kind 를 방출하므로, kind 만으로는 command-hijack 을 identity_access 나
# communication blip 과 구분할 수 없다. signed_guided(send_signed_mode)는 HIGH/OPER *비가역 비행
# 업링크*(GUIDED 30m 재수립)이며 command 도메인 incident 에 대해서만 발화해야 한다 — 무관한
# single-signal 에는 절대 안 됨. 이것이 없으면 signing=CONFIRMED_ON(testbed 태세) +
# gcs_proxy 검증됨이지만 web_backend 는 아님(backdoor_pause 필터됨)일 때 signed_guided 가
# 예컨대 MongoDB 이상에 대한 유일한 legal 후보가 되어 flight-mode 명령을 발행한다(PS-7
# 허위-액추에이터 / 안전 표면 확장). 비행 rtype 을 incident 의
# 도메인으로 게이트한다. 이 도메인은 트립된 멤버 메트릭의 config 도메인(D.METRICS[metric].domain)에서 파생된다.
# FAIL-CLOSED: 인식되지 않는 멤버 메트릭은 도메인을 산출하지 못함 -> signed_guided 미허용.
# 컨테이너 격리(backdoor_pause)는 도메인 불가지로 유지된다. 이것은 후보 집합만
# 제한한다; legality signing 게이트가 여전히 UNKNOWN signing 하에서 signed_guided 를 이중 게이트로 제외하므로
# 라이브/리플레이 legal 집합은 바이트 동일하게 유지된다(불변식1.). Command single-signal
# (Unauthorized_Command / Signature_Verify_Fail)은 영향 없음 — signed_guided 는 여전히 진입한다.
_RTYPE_DOMAIN_GUARD = {"signed_guided": "command"}

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _incident_domains(inc) -> set[str]:
    """incident 의 트립된 멤버 메트릭의 도메인(config-sourced, D.METRICS —
    compute_trust 가 직접 읽는 동일 테이블). 알 수 없는 메트릭은 아무것도 기여하지 않는다
    (flight-actuator 가드에 대해 fail-closed)."""
    out: set[str] = set()
    for m in getattr(inc, "members", []) or []:
        spec = D.METRICS.get(m)
        if isinstance(spec, dict) and spec.get("domain"):
            out.add(str(spec["domain"]))
    return out

# recovery_type -> 집행 초크포인트 CONTAINER 키(finding P4-2)는 CONFIG-sourced
# (recovery_priors[<rtype>].enforce_at + default_enforce_at)이며 여기 인라인 리터럴이 아니다:
# 결정론 코어는 testbed role/container 이름을 0개 실어야 한다(GATE2 hardcoding-0, finding
# P2-3/A-1). 키스페이스는 CONTAINER 이름 — pid/role_verified 는 container-keyed 이고,
# response._resolve_endpoints 는 container-keyed pid 맵으로 enforce_at 을 해석한다(role 별칭은
# 미스 -> inert). 공격자 SOURCE 를 INPUT 필터링하는 netns — 소스와 구분되어야 DROP 이
# 일관된다(공격자 자신의 netns 에 들어가 자기 ip 를 드롭하는 것은 no-op). 키는
# dispatch 에서 VERIFIED 바인딩으로 해석되어야 하며 아니면 계획은 inert DRY 로 유지된다(fail-closed);
# 라이브 집행점 라우팅은 GATE2/operator-go RESERVED — 해석 안 되는 키는 절대 오DROP 하지 않는다.
# 예: pfcp_firewall 의 enforce_at 은 recovery_priors(steps 8/9)에 의해 container "gcs_proxy" 로
# 고정되며, 이는 아래 default_enforce_at=gcs_proxy 폴백과 일치한다; config 등록이 올바른
# 집행 chokepoint 의 단일 진실 소스인 이유이다.


def _classify_target(t: str) -> str:
    """신뢰되지 않은 incident.target 문자열에서 target_kind 셀렉터 KIND(P4-Q1)를 파생한다.
    순수 구문 분류 — 여기서 라이브 해석 없음(그것은 dispatch 에서의 verified-map
    조회). 빈 값 -> ""(dispatch 에서 레거시 role 로 폴백)."""
    t = (t or "").strip()
    if not t:
        return ""
    if _IPV4_RE.match(t):
        return "ip"
    if t.isdigit():
        return "imsi"
    return "role"


def _candidates(state: MDGState) -> list[Action]:
    rp = loader.recovery_priors()
    priors = rp.get("recovery_priors", {})
    default_enforce_at = str(rp.get("default_enforce_at", ""))
    incidents = state.get("incidents", [])
    seen: set[str] = set()
    out: list[Action] = []
    for inc in incidents:
        doms = None  # lazily computed once per incident
        for rtype in _INCIDENT_RECOVERY.get(inc.kind, []):
            # flight-actuator 도메인 가드(스킵될 때 `seen` 을 소비하지 마라: 이 tick 의 다른
            # command-domain incident 가 여전히 이 rtype 을 정당하게 방출할 수 있다).
            guard = _RTYPE_DOMAIN_GUARD.get(rtype)
            if guard is not None:
                if doms is None:
                    doms = _incident_domains(inc)
                if guard not in doms:
                    continue
            if rtype in seen:
                continue
            seen.add(rtype)
            p = priors.get(rtype, {})
            out.append(Action(
                tool_id=str(p.get("response_tool", "nsenter_input_drop")),
                params={"recovery_type": rtype, "target": inc.target,
                        "target_kind": _classify_target(inc.target),
                        # 집행 초크포인트(finding P4-2) — 공격자 소스와 구분됨.
                        # Config-sourced CONTAINER KEY(core 리터럴 없음, P2-3/A-1). priors 가
                        # enforce_at 을 실으면 p.get 이 이기고, 없으면 default_enforce_at 폴백이 쓰인다.
                        "enforce_at": str(p.get("enforce_at") or default_enforce_at)},
                risk=str(p.get("risk", "MED")),
                reversible=bool(p.get("reversible", True)),
                recovery_type=rtype,
            ))
    return out


def select_policy(state: MDGState) -> dict:
    world: WorldState = state.get("worldstate") or WorldState()
    cfg = state.get("config_version", world.config_version)
    cands = _candidates(state)
    legal = legal_actions(cands, world, cfg)
    return {"legal_actions": legal}
