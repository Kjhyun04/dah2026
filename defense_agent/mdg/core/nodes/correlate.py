"""correlate (E19, P4-4) — 시간창 동시발생 (source_ip join은 plane 간
불가, FEASIBILITY §2). 2-layer join: metric diff (발생) + SMF-log
session-table delete 이벤트 (귀속). RTT는 multi-signal gate 입력일 뿐,
단독 trip 아님 (P4-6). incident target이 바뀌면 pivots++.
"""
from __future__ import annotations

from ...config import defaults as D
from ..scoring import correlation_score, severity_factor
from ..state import Incident, MDGState, SensorEv


def correlate(state: MDGState, clock=None) -> dict:
    evidence: list[SensorEv] = [e for e in state.get("evidence", []) if not e.tamper]
    ts = clock.now() if clock is not None else 0.0
    incidents: list[Incident] = []

    # single-signal incident (트립된 band)
    tripped = [e for e in evidence if e.band in ("warning", "critical", "danger")]
    for e in tripped:
        # row D — 5762 backdoor (metric Port_5762_State, uav_ue netns)는
        # DEDICATED kind를 받아 select_policy가 이 신호만 nsenter DROP으로 라우팅.
        # 다른 모든 트립된 metric (RTT/mongo/NAS/telemetry/PFCP)은 generic
        # single-signal 유지; 한 kind로 뭉치면 그 회복이 uav_ue 5762 DROP으로
        # 오라우팅됨 (self-DoS). 순전히 metric으로 식별; members가 metric을 실어
        # 하류에서 5762 귀속을 확인할 수 있게 함.
        # 5762 backdoor -> BACKDOOR_5762 (nsenter DROP@uav_ue). PFCP delete flood ->
        # dedicated PFCP_DELETE로 select_policy가 pfcp_firewall로 라우팅 (uav_ue
        # 5762 DROP 아님). 나머지는 모두 generic single-signal 유지.
        kind = ("BACKDOOR_5762" if e.metric == "Port_5762_State"
                else "PFCP_DELETE" if e.metric == "PFCP_Delete_Attempt"
                else "single-signal")
        # target = 귀속 셀렉터 (drop 가능 endpoint). 오직 5762 backdoor만
        # 공격자-귀속 가능 peer를 실음 (step-4 WebProbe peer). PFCP delete는 귀속 가능
        # 공격자가 없음: Prometheus 집계는 source IP가 없고 SMF 로그는
        # VICTIM UAV tun-IP를 실음 — 그래서 PFCP target ""를 fail-closed로 둠, 아니면 pfcp_firewall이
        # 피해자를 -s DROP 할 수 있음 (self-DoS, harmlessness/leak-0 위반). source 없음 -> "" (DRY).
        target = e.source if e.metric == "Port_5762_State" else ""
        incidents.append(Incident(
            id=f"sig-{state.get('tick_i',0)}-{e.metric}", kind=kind,
            score=severity_factor(e.band), members=[e.metric], ts=e.ts or ts,
            target=target,
        ))

    # CR01 시간창 상관 (E19)
    for rule_id, rule in D.CORRELATION_RULES.items():
        members = [e for e in tripped if e.metric in rule["metrics"]]
        sevs = [severity_factor(e.band) for e in members]
        score = correlation_score(float(rule.get("weight", 1.0)), sevs,
                                  int(rule.get("min_members", 2)))
        if score > 0:
            incidents.append(Incident(
                id=f"{rule_id}-{state.get('tick_i',0)}", kind=rule_id, score=score,
                members=[e.metric for e in members], ts=ts,
                containment_only_flag=False,
            ))

    out: dict = {}
    if incidents:
        out["incidents"] = incidents           # operator.add

    # target 변경 시 pivots++
    prev = state.get("incidents", [])
    prev_target = prev[-1].target if prev else ""
    new_target = next((i.target for i in incidents if i.target), "")
    if new_target and new_target != prev_target:
        out["pivots"] = int(state.get("pivots", 0)) + 1
    return out
