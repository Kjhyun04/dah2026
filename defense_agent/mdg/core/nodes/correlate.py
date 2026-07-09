"""correlate (E19, P4-4) — time-window co-occurrence (source_ip join impossible
across planes, FEASIBILITY §2). 2-layer join: metric diff (occurrence) + SMF-log
session-table delete event (attribution). RTT is a multi-signal gate input only,
never a solo trip (P4-6). pivots++ when the incident target changes.
"""
from __future__ import annotations

from ...config import defaults as D
from ..scoring import correlation_score, severity_factor
from ..state import Incident, MDGState, SensorEv


def correlate(state: MDGState, clock=None) -> dict:
    evidence: list[SensorEv] = [e for e in state.get("evidence", []) if not e.tamper]
    ts = clock.now() if clock is not None else 0.0
    incidents: list[Incident] = []

    # single-signal incidents (tripped bands)
    tripped = [e for e in evidence if e.band in ("warning", "critical", "danger")]
    for e in tripped:
        # row D — the 5762 backdoor (metric Port_5762_State, uav_ue netns) gets a
        # DEDICATED kind so select_policy routes ONLY this signal to the nsenter DROP.
        # Every other tripped metric (RTT/mongo/NAS/telemetry/PFCP) stays generic
        # single-signal; collapsing them under one kind would mis-route their recovery
        # to a uav_ue 5762 DROP (self-DoS). Identified purely by metric; members carries
        # the metric so downstream can confirm the 5762 attribution.
        # 5762 backdoor -> BACKDOOR_5762 (nsenter DROP@uav_ue). PFCP delete flood ->
        # dedicated PFCP_DELETE so select_policy routes it to pfcp_firewall (NOT a uav_ue
        # 5762 DROP). Everything else stays generic single-signal.
        kind = ("BACKDOOR_5762" if e.metric == "Port_5762_State"
                else "PFCP_DELETE" if e.metric == "PFCP_Delete_Attempt"
                else "single-signal")
        # target = attribution selector (droppable endpoint). ONLY the 5762 backdoor carries
        # an attacker-attributable peer (step-4 WebProbe peer). PFCP delete has NO attributable
        # attacker: the Prometheus aggregate has no source IP and the SMF log carries the
        # VICTIM UAV tun-IP — so leave PFCP target "" fail-closed, else pfcp_firewall could
        # -s DROP a victim (self-DoS, harmlessness/leak-0 violation). No source -> "" (DRY).
        target = e.source if e.metric == "Port_5762_State" else ""
        incidents.append(Incident(
            id=f"sig-{state.get('tick_i',0)}-{e.metric}", kind=kind,
            score=severity_factor(e.band), members=[e.metric], ts=e.ts or ts,
            target=target,
        ))

    # CR01 time-window correlation (E19)
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

    # pivots++ on target change
    prev = state.get("incidents", [])
    prev_target = prev[-1].target if prev else ""
    new_target = next((i.target for i in incidents if i.target), "")
    if new_target and new_target != prev_target:
        out["pivots"] = int(state.get("pivots", 0)) + 1
    return out
