"""compute_impact (E8/M5/M7) — 0-100 mission impact, Green/Yellow/Red.

overall_impact = max( weighted_mean , criticality_floor )   (P0 panel-3 계약):
  weighted_mean = Σ w·distrust / Σw, PRESENT 도메인 집합 대상 (distrust = 100-trust),
  criticality_floor = max_d floor(domain, distrust)  (가중치 독립 안전 등급).
단순 가중평균만으로는 보상적이어서 단일 안전 크리티컬
도메인의 완전 침해를 Green으로 희석한다 (예: command trust=0 -> 20 = Green); floor가 그것을
Red로 고정. 부재/stale 도메인은 EXCLUDE (trust=100으로 기본값 처리 안 함), 아니면 죽은
collector가 만점으로 읽혀 impact를 가린다 (fail-open). 모든 도메인 stale -> 이전
band 유지 (Green 절대 아님) + sensor-loss Incident 발행.

Confidence는 한 번만 사용: 최저-present-도메인 confidence가 risk band를 한 단계 올림
(보수적), 곱셈적 이중 페널티 아님. Green tick은 orient
(route_after_impact) 전에 끝나고 dry_streak을 증가시킨다.
"""
from __future__ import annotations

from ...config import defaults as D
from ...config import loader
from ..scoring import bump_band
from ..scoring import compute_impact as score_impact
from ..scoring import overall_impact as agg_overall
from ..state import ImpactObj, Incident, MDGState


def compute_impact(state: MDGState) -> dict:
    trust = state.get("trust", {})
    profile = loader.mission_profile()
    weights = profile.get("mission_weight", {})
    floor_table = profile.get("criticality_floor", {})

    # PRESENT-set만: trust에 없는 도메인(stale/죽은 collector)은 EXCLUDE,
    # trust=100으로 주입 안 함 — 100 주입은 평균을 희석하고 impact를 가린다.
    distrust: dict[str, float] = {}
    min_conf = 1.0
    for dom, w in weights.items():
        if dom == "recovery":
            continue
        t = trust.get(dom)
        if t is None:
            continue                                           # stale/부재 -> D에서 제외
        distrust[dom] = 100.0 - float(t.trust_score)
        min_conf = min(min_conf, float(t.confidence))

    if not distrust:
        # 모든 도메인 stale -> 이전 band 유지, Green 절대 발행 안 함 (contract #1)
        prev = state.get("impact") or ImpactObj()
        held = prev.band if prev.band != "Green" else "Yellow"
        return {
            "impact": ImpactObj(score=prev.score, band=held,
                                confidence_margin=prev.confidence_margin),
            "incidents": [Incident(id=f"sensorloss-t{int(state.get('tick_i', 0))}",
                                   kind="sensor-loss", target="all-domains")],
        }

    overall, _raw = agg_overall(distrust, weights, floor_table)
    score, band, shift = score_impact(overall, min_conf)

    # CR01 동시발생 bump: 동일 tick 상관 incident (예: PFCP_Delete_Attempt +
    # Unauthorized_Command, min_members=2)는 각각은 criticality floor 아래에 있어도
    # 여러 도메인이 동시에 공격받았음을 뜻한다. band를 한 단계 올려 (Red 초과
    # 안 함) 2-signal 상관이 Green을 벗어나 -> orient. THIS tick의 incident
    # id에 스코프(endswith '-<tick>')되어 영구 bump 아님. 결정론적 (incident.kind +
    # tick, LLM 필드 없음) -> 라우팅 순수성 유지; 라우팅된 회복(pfcp_firewall)은 되돌릴 수 있음.
    tick = int(state.get("tick_i", 0))
    corr_now = any(
        getattr(inc, "kind", None) in D.CORRELATION_RULES
        and str(getattr(inc, "id", "")).endswith(f"-{tick}")
        for inc in state.get("incidents", [])
    )
    if corr_now and band != "Red":
        band = bump_band(band, 1)

    impact = ImpactObj(score=score, band=band, confidence_margin=float(shift))

    out: dict = {"impact": impact}
    if band == "Green":
        # Green-END 경로는 dry_streak을 증가시킴 (PA-1)
        out["dry_streak"] = int(state.get("dry_streak", 0)) + 1
    return out
