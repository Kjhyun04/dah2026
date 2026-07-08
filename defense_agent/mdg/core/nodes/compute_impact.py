"""compute_impact (E8/M5/M7) — 0-100 mission impact, Green/Yellow/Red.

overall_impact = max( weighted_mean , criticality_floor )   (P0 panel-3 contract):
  weighted_mean = Σ w·distrust / Σw over the PRESENT domain set (distrust = 100-trust),
  criticality_floor = max_d floor(domain, distrust)  (weight-independent safety tier).
The plain weighted mean alone is compensatory and would dilute a single safety-critical
domain's full compromise to Green (e.g. command trust=0 -> 20 = Green); the floor pins it
to Red. Absent/stale domains are EXCLUDED (not defaulted to trust=100), else a dead
collector reads as full marks and masks the impact (fail-open). All domains stale -> hold
the prior band (never Green) + emit a sensor-loss Incident.

Confidence used ONCE: lowest-present-domain confidence bumps the risk band up one step
(conservative), NOT a multiplicative double penalty. Green tick ends before orient
(route_after_impact) and increments dry_streak.
"""
from __future__ import annotations

from ...config import loader
from ..scoring import compute_impact as score_impact
from ..scoring import overall_impact as agg_overall
from ..state import ImpactObj, Incident, MDGState


def compute_impact(state: MDGState) -> dict:
    trust = state.get("trust", {})
    profile = loader.mission_profile()
    weights = profile.get("mission_weight", {})
    floor_table = profile.get("criticality_floor", {})

    # PRESENT-set only: a domain absent from trust (stale/dead collector) is EXCLUDED,
    # NOT injected as trust=100 — injecting 100 would dilute the mean and mask impact.
    distrust: dict[str, float] = {}
    min_conf = 1.0
    for dom, w in weights.items():
        if dom == "recovery":
            continue
        t = trust.get(dom)
        if t is None:
            continue                                           # stale/absent -> excluded from D
        distrust[dom] = 100.0 - float(t.trust_score)
        min_conf = min(min_conf, float(t.confidence))

    if not distrust:
        # all domains stale -> hold prior band, never emit Green (contract #1)
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
    impact = ImpactObj(score=score, band=band, confidence_margin=float(shift))

    out: dict = {"impact": impact}
    if band == "Green":
        # Green-END path increments dry_streak (PA-1)
        out["dry_streak"] = int(state.get("dry_streak", 0)) + 1
    return out
