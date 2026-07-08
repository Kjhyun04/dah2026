"""Deterministic scoring pipeline — E5/E6/E7/E8/E19 (prototype §5 정본 수식).

Pure functions. No I/O, no subprocess, no LLM. compute_trust / compute_impact /
correlate nodes call these; tests/test_math.py tests these directly. This is the
numeric authority that the conditional edges route on (불변식① — LLM never here).
"""
from __future__ import annotations

import math

from ..config import defaults as D


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


# --------------------------------------------------------------------------- #
# E7 — band -> (severity, deviation)
# --------------------------------------------------------------------------- #
def severity_factor(band: str) -> float:
    """severity_factor for a band name via BAND_MAP -> SEVERITY_FACTOR (E7)."""
    sev_name = D.BAND_MAP[band]["severity"]
    return D.SEVERITY_FACTOR[sev_name]


def deviation(band: str) -> float:
    """In-band deviation scale (E7). No 0-분모: dev is band-derived, not (obs-exp)/exp."""
    return float(D.BAND_MAP[band]["dev"])


# --------------------------------------------------------------------------- #
# E5 + E6 — Trust score
#   trust = clamp(100 * (1 - confidence * min(Σ w·sev·dev, 1)), 0, 100)
#   idle(Σ=0) => 100 regardless of confidence (E5).
#   weight fixed Σ<=1, saturation min(...,1) (E6). NO renormalization.
# --------------------------------------------------------------------------- #
def domain_penalty(contributions: list[tuple[float, str]]) -> float:
    """Σ w·sev·dev, saturated to <=1 (E6). contributions = [(weight, band), ...]."""
    s = 0.0
    for weight, band in contributions:
        s += weight * severity_factor(band) * deviation(band)
    return min(s, 1.0)  # E6 saturation


def trust_score(contributions: list[tuple[float, str]], confidence: float) -> float:
    """E5+E6+E7. idle (empty/all-normal) -> 100 (confidence irrelevant)."""
    penalty = domain_penalty(contributions)
    raw = 100.0 * (1.0 - confidence * penalty)
    return clamp(raw, 0.0, 100.0)


def trust_level(score: float) -> str:
    for name, (lo, hi) in D.TRUST_BANDS.items():
        if lo <= score <= hi:
            return name
    return "very_low"


# --------------------------------------------------------------------------- #
# Confidence — conf = avg_q * corr * decay * (1 - conflict)
#   Separate field (NOT multiplied into trust twice — E5/E8).
# --------------------------------------------------------------------------- #
def confidence(avg_quality: float, corr: float, decay: float, conflict: float) -> float:
    return clamp(avg_quality * corr * decay * (1.0 - conflict), 0.0, 1.0)


# --------------------------------------------------------------------------- #
# E8 — Mission impact. 0-100, higher = worse, Green/Yellow/Red.
#   Confidence used ONCE: low confidence bumps the band up ONE step
#   (conservative), NOT a multiplicative double penalty.
# --------------------------------------------------------------------------- #
def impact_band(score: int) -> str:
    for name, (lo, hi) in D.IMPACT_BANDS.items():
        if lo <= score <= hi:
            return name
    return "Red"


def bump_band(band: str, steps: int = 1) -> str:
    """Move band conservatively upward (Green->Yellow->Red); Red saturates."""
    order = D.IMPACT_BAND_ORDER
    idx = order.index(band)
    return order[min(idx + steps, len(order) - 1)]


def apply_confidence_shift(band: str, conf: float,
                           low_threshold: float = D.LOW_CONFIDENCE_THRESHOLD) -> tuple[str, int]:
    """E8: apply confidence exactly once as a band shift. Returns (band, shift)."""
    if conf < low_threshold:
        return bump_band(band, 1), 1
    return band, 0


def compute_impact(overall_impact: int, conf: float,
                   low_threshold: float = D.LOW_CONFIDENCE_THRESHOLD) -> tuple[int, str, int]:
    """Return (overall_impact clamped, mission_risk band after 1-time conf shift, shift)."""
    score = int(clamp(overall_impact, 0, 100))
    base_band = impact_band(score)
    band, shift = apply_confidence_shift(base_band, conf, low_threshold)
    return score, band, shift


# --------------------------------------------------------------------------- #
# E19 — Correlation. score = weight * mean(member.severity_factor) * (n>=2 ? 1 : 0)
# --------------------------------------------------------------------------- #
def correlation_score(weight: float, member_severities: list[float],
                      min_members: int = 2) -> float:
    n = len(member_severities)
    if n < min_members:
        return 0.0
    mean_sev = sum(member_severities) / n
    return weight * mean_sev


# --------------------------------------------------------------------------- #
# Recovery — recovery_score = clamp(
#   succ * (0.6·Σtrust_rec/100 + 0.4·mission_rec/100) * (1-risk)/(1+cost), 0, 1)
# --------------------------------------------------------------------------- #
def recovery_score(succ: float, trust_rec: float, mission_rec: float,
                   risk: float, cost: float) -> float:
    """RANKING-ONLY score (prototype §5). NOT a feasibility threshold.

    P0 panel decision (M6/E-2): the feasibility GATE is success_probability >=
    feasible_min (rank_recovery), NEVER recovery_score >= 0.7. The 20-40pt trust-delta
    priors cap this composite at ~0.14-0.38, so gating on it makes every response
    permanently infeasible. This value is used solely to order feasible candidates.
    """
    val = succ * (0.6 * trust_rec / 100.0 + 0.4 * mission_rec / 100.0) * (1.0 - risk) / (1.0 + cost)
    return clamp(val, 0.0, 1.0)


# --------------------------------------------------------------------------- #
# Cross-domain overall impact (P0 panel-3 contract, supersedes plain weighted-mean)
#   overall = max( weighted_mean , criticality_floor )
#   weighted_mean = Σ w·distrust / Σ w   (normalized by PRESENT-set Σw, not assumed 100)
#   criticality_floor = max_d floor(domain, distrust_d)  (weight-INDEPENDENT tier)
# A single safety-critical domain fully compromised (e.g. command trust=0) must NOT be
# diluted to Green by a compensatory weighted mean — the floor pins it to Red.
# --------------------------------------------------------------------------- #
def crit_floor(domain: str, distrust: float, table: dict) -> float:
    """Weight-independent criticality floor for one domain. ``table[domain]`` is a list
    of ``[distrust_threshold, floor]`` pairs evaluated high->low; first match wins, else 0.
    Fires even when mission_weight[domain]==0, so config tampering (weight->0) cannot
    neutralize a safety domain (P0 panel-3 contract #2)."""
    rules = table.get(domain, []) or []
    for thr, val in sorted(rules, key=lambda r: -float(r[0])):
        if distrust >= float(thr):
            return float(val)
    return 0.0


def overall_impact(distrust_by_domain: dict, weights: dict, floor_table: dict) -> tuple[int, float]:
    """Cross-domain aggregation (P0 panel-3). ``distrust_by_domain = {domain: 100-trust}``
    over the PRESENT (non-stale) domain set D only. Returns ``(overall 0-100 int, raw float)``.

    - weighted_mean is normalized by Σw over D (Σw>0 guard). Absent/stale domains are
      excluded by the caller — NOT defaulted to distrust 0, which would fail-open and mask
      a dead-collector domain (contract #1).
    - the criticality floor is computed over D regardless of weights (contract #2).
    - overall is monotonic non-decreasing in every distrust: injected fake signals can only
      RAISE impact, never conceal it (불변식① / PS-7 contract #3).
    """
    D = list(distrust_by_domain.keys())
    floor = max((crit_floor(d, float(distrust_by_domain[d]), floor_table) for d in D), default=0.0)
    total_w = sum(float(weights.get(d, 0.0)) for d in D)
    if total_w > 0.0:
        num = sum(float(weights.get(d, 0.0)) * float(distrust_by_domain[d]) for d in D)
        weighted_mean = num / total_w
    else:
        weighted_mean = 0.0
    raw = max(weighted_mean, floor)
    return int(clamp(math.floor(raw), 0, 100)), raw
