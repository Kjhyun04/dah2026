"""결정론적 scoring 파이프라인 — E5/E6/E7/E8/E19 (prototype §5 정본 수식).

순수 함수. I/O 없음, subprocess 없음, LLM 없음. compute_trust / compute_impact /
correlate 노드가 이들을 호출한다; tests/test_math.py 가 이들을 직접 테스트한다. 조건부 edge 가
라우팅 근거로 삼는 수치 권위이다 (불변식1. — LLM 은 여기 절대 없음).
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
    """band 이름에 대한 severity_factor 를 BAND_MAP -> SEVERITY_FACTOR 로 산출 (E7)."""
    sev_name = D.BAND_MAP[band]["severity"]
    return D.SEVERITY_FACTOR[sev_name]


def deviation(band: str) -> float:
    """band 내 deviation 스케일 (E7). 0-분모 없음: dev 는 band 파생이며 (obs-exp)/exp 아님."""
    return float(D.BAND_MAP[band]["dev"])


# --------------------------------------------------------------------------- #
# E5 + E6 — Trust score
#   trust = clamp(100 * (1 - confidence * min(Σ w·sev·dev, 1)), 0, 100)
#   idle(Σ=0) => confidence 무관하게 100 (E5).
#   weight 는 고정 Σ<=1, saturation min(...,1) (E6). 재정규화 없음.
# --------------------------------------------------------------------------- #
def domain_penalty(contributions: list[tuple[float, str]]) -> float:
    """Σ w·sev·dev, <=1 로 saturation (E6). contributions = [(weight, band), ...]."""
    s = 0.0
    for weight, band in contributions:
        s += weight * severity_factor(band) * deviation(band)
    return min(s, 1.0)  # E6 saturation


def trust_score(contributions: list[tuple[float, str]], confidence: float) -> float:
    """E5+E6+E7. idle (empty/all-normal) -> 100 (confidence 무관)."""
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
#   별도 필드 (trust 에 이중으로 곱해지지 않음 — E5/E8).
# --------------------------------------------------------------------------- #
def confidence(avg_quality: float, corr: float, decay: float, conflict: float) -> float:
    return clamp(avg_quality * corr * decay * (1.0 - conflict), 0.0, 1.0)


# --------------------------------------------------------------------------- #
# E8 — Mission impact. 0-100, 높을수록 나쁨, Green/Yellow/Red.
#   Confidence 는 한 번만 사용: 낮은 confidence 는 band 를 한 단계 올림
#   (보수적), 곱셈식 이중 패널티 아님.
# --------------------------------------------------------------------------- #
def impact_band(score: int) -> str:
    for name, (lo, hi) in D.IMPACT_BANDS.items():
        if lo <= score <= hi:
            return name
    return "Red"


def bump_band(band: str, steps: int = 1) -> str:
    """band 를 보수적으로 상향 이동 (Green->Yellow->Red); Red 는 saturation."""
    order = D.IMPACT_BAND_ORDER
    idx = order.index(band)
    return order[min(idx + steps, len(order) - 1)]


def apply_confidence_shift(band: str, conf: float,
                           low_threshold: float = D.LOW_CONFIDENCE_THRESHOLD) -> tuple[str, int]:
    """E8: confidence 를 band shift 로 정확히 한 번 적용. (band, shift) 반환."""
    if conf < low_threshold:
        return bump_band(band, 1), 1
    return band, 0


def compute_impact(overall_impact: int, conf: float,
                   low_threshold: float = D.LOW_CONFIDENCE_THRESHOLD) -> tuple[int, str, int]:
    """(clamp 된 overall_impact, 1회 conf shift 후 mission_risk band, shift) 반환."""
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
    """RANKING 전용 score (prototype §5). feasibility 임계값 아님.

    P0 panel 결정 (M6/E-2): feasibility GATE 는 success_probability >=
    feasible_min (rank_recovery) 이며, recovery_score >= 0.7 이 절대 아니다. 20-40pt trust-delta
    사전값이 이 합성값을 ~0.14-0.38 로 제한하므로, 이를 게이트로 삼으면 모든 응답이
    영구히 infeasible 해진다. 이 값은 오직 feasible 후보의 순서 결정에만 쓰인다.
    """
    val = succ * (0.6 * trust_rec / 100.0 + 0.4 * mission_rec / 100.0) * (1.0 - risk) / (1.0 + cost)
    return clamp(val, 0.0, 1.0)


# --------------------------------------------------------------------------- #
# Cross-domain overall impact (P0 panel-3 계약, 단순 weighted-mean 을 대체)
#   overall = max( weighted_mean , criticality_floor )
#   weighted_mean = Σ w·distrust / Σ w   (PRESENT-set Σw 로 정규화, 100 가정 아님)
#   criticality_floor = max_d floor(domain, distrust_d)  (weight-독립 tier)
# 단일 safety-critical 도메인이 완전 침해 (예: command trust=0) 되었을 때 보상적
# weighted mean 으로 Green 까지 희석되면 안 됨 — floor 가 이를 Red 로 고정한다.
# --------------------------------------------------------------------------- #
def crit_floor(domain: str, distrust: float, table: dict) -> float:
    """한 도메인에 대한 weight-독립 criticality floor. ``table[domain]`` 은
    ``[distrust_threshold, floor]`` 쌍의 리스트로 high->low 평가; 첫 일치가 승리, 없으면 0.
    mission_weight[domain]==0 일 때도 발화하므로, config 변조 (weight->0) 로도
    safety 도메인을 무력화할 수 없다 (P0 panel-3 계약 #2)."""
    rules = table.get(domain, []) or []
    for thr, val in sorted(rules, key=lambda r: -float(r[0])):
        if distrust >= float(thr):
            return float(val)
    return 0.0


def overall_impact(distrust_by_domain: dict, weights: dict, floor_table: dict) -> tuple[int, float]:
    """Cross-domain 집계 (P0 panel-3). ``distrust_by_domain = {domain: 100-trust}`` 를
    PRESENT (non-stale) 도메인 집합 D 에 대해서만. ``(overall 0-100 int, raw float)`` 반환.

    - weighted_mean 은 D 상의 Σw 로 정규화 (Σw>0 가드). 부재/stale 도메인은 caller 가
      제외 — distrust 0 으로 기본값 처리하지 않음, 그러면 fail-open 되어
      dead-collector 도메인을 가리게 됨 (계약 #1).
    - criticality floor 는 weight 무관하게 D 상에서 계산 (계약 #2).
    - overall 은 모든 distrust 에 대해 단조 비감소: 주입된 가짜 신호는 impact 를
      올릴 수만 있고 절대 은폐할 수 없다 (불변식1. / PS-7 계약 #3).
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
