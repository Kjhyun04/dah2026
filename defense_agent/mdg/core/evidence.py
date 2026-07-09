"""증거 분석 프리미티브 (E7 band->sev/dev + TTL freshness).

두 관심사, 모두 순수/결정론적 (no I/O, no LLM, no subprocess):

1. band -> (severity, deviation)  — E7 매핑. 숫자의 단일 소스가 되도록 ``scoring`` 에
   위임한다; 분석 계층이 사용하는 명명된 접근자다.

2. TTL freshness — SensorEv(또는 도메인의 최신 증거)를 ``evidence_ttl_s``(config) 기준으로
   fresh vs stale 로 분류한다. compute_impact (PP-3) 의 present-set
   제외가 소비하는 분류기다: 최신 증거가 STALE 인 도메인은
   제외 대상 dead-collector 후보이며, IDLE 도메인(증거 없음
   -> trust 100, 여전히 present)과 구분된다. stale/dead 도메인을 trust=100 으로 주입하면
   fail-open 되어 impact 를 가린다 (PP-3 contract #1); 제외하는 것이 보수적 선택이다.

``fresh_domains`` 를 compute_trust/compute_impact 로 실 liveness 배선하는 것은 유보 상태다
(PP-3 잔여: "present-set 제외 구조만 배선, 감지신호 배선은 후속"). 이 모듈은
그 배선이 호출할 결정론적 분류기를 제공한다.
"""
from __future__ import annotations

from typing import Iterable

from ..config import defaults as D
from ..config import loader
from . import scoring


# --------------------------------------------------------------------------- #
# E7 — band -> (severity, deviation)
# --------------------------------------------------------------------------- #
def sev_dev(band: str) -> tuple[float, float]:
    """band 이름에 대한 (severity_factor, deviation) (E7). 단일 소스 = scoring."""
    return scoring.severity_factor(band), scoring.deviation(band)


# --------------------------------------------------------------------------- #
# TTL freshness
# --------------------------------------------------------------------------- #
def evidence_ttl_s(cfg: dict | None = None) -> float:
    """증거 신선도용 Config TTL. thresholds.yaml 오버라이드 -> defaults 폴백."""
    if cfg is not None and "evidence_ttl_s" in cfg:
        return float(cfg["evidence_ttl_s"])
    thr = loader.thresholds()
    if isinstance(thr, dict) and "evidence_ttl_s" in thr:
        return float(thr["evidence_ttl_s"])
    tw = thr.get("time_windows") if isinstance(thr, dict) else None
    if isinstance(tw, dict) and "evidence_ttl_s" in tw:
        return float(tw["evidence_ttl_s"])
    return float(D.TIME_WINDOWS["evidence_ttl_s"])


def age(ev_ts: float, now: float) -> float:
    """초 단위 음수 아닌 age (clock skew / ts==0 스캐폴딩에 대해 0 으로 클램프)."""
    return max(0.0, float(now) - float(ev_ts))


def is_fresh(ev_ts: float, now: float, ttl: float | None = None) -> bool:
    """age <= ttl 인 경우에만 fresh. ts==0 이고 now==0 (test/scaffold)은 age 0 -> fresh."""
    ttl = evidence_ttl_s() if ttl is None else float(ttl)
    return age(ev_ts, now) <= ttl


def is_stale(ev_ts: float, now: float, ttl: float | None = None) -> bool:
    return not is_fresh(ev_ts, now, ttl)


def fresh(evidence: Iterable, now: float, ttl: float | None = None) -> list:
    """tamper 아니고 TTL 이내인 증거만 (provenance gate + freshness, PS-2/PP-3)."""
    ttl = evidence_ttl_s() if ttl is None else float(ttl)
    return [e for e in evidence
            if not getattr(e, "tamper", False)
            and is_fresh(getattr(e, "ts", 0.0), now, ttl)]


def latest_ts_by_domain(evidence: Iterable) -> dict[str, float]:
    """도메인별 최신 증거 ts (non-tamper), staleness 분류용."""
    out: dict[str, float] = {}
    for e in evidence:
        if getattr(e, "tamper", False):
            continue
        dom = getattr(e, "domain", None)
        if dom is None:
            continue
        ts = float(getattr(e, "ts", 0.0))
        if dom not in out or ts > out[dom]:
            out[dom] = ts
    return out


def fresh_domains(evidence: Iterable, now: float, ttl: float | None = None) -> set[str]:
    """이번 윈도우에 fresh, non-tamper 증거가 하나 이상 있는 도메인들. 유보된
    present-set liveness 배선(PP-3)이 trust 도메인을 이 집합과 교집합하여
    dead-collector 도메인이 만점으로 읽히지 않고 EXCLUDED 되게 한다."""
    ttl = evidence_ttl_s() if ttl is None else float(ttl)
    return {dom for dom, ts in latest_ts_by_domain(evidence).items()
            if is_fresh(ts, now, ttl)}
