"""evidence analysis primitives (E7 band->sev/dev + TTL freshness).

Two concerns, both pure/deterministic (no I/O, no LLM, no subprocess):

1. band -> (severity, deviation)  — the E7 mapping. Delegates to ``scoring`` so there is
   a SINGLE source for the numbers; this is the named accessor the analysis layer uses.

2. TTL freshness — classify a SensorEv (or a domain's latest evidence) as fresh vs stale
   relative to ``evidence_ttl_s`` (config). This is the classifier the present-set
   exclusion in compute_impact (PP-3) consumes: a domain whose latest evidence is STALE
   is a dead-collector candidate for exclusion, distinct from an IDLE domain (no evidence
   -> trust 100, still present). Injecting a stale/dead domain as trust=100 would fail-open
   and mask impact (PP-3 contract #1); excluding it is the conservative move.

Live liveness wiring of ``fresh_domains`` into compute_trust/compute_impact is deferred
(PP-3 잔여: "present-set 제외 구조만 배선, 감지신호 배선은 후속"). This module supplies
the deterministic classifier that wiring will call.
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
    """(severity_factor, deviation) for a band name (E7). Single source = scoring."""
    return scoring.severity_factor(band), scoring.deviation(band)


# --------------------------------------------------------------------------- #
# TTL freshness
# --------------------------------------------------------------------------- #
def evidence_ttl_s(cfg: dict | None = None) -> float:
    """Config TTL for evidence freshness. thresholds.yaml override -> defaults fallback."""
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
    """Non-negative age in seconds (clamped at 0 for clock skew / ts==0 scaffolding)."""
    return max(0.0, float(now) - float(ev_ts))


def is_fresh(ev_ts: float, now: float, ttl: float | None = None) -> bool:
    """Fresh iff age <= ttl. ts==0 with now==0 (test/scaffold) reads age 0 -> fresh."""
    ttl = evidence_ttl_s() if ttl is None else float(ttl)
    return age(ev_ts, now) <= ttl


def is_stale(ev_ts: float, now: float, ttl: float | None = None) -> bool:
    return not is_fresh(ev_ts, now, ttl)


def fresh(evidence: Iterable, now: float, ttl: float | None = None) -> list:
    """Non-tamper, within-TTL evidence only (provenance gate + freshness, PS-2/PP-3)."""
    ttl = evidence_ttl_s() if ttl is None else float(ttl)
    return [e for e in evidence
            if not getattr(e, "tamper", False)
            and is_fresh(getattr(e, "ts", 0.0), now, ttl)]


def latest_ts_by_domain(evidence: Iterable) -> dict[str, float]:
    """Most-recent evidence ts per domain (non-tamper), for staleness classification."""
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
    """Domains with at least one fresh, non-tamper evidence this window. The deferred
    present-set liveness wiring (PP-3) intersects trust domains with this set so a
    dead-collector domain is EXCLUDED rather than read as full marks."""
    ttl = evidence_ttl_s() if ttl is None else float(ttl)
    return {dom for dom, ts in latest_ts_by_domain(evidence).items()
            if is_fresh(ts, now, ttl)}
