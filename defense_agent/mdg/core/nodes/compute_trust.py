"""compute_trust (E5/E6/E7) — deterministic 5-domain trust.

trust = clamp(100*(1 - confidence*min(Σ w·sev·dev, 1)), 0, 100). idle -> 100.
Confidence is computed separately (E5/E8) and NOT multiplied into trust twice.
Provenance gate: tamper evidence is structurally excluded (PS-2/PS-7).

Liveness (P3-Q5): a watchdog-dead domain (listed in ``worldstate.dead_domains``, driven by
the collector HEARTBEAT via Watchdog sensor_loss) is NOT emitted as a TrustObj — it drops
out of the returned dict entirely. This activates compute_impact's already-wired present-set
exclusion (``if t is None: continue``) with ZERO change to compute_impact. The verdict is
READ from state (computed upstream against now); this node stays a pure, clock-free function
of state (불변식1.). Absent field -> empty set -> all-present fallback (existing behavior).

Distrust-input contract (P3-Q4 lock — the real accuracy anchor for the crit_floor, NOT the
71/45 magnitude): command-domain distrust maps to the Red-floor trigger (>=71) ONLY on a real
unauthenticated-actuation observation (5762-bypass command / a CONFIRMED_OFF unsigned command
reaching SITL; same P3-Q3 latch anchor). Mere suspicion / signing=UNKNOWN stays in the 40-70
band (mid-Yellow floor 45), so an injected doubt cannot auto-confirm Red and self-DoS (PS-7).
A signature-verify-fail DROP (uav_proxy '서명검증 실패 -> SITL 차단 (누적 N)') is defense
SUCCESS, NOT a compromise -> it adds ZERO distrust (the drop counter is a P3-Q2 activity metric,
not a posture signal; it must never fire the floor alone). The actuation-observation SOURCE
(uav_signing collector / 5762 vantage) is D-2 un-wired -> operator-go deferred; until it is
wired the command distrust stays evidence-derived (fail-safe: the floor simply does not fire).
"""
from __future__ import annotations

from ...config import defaults as D
from ..scoring import confidence as calc_confidence
from ..scoring import trust_level, trust_score
from ..state import MDGState, SensorEv, TrustObj


def compute_trust(state: MDGState) -> dict:
    evidence: list[SensorEv] = [e for e in state.get("evidence", []) if e.verified and not e.tamper]

    # group (weight, band) contributions per domain from thresholds metric weights
    by_domain: dict[str, list[tuple[float, str]]] = {d: [] for d in D.DOMAINS}
    conf_samples: dict[str, list[float]] = {d: [] for d in D.DOMAINS}
    for e in evidence:
        spec = D.METRICS.get(e.metric)
        if spec is None:
            continue
        dom = str(spec["domain"])
        weight = float(spec["weight"])
        by_domain.setdefault(dom, []).append((weight, e.band))
        conf_samples.setdefault(dom, []).append(float(e.confidence))

    # liveness present-set exclusion (P3-Q5): read the watchdog-dead verdict from the
    # upstream-merged WorldState. Absent field -> no dead domains (all-present fallback).
    world = state.get("worldstate")
    dead = set(getattr(world, "dead_domains", None) or [])

    trust: dict[str, TrustObj] = {}
    for dom in D.DOMAINS:
        if dom in dead:
            continue                                    # watchdog-dead -> drop (excluded from impact D)
        contribs = by_domain.get(dom, [])
        qs = conf_samples.get(dom, [])
        avg_q = sum(qs) / len(qs) if qs else 1.0
        conf = calc_confidence(avg_q, corr=1.0, decay=1.0, conflict=0.0)
        score = trust_score(contribs, conf)
        trust[dom] = TrustObj(
            domain=dom, trust_score=score, trust_level=trust_level(score),
            confidence=conf,
            reason="idle" if not contribs else f"{len(contribs)} signals",
        )
    return {"trust": trust}
