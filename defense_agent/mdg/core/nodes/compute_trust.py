"""compute_trust (E5/E6/E7) — 결정론적 5-도메인 trust.

trust = clamp(100*(1 - confidence*min(Σ w·sev·dev, 1)), 0, 100). idle -> 100.
Confidence는 별도로 계산되며 (E5/E8) trust에 두 번 곱해지지 않는다.
Provenance gate: tamper 증거는 구조적으로 제외된다 (PS-2/PS-7).

Liveness (P3-Q5): watchdog-dead 도메인(``worldstate.dead_domains``에 등재, Watchdog
sensor_loss를 통한 collector HEARTBEAT로 구동)은 TrustObj로 발행되지 않는다 — 반환
dict에서 완전히 빠진다. 이는 compute_impact의 이미 배선된 present-set
제외(``if t is None: continue``)를 compute_impact 변경 ZERO로 활성화한다. 판정은
state에서 READ (상류에서 now 대비 계산됨); 이 노드는 순수하고 clock-free한 state
함수로 남는다 (불변식1.). 필드 부재 -> 빈 집합 -> all-present 폴백 (기존 동작).

Distrust-input contract (P3-Q4 lock — crit_floor의 실제 정확도 앵커, 71/45
크기가 아님): command 도메인 distrust는 실제 미인증-작동 관측에서만
Red-floor 트리거(>=71)로 매핑된다 (5762-bypass command / SITL에 도달하는 CONFIRMED_OFF
미서명 command; 동일 P3-Q3 latch 앵커). 단순 의심 / signing=UNKNOWN은 40-70
band(mid-Yellow floor 45)에 머물러, 주입된 의심이 Red를 자동확정해 self-DoS 할 수 없다 (PS-7).
서명검증 실패 DROP (uav_proxy '서명검증 실패 -> SITL 차단 (누적 N)')은 방어
SUCCESS이지 침해가 아님 -> distrust를 ZERO 추가 (drop 카운터는 P3-Q2 활동 메트릭이지
posture 신호가 아님; 단독으로 floor를 발화해서는 안 됨). 작동-관측 SOURCE
(uav_signing collector / 5762 vantage)는 D-2 미배선 -> operator-go 유예; 배선되기
전까지 command distrust는 evidence-derived로 유지 (fail-safe: floor가 그냥 발화 안 함).
"""
from __future__ import annotations

from ...config import defaults as D
from ..scoring import confidence as calc_confidence
from ..scoring import trust_level, trust_score
from ..state import MDGState, SensorEv, TrustObj


def compute_trust(state: MDGState) -> dict:
    evidence: list[SensorEv] = [e for e in state.get("evidence", []) if e.verified and not e.tamper]

    # thresholds 메트릭 가중치에서 도메인별 (weight, band) 기여를 그룹화
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

    # liveness present-set 제외 (P3-Q5): 상류에서 병합된 WorldState에서
    # watchdog-dead 판정을 읽음. 필드 부재 -> dead 도메인 없음 (all-present 폴백).
    world = state.get("worldstate")
    dead = set(getattr(world, "dead_domains", None) or [])

    trust: dict[str, TrustObj] = {}
    for dom in D.DOMAINS:
        if dom in dead:
            continue                                    # watchdog-dead -> drop (impact D에서 제외)
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
