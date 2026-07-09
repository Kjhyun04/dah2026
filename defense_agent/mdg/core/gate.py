"""gate.py — 2-tier 인가 게이트 (DETERMINISTIC, secret-free — 불변식1.).

두 개의 독립 tier 가 모든 응답을 게이트한다:

  Tier-1 (엣지, edges.route_after_decide): RISK 기반 상태 라우팅.
      HIGH -> escalate · MED/LOW ∧ reversible -> act · chosen None -> END.

  Tier-2 (이 모듈, act 내부에서 평가): TOOL-TIER 인가.
      Tier-1 이 act 로 라우팅한 MED/reversible 액션이라도 OPER-tier 도구
      (flight-mode set / docker pause / net-disconnect)일 수 있다. 이들은 절대 자동 작동해선 안 된다 —
      act 노드가 이를 operator 에게 위임한다 (operator-gate Intent 기록, side-effect
      0). AUTO-tier 도구만 자동 실행된다. closed registry (P3-Q1 #1)에 따라 유일한
      AUTO 응답은 nsenter_input_drop (netns INPUT DROP)이며; signing-key 인접 또는
      container-lifecycle 도구는 모두 OPER 다 ("flight = operator").

순수성: REGISTRY tier/effect + 숫자/불리언 risk/reversible 만 읽는다.
LLM 필드, secret, subprocess, docker/sock 참조 없음 (core 경계). 이로써
AUTO/OPER 분리는 registry + risk 의 byte-stable 함수가 되어, 적대적 LLM 조언
(tighten-only, edge-invisible)이 auto 표면을 넓힐 수 없다.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..tools.registry import REGISTRY

Tier2 = Literal["AUTO", "OPER", "AUTO_BY_OPERATOR"]
FLIGHT_EFFECT = "flight_mode_set"


@dataclass(frozen=True)
class GateDecision:
    """tier-2 도구 게이트의 결과. auto True == 자동 작동 가능."""
    tool_id: str
    tier2: Tier2
    auto: bool
    flight: bool
    registry_tier: str          # closed registry 의 "RO" | "AUTO" | "OPER"
    reason: str

    @property
    def operator_required(self) -> bool:
        return not self.auto


def gate_for(tool_id: str, risk: str, reversible: bool,
             operator_auto: bool = False) -> GateDecision:
    """선택된 응답 도구를 AUTO vs OPER 로 분류한다 (OPER 로 fail-closed).

    AUTO 는 다음을 모두 요구한다: registered ∧ registry tier == AUTO ∧ risk in {LOW,MED} ∧ reversible
    ∧ flight 액션 아님. 그 외(unregistered, OPER/RO tier, HIGH risk, irreversible,
    flight)는 OPER 다. 알 수 없는 도구는 OPER — ghost id 는 절대 작동할 수 없다.

    operator_auto (Phase 1, SANDBOX DEMO): True 이면 REGISTERED OPER 결정을
    auto=True 로 확장하여 (sandbox operator auto-confirm) OPER 복구 경로(docker_pause / flight)가
    사람에게 위임되는 대신 실행된다. flight 와 registry_tier 필드는
    PRESERVED (원래 OPER 분류를 그대로 유지)되어, 이것이 native AUTO 도구가 아니라
    operator-gate 도구가 자동 승인된 것임을 routing/ledger 가 투명하게 유지한다. 이는
    (registry + risk + env 유래 operator_auto 불리언)의 DETERMINISTIC 함수다: LLM 필드가 없으므로
    적대적 조언이 뒤집을 수 없다 (불변식1.). UNREGISTERED/ghost id 는 절대 확장되지 않는다 —
    closed-registry fail-closed 은 절대적이며, operator_auto 는 알 수 없는 도구를 구제하지 않는다.
    """
    spec = REGISTRY.get(tool_id)
    if spec is None:
        # ghost/unregistered id 는 절대 작동하지 않는다 — operator_auto 가 구제하지 않는다 (closed registry).
        return GateDecision(tool_id, "OPER", False, False, "",
                            f"unregistered tool_id '{tool_id}' -> operator (fail-closed)")
    flight = spec.effect == FLIGHT_EFFECT
    reg_tier = spec.tier
    if flight:
        base = GateDecision(tool_id, "OPER", False, True, reg_tier,
                            "flight action -> operator (2-tier: 비행=operator)")
    elif reg_tier != "AUTO":
        base = GateDecision(tool_id, "OPER", False, False, reg_tier,
                            f"registry tier '{reg_tier}' != AUTO -> operator")
    elif risk not in ("LOW", "MED"):
        base = GateDecision(tool_id, "OPER", False, False, reg_tier,
                            f"risk '{risk}' not auto-eligible -> operator")
    elif not reversible:
        base = GateDecision(tool_id, "OPER", False, False, reg_tier,
                            "irreversible bundle -> operator")
    else:
        base = GateDecision(tool_id, "AUTO", True, False, reg_tier,
                            "AUTO-tier reversible response")

    if operator_auto and base.operator_required:
        # sandbox operator auto-confirm: OPER -> auto=True. 투명성을 위해 flight/registry_tier 는
        # PRESERVED (ledger/routing 이 여전히 원래 OPER 분류를 본다).
        return GateDecision(tool_id, "AUTO_BY_OPERATOR", True, base.flight, base.registry_tier,
                            "sandbox operator auto-confirm")
    return base


def is_auto(tool_id: str, risk: str, reversible: bool, operator_auto: bool = False) -> bool:
    """편의 술어: 도구가 자동 작동 가능한 경우에만 True (tier-2 AUTO)."""
    return gate_for(tool_id, risk, reversible, operator_auto).auto


def requires_operator(tool_id: str, risk: str, reversible: bool,
                      operator_auto: bool = False) -> bool:
    """도구가 operator 에게 위임되어야 하는 경우에만 True (tier-2 OPER)."""
    return gate_for(tool_id, risk, reversible, operator_auto).operator_required
