"""조건부 엣지 분기 함수 (불변식1. — DETERMINISTIC ROUTING).

숫자/불리언 상태 필드만 읽는다:
  impact.band, chosen_action_risk, chosen_action_reversible, chosen_action is None.
LLM 파생 필드(orient_note / decide_note)는 절대 읽지 않는다. verify_routing.py 가
이 모듈을 AST 스캔하여 이를 강제한다.
"""
from __future__ import annotations

from .state import MDGState

# 리터럴 엣지 라벨 (LangGraph END 센티널은 "__end__")
END = "__end__"


def route_after_impact(state: MDGState) -> str:
    """compute_impact -> orient | END. Green 틱은 LLM 호출 전에 종료 (E13/G6)."""
    impact = state.get("impact")
    band = getattr(impact, "band", "Green")
    if band == "Green":
        return END
    return "orient"


def route_after_decide(state: MDGState) -> str:
    """decide -> act | escalate | END. risk/reversible/chosen_action + env 유래
    ``operator_auto`` 불리언(Phase 1)만 읽는다. LLM 파생 필드는 절대 읽지 않는다 (불변식1. — 결정론적 라우팅;
    ``operator_auto`` 는 조언이 아니라 숫자/불리언 env 입력이며 verify_routing 이 허용한다).

      legal ∧ risk in {LOW,MED} ∧ reversible          -> act
      risk == HIGH / non-reversible                    -> escalate  (기본 자세)
      ... but with operator_auto (sandbox demo)        -> act        (OPER 자동 확인)
      chosen_action is None                            -> END
    """
    if state.get("chosen_action") is None:
        return END
    risk = state.get("chosen_action_risk", "LOW")
    reversible = state.get("chosen_action_reversible", True)
    if risk in ("LOW", "MED") and reversible:
        return "act"
    # risk == HIGH 또는 non-reversible -> operator gate (보수적). sandbox demo 에서는
    # operator_auto 플래그가 OPER 경로를 결정론적으로 자동 확인하므로 escalate 대신 act 로
    # 라우팅한다 (act 가 operator_auto_confirmed 를 스탬프 + 집행을 투명하게 기록).
    if bool(state.get("operator_auto")):
        return "act"
    return "escalate"
