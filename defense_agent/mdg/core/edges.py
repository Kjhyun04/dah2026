"""Conditional edge branch functions (불변식① — DETERMINISTIC ROUTING).

These read ONLY numeric/bool state fields:
  impact.band, chosen_action_risk, chosen_action_reversible, chosen_action is None.
They NEVER read LLM-derived fields (orient_note / decide_note). verify_routing.py
enforces this by AST-scanning this module.
"""
from __future__ import annotations

from .state import MDGState

# Literal edge labels (LangGraph END sentinel is "__end__")
END = "__end__"


def route_after_impact(state: MDGState) -> str:
    """compute_impact -> orient | END. Green tick ends before any LLM call (E13/G6)."""
    impact = state.get("impact")
    band = getattr(impact, "band", "Green")
    if band == "Green":
        return END
    return "orient"


def route_after_decide(state: MDGState) -> str:
    """decide -> act | escalate | END. Reads ONLY risk/reversible/chosen_action.

      legal ∧ risk in {LOW,MED} ∧ reversible -> act
      risk == HIGH                            -> escalate
      chosen_action is None                   -> END
    """
    if state.get("chosen_action") is None:
        return END
    risk = state.get("chosen_action_risk", "LOW")
    reversible = state.get("chosen_action_reversible", True)
    if risk == "HIGH":
        return "escalate"
    if risk in ("LOW", "MED") and reversible:
        return "act"
    # non-reversible but not HIGH -> operator gate (conservative)
    return "escalate"
