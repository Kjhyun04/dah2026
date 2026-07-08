"""gate.py — 2-tier authorization gate (DETERMINISTIC, secret-free — 불변식①).

Two independent tiers gate every response:

  Tier-1 (edge, ``edges.route_after_decide``): RISK-based state routing.
      HIGH -> escalate · MED/LOW ∧ reversible -> act · chosen None -> END.

  Tier-2 (THIS module, evaluated INSIDE act): TOOL-TIER authorization.
      Even a MED/reversible action that Tier-1 routed to ``act`` may be an OPER-tier tool
      (flight-mode set / docker pause / net-disconnect). Those must NEVER auto-actuate —
      the act node defers them to the operator (records an operator-gate Intent, side-effect
      0). Only AUTO-tier tools auto-execute. Per the closed registry (P3-Q1 #1) the SOLE
      AUTO response is ``nsenter_input_drop`` (netns INPUT DROP); every signing-key-adjacent
      or container-lifecycle tool is OPER ("flight = operator").

Purity: reads REGISTRY ``tier``/``effect`` + the numeric/bool ``risk``/``reversible`` ONLY.
No LLM field, no secret, no subprocess, no docker/sock reference (core boundary). This makes
the AUTO/OPER split a byte-stable function of the registry + risk, so a hostile LLM advice
(tighten-only, edge-invisible) can never widen the auto surface.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..tools.registry import REGISTRY

Tier2 = Literal["AUTO", "OPER"]
FLIGHT_EFFECT = "flight_mode_set"


@dataclass(frozen=True)
class GateDecision:
    """Result of the tier-2 tool gate. ``auto`` True == may auto-actuate."""
    tool_id: str
    tier2: Tier2
    auto: bool
    flight: bool
    registry_tier: str          # "RO" | "AUTO" | "OPER" from the closed registry
    reason: str

    @property
    def operator_required(self) -> bool:
        return not self.auto


def gate_for(tool_id: str, risk: str, reversible: bool) -> GateDecision:
    """Classify a chosen response tool into AUTO vs OPER (fail-closed to OPER).

    AUTO requires ALL of: registered ∧ registry tier == AUTO ∧ risk in {LOW,MED} ∧ reversible
    ∧ not a flight action. Anything else (unregistered, OPER/RO tier, HIGH risk, irreversible,
    flight) is OPER. An unknown tool is OPER — a ghost id can never actuate.
    """
    spec = REGISTRY.get(tool_id)
    if spec is None:
        return GateDecision(tool_id, "OPER", False, False, "",
                            f"unregistered tool_id '{tool_id}' -> operator (fail-closed)")
    flight = spec.effect == FLIGHT_EFFECT
    reg_tier = spec.tier
    if flight:
        return GateDecision(tool_id, "OPER", False, True, reg_tier,
                            "flight action -> operator (2-tier: 비행=operator)")
    if reg_tier != "AUTO":
        return GateDecision(tool_id, "OPER", False, False, reg_tier,
                            f"registry tier '{reg_tier}' != AUTO -> operator")
    if risk not in ("LOW", "MED"):
        return GateDecision(tool_id, "OPER", False, False, reg_tier,
                            f"risk '{risk}' not auto-eligible -> operator")
    if not reversible:
        return GateDecision(tool_id, "OPER", False, False, reg_tier,
                            "irreversible bundle -> operator")
    return GateDecision(tool_id, "AUTO", True, False, reg_tier, "AUTO-tier reversible response")


def is_auto(tool_id: str, risk: str, reversible: bool) -> bool:
    """Convenience predicate: True iff the tool may auto-actuate (tier-2 AUTO)."""
    return gate_for(tool_id, risk, reversible).auto


def requires_operator(tool_id: str, risk: str, reversible: bool) -> bool:
    """True iff the tool must be deferred to the operator (tier-2 OPER)."""
    return gate_for(tool_id, risk, reversible).operator_required
