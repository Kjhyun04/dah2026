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

Tier2 = Literal["AUTO", "OPER", "AUTO_BY_OPERATOR"]
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


def gate_for(tool_id: str, risk: str, reversible: bool,
             operator_auto: bool = False) -> GateDecision:
    """Classify a chosen response tool into AUTO vs OPER (fail-closed to OPER).

    AUTO requires ALL of: registered ∧ registry tier == AUTO ∧ risk in {LOW,MED} ∧ reversible
    ∧ not a flight action. Anything else (unregistered, OPER/RO tier, HIGH risk, irreversible,
    flight) is OPER. An unknown tool is OPER — a ghost id can never actuate.

    ``operator_auto`` (Phase 1, SANDBOX DEMO): when True, a REGISTERED OPER decision is widened to
    ``auto=True`` (sandbox operator auto-confirm) so the OPER recovery path (docker_pause / flight)
    executes instead of deferring to a human. The ``flight`` and ``registry_tier`` fields are
    PRESERVED (still carry the original OPER classification) so routing/ledger stays transparent
    that this was an operator-gate tool auto-approved — not a native AUTO tool. This is a
    DETERMINISTIC function of (registry + risk + the env-sourced operator_auto bool): no LLM field,
    so a hostile advice can never flip it (불변식①). An UNREGISTERED/ghost id is NEVER widened —
    the closed-registry fail-closed is absolute, operator_auto does not rescue an unknown tool.
    """
    spec = REGISTRY.get(tool_id)
    if spec is None:
        # ghost/unregistered id NEVER actuates — operator_auto does NOT rescue it (closed registry).
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
        # sandbox operator auto-confirm: OPER -> auto=True. flight/registry_tier PRESERVED for
        # transparency (ledger/routing still see the original OPER classification).
        return GateDecision(tool_id, "AUTO_BY_OPERATOR", True, base.flight, base.registry_tier,
                            "sandbox operator auto-confirm")
    return base


def is_auto(tool_id: str, risk: str, reversible: bool, operator_auto: bool = False) -> bool:
    """Convenience predicate: True iff the tool may auto-actuate (tier-2 AUTO)."""
    return gate_for(tool_id, risk, reversible, operator_auto).auto


def requires_operator(tool_id: str, risk: str, reversible: bool,
                      operator_auto: bool = False) -> bool:
    """True iff the tool must be deferred to the operator (tier-2 OPER)."""
    return gate_for(tool_id, risk, reversible, operator_auto).operator_required
