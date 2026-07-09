"""MDGState channel schema + all pydantic v2 models (DESIGN_DECISIONS PA-3/PA-5).

MDGState is a TypedDict with LangGraph channel reducers:
  - accumulator channels (ledger/decisions/incidents) use ``operator.add``
  - everything else is LastValue (replace).

Secrets (LLM key / operator token / HMAC key) are STRUCTURALLY absent from this
schema (PS-3). The verifier verdict channel is intentionally absent (PA-2) — the
core cannot import a verdict store. ``to_record()`` is the allow-field projection
used by the recording hook.
"""
from __future__ import annotations

import operator
from typing import Annotated, Literal, Optional, TypedDict

from pydantic import BaseModel, ConfigDict, Field, constr

from .worldstate import WorldState  # re-export: mdg.core.state.WorldState resolves

__all__ = [
    "MDGState", "WorldState", "TrustObj", "ImpactObj", "Intent", "Incident",
    "Decision", "SensorEv", "OrientNote", "DecideNote", "Action",
    "initial_state", "to_record",
]

Risk = Literal["LOW", "MED", "HIGH"]
Domain = Literal["communication", "identity_access", "session_network", "command", "mission"]


# --------------------------------------------------------------------------- #
# Evidence envelope payload (secret-free; hmac/kid verified at drain, PS-2)
# --------------------------------------------------------------------------- #
class SensorEv(BaseModel):
    source_id: str
    kid: str = ""
    seq: int = 0
    ts: float = 0.0
    nonce: str = ""
    metric: str = ""                       # thresholds metric name (or log signal)
    value: object = None                   # numeric/enum derived value ONLY (PS-7)
    band: str = "normal"                   # normal|warning|critical|danger
    domain: Optional[Domain] = None
    channel: str = ""                      # channel_quality key
    source: str = ""                       # opaque attribution selector (ip/imsi/remote); DATA-only, edge-invisible
    confidence: float = 0.9                # channel prior (not a verdict)
    verified: bool = False                 # HMAC/seq verified at drain
    tamper: bool = False                   # provenance gate: excluded from merge/trust


# --------------------------------------------------------------------------- #
# Trust / Impact
# --------------------------------------------------------------------------- #
class TrustObj(BaseModel):
    domain: Domain
    trust_score: float = 100.0             # E5 idle -> 100
    trust_level: str = "very_high"
    confidence: float = 1.0                # separate field (E5/E8; used once by impact)
    reason: str = ""
    supporting: list[str] = Field(default_factory=list)
    conflicting: list[str] = Field(default_factory=list)


class ImpactObj(BaseModel):
    score: int = 0                         # 0-100, higher = worse (M5/M7)
    band: Literal["Green", "Yellow", "Red"] = "Green"
    confidence_margin: float = 0.0         # conservative shift magnitude applied once (E8)
    availability: int = 0
    integrity: int = 0
    safety: int = 0
    continuity: int = 0


# --------------------------------------------------------------------------- #
# Incident / Decision / Intent / Action
# --------------------------------------------------------------------------- #
class Incident(BaseModel):
    id: str
    kind: str                              # e.g. CR01, tamper, single-signal
    score: float = 0.0
    containment_only_flag: bool = False    # V4 key-forgery = containment only
    members: list[str] = Field(default_factory=list)
    ts: float = 0.0
    target: str = ""                       # pivot target (imsi/ip/role)


class Action(BaseModel):
    """A legal candidate response (closed registry tool + bound params)."""
    tool_id: str
    params: dict[str, object] = Field(default_factory=dict)
    risk: Risk = "LOW"
    reversible: bool = True
    recovery_type: str = ""


class Intent(BaseModel):
    """Recorded BEFORE side effects (guard 밖) so recover_on_boot can revert (G3)."""
    rule: str
    revert_cmd: str = ""
    ts: float = 0.0
    decision_id: str = ""
    config_version: str = ""
    tool_id: str = ""
    operator_gate: bool = False            # escalate records these (side-effect 0)
    # Phase 1 (sandbox demo) audit fields: an OPER tool executed via operator_auto records
    # operator_auto_confirmed=True + authority="sandbox-auto" so an auditor can distinguish an
    # auto-confirmed OPER enforcement from a native AUTO one. Defaults keep every other path intact.
    operator_auto_confirmed: bool = False
    authority: str = ""                    # "" | "sandbox-auto" | "operator-select" (who authorized)
    # Phase 2 (PS-7/B3, sandbox demo): when the injected-high-severity provenance/debounce gate is
    # RELAXED under operator_auto (record-then-pass), rank_recovery stamps provenance_relaxed=True so
    # the ledger/trace transparently records that the strict trusted-source hold was waived for the
    # demo. Production (operator_auto off) keeps False — the strict posture is unrecorded because it
    # was not relaxed. Defaulted, so every non-demo Intent construction is unaffected.
    provenance_relaxed: bool = False       # demo record-then-pass marker (audit/trace)
    # P4-Q1 — pivot target as an OPAQUE VALIDATED SELECTOR (NOT a live IP). Pure data-carrying:
    # ``target`` is an UNTRUSTED value (from telemetry/correlation) and MUST NEVER be used as a
    # raw ``iptables -s`` argument. It is only a KEY resolved against the verified WorldState
    # binding map at dispatch (response.py); a forged selector (operator IP / out-of-pool / unknown
    # role) fails the verified gate -> inert DRY (self-DoS closed, PS-7). No conditional edge may
    # read these two fields (불변식1. — enforced by verify_routing FORBIDDEN_KEYS).
    target: str = ""                       # opaque selector (untrusted; never a raw -s arg)
    target_kind: Literal["role", "imsi", "ip", ""] = ""  # how to resolve the selector KEY
    # Two-endpoint containment (finding P4-2): a coherent netns DROP needs TWO DISTINCT endpoints —
    # the ENFORCEMENT netns (chokepoint/victim whose INPUT filters the attacker) and the SOURCE
    # (attacker). ``target``/``target_kind`` above is the SOURCE selector (drop_src); ``enforce_at``
    # is the ENFORCEMENT-netns role KEY. Collapsing a single selector into BOTH the nsenter pid AND
    # the ``-s`` source made the DROP enter the attacker's OWN netns and drop its own inbound ip — a
    # near no-op that never stops the attacker's malicious OUTBOUND. dispatch (response.py) now builds
    # the DROP ONLY when enforce_at and the source resolve to two DISTINCT verified bindings, else
    # inert DRY (self-DoS closed, PS-7). ``enforce_at`` is ALSO an opaque KEY (untrusted; never a raw
    # arg) and edge-invisible (불변식1. — verify_routing FORBIDDEN_KEYS).
    enforce_at: str = ""                   # enforcement-netns role KEY (chokepoint/victim; ≠ source)
    # PS-9 command-bound OperatorRequest fields (NON-secret: the binding, NOT the HMAC key
    # or signed token — those never leave signer_shim.OperatorGate / MDGState secret-free).
    # A captured approval cannot authorize a different command because the token is HMAC'd
    # over command_digest (verify_operator_binding).
    command_digest: str = ""               # sha256 over (decision_id|rule|tool_id|config_version|params)
    nonce: str = ""                        # single-use nonce
    expiry: float = 0.0                    # TTL absolute deadline (0 = unbound / not issued)


class Decision(BaseModel):
    id: str
    decision: Literal[
        "Continue", "Continue+Monitoring", "Mission Reconfiguration",
        "Graceful Degradation", "Operator Confirmation", "Mission Abort",
    ] = "Continue"
    enforcement: Literal["auto", "operator_confirm"] = "auto"
    config_version: str = ""
    ts: float = 0.0
    debounce_ticks: int = 0
    trust_summary: dict[str, float] = Field(default_factory=dict)
    mission_impact: int = 0
    confidence: float = 1.0


# --------------------------------------------------------------------------- #
# LLM advice notes (PA-5) — tighten-only, edge-invisible
# --------------------------------------------------------------------------- #
class OrientNote(BaseModel):
    # extra='forbid' (P3-Q6): the LLM response is untrusted (PS-7). Reject smuggled keys at
    # the parse boundary so a hostile-but-valid-looking payload can only tighten via the
    # bounded fields below (all constr/Literal bounded) — never inject new surface.
    model_config = ConfigDict(extra="forbid")
    rationale: constr(max_length=800) = ""            # type: ignore[valid-type]
    novelty_flag: bool = False
    ambiguity: bool = False
    severity_bump: Literal[0, 1] = 0                  # raise-only, magnitude <= 1
    suggested_focus: list[constr(max_length=64)] = Field(default_factory=list, max_length=8)  # type: ignore[valid-type]


class DecideNote(BaseModel):
    model_config = ConfigDict(extra="forbid")         # P3-Q6: reject smuggled keys (untrusted LLM output)
    rationale: constr(max_length=800) = ""            # type: ignore[valid-type]
    escalate_recommended: bool = False
    caveats: list[constr(max_length=200)] = Field(default_factory=list, max_length=8)  # type: ignore[valid-type]


# --------------------------------------------------------------------------- #
# MDGState — LangGraph channels
# --------------------------------------------------------------------------- #
class MDGState(TypedDict, total=False):
    config_version: str
    worldstate: WorldState
    evidence: list[SensorEv]                                   # sense drains + replaces
    trust: dict[str, TrustObj]
    impact: ImpactObj
    # accumulators (operator.add reducers) — NOT LastValue (PA-3)
    ledger: Annotated[list[Intent], operator.add]
    decisions: Annotated[list[Decision], operator.add]
    incidents: Annotated[list[Incident], operator.add]
    # LLM advice (non-authoritative, edge-invisible)
    orient_note: Optional[OrientNote]
    decide_note: Optional[DecideNote]
    # action selection fields (PA-4) — the ONLY LLM-untouched routing inputs
    chosen_action: Optional[Intent]
    chosen_action_risk: Risk
    chosen_action_reversible: bool
    legal_actions: list[Action]
    # counters (int LastValue; node read-modify-return) — PA-1
    tick_i: int
    pivots: int
    dry_streak: int
    goal_reached: bool
    # Phase 1 (sandbox demo) routing input: env-sourced bool. When True the decide-edge routes an
    # otherwise-escalated OPER response to act (deterministic — a bool, never an LLM field, 불변식1.)
    # and act records the enforcement as operator-auto-confirmed. Absent/False -> unchanged posture.
    operator_auto: bool
    operator_auto_confirmed: bool
    # 1. operator-select routing input: env-sourced string (recovery_type or tool_id) the operator
    # explicitly picks from the legal candidate set. When it matches a legal Action, rank_recovery
    # promotes THAT action to chosen_action (overriding the autonomous ranking) and marks
    # authority="operator-select"; blank/non-matching -> autonomous ranking stands (fail-safe).
    # Seeded into state0 by live_autorun (like operator_auto) and carried each tick (LastValue).
    # Deterministic (a string, never an LLM field, 불변식1.).
    operator_pick: str


def initial_state(config_version: str) -> MDGState:
    """recon_boot builds the tick-0 state (defaults per PA-3)."""
    return MDGState(
        config_version=config_version,
        worldstate=WorldState(config_version=config_version),
        evidence=[],
        trust={},
        impact=ImpactObj(),
        ledger=[],
        decisions=[],
        incidents=[],
        orient_note=None,
        decide_note=None,
        chosen_action=None,
        chosen_action_risk="LOW",
        chosen_action_reversible=True,
        legal_actions=[],
        tick_i=0,
        pivots=0,
        dry_streak=0,
        goal_reached=False,
    )


# PS-3: allow-field projection. Secrets have no field here (structural), and this
# projection additionally drops any non-declared keys before recording.
_RECORD_ALLOW = {
    "config_version", "tick_i", "pivots", "dry_streak", "goal_reached",
    "impact", "trust", "incidents", "decisions", "ledger", "evidence",
    "chosen_action_risk", "chosen_action_reversible", "worldstate",
}


def _json_safe(v: object) -> object:
    if isinstance(v, BaseModel):
        return v.model_dump()
    if isinstance(v, dict):
        return {k: _json_safe(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_json_safe(x) for x in v]
    return v


def to_record(state: MDGState) -> dict:
    """Allow-field projection for the recording hook (PS-3). No secret fields exist
    in MDGState, and undeclared keys are dropped here."""
    return {k: _json_safe(state[k]) for k in _RECORD_ALLOW if k in state}
