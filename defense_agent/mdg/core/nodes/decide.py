"""decide (LLM2, PA-4/PA-5) — advice ONLY. Writes decide_note; NEVER sets
chosen_action/chosen_action_risk/chosen_action_reversible (those are rank_recovery's,
PA-4). Emits a Decision record. Render/error -> deterministic fallback (G6). The
decide-edge reads risk/reversible fields set upstream, not this note.
"""
from __future__ import annotations

from ..state import Decision, DecideNote, MDGState


def _fallback_note() -> DecideNote:
    return DecideNote(rationale="fallback: deterministic", escalate_recommended=False)


def decide(state: MDGState, llm=None, clock=None) -> dict:
    chosen = state.get("chosen_action")
    impact = state.get("impact")
    ts = clock.now() if clock is not None else 0.0

    features = {
        "impact_band": getattr(impact, "band", "Green"),
        "risk": state.get("chosen_action_risk", "LOW"),
        "reversible": state.get("chosen_action_reversible", True),
        "has_action": chosen is not None,
    }
    if llm is None:
        note = _fallback_note()
    else:
        try:
            note = llm(features)
            if not isinstance(note, DecideNote):
                note = _fallback_note()
        except Exception:
            note = _fallback_note()

    # Decision record (flight action enforcement always operator_confirm, X2)
    risk = state.get("chosen_action_risk", "LOW")
    enforcement = "operator_confirm" if risk == "HIGH" else "auto"
    decision = Decision(
        id=f"dec-{state.get('tick_i', 0)}",
        decision="Operator Confirmation" if risk == "HIGH" else (
            "Continue+Monitoring" if chosen is None else "Mission Reconfiguration"),
        enforcement=enforcement,
        config_version=state.get("config_version", ""),
        ts=ts,
        mission_impact=getattr(impact, "score", 0),
    )

    out: dict = {"decide_note": note, "decisions": [decision]}       # decisions accumulator
    if chosen is None:
        out["dry_streak"] = int(state.get("dry_streak", 0)) + 1      # no-legal -> dry (PA-1)
    return out
