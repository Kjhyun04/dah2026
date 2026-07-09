"""decide (LLM2, PA-4/PA-5) — advice 전용(ONLY). decide_note 를 쓴다;
chosen_action/chosen_action_risk/chosen_action_reversible 는 절대(NEVER) 설정하지 않는다
(그것들은 rank_recovery 의 몫, PA-4). Decision record 를 emit 한다. Render/error 시
-> deterministic fallback (G6). decide-edge 는 이 note 가 아니라 upstream 에서 설정된
risk/reversible 필드를 읽는다.
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

    # Decision record (비행 action enforcement 은 항상 operator_confirm, X2)
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

    out: dict = {"decide_note": note, "decisions": [decision]}       # decisions 누산기
    if chosen is None:
        out["dry_streak"] = int(state.get("dry_streak", 0)) + 1      # legal 없음 -> dry (PA-1)
    return out
