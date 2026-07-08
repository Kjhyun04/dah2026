"""orient (LLM1, PA-5/PS-7) — temp=0 structured advice, tighten-only.

Inputs to the prompt are DERIVED NUMERIC/ENUM ONLY (counts/band/bools) — never raw
wire/telemetry free text (PS-7 injection gate). Produces OrientNote (raise-only).
apply_advice merges monotonically (band up only). Render/empty/schema error ->
deterministic fallback (G6): OrientNote() with no bump. Edges NEVER read the note.
"""
from __future__ import annotations

from ..advice import apply_advice
from ..state import MDGState, OrientNote


def _fallback_note() -> OrientNote:
    return OrientNote(rationale="fallback: deterministic", severity_bump=0)


def orient(state: MDGState, llm=None) -> dict:
    """llm: callable(features)->OrientNote injected by graph; default = fallback (G6)."""
    impact = state.get("impact")
    trust = state.get("trust", {})
    incidents = state.get("incidents", [])

    # derived features only (PS-7): no raw strings
    features = {
        "impact_band": getattr(impact, "band", "Green"),
        "impact_score": getattr(impact, "score", 0),
        "n_incidents": len(incidents),
        "min_trust": min((t.trust_score for t in trust.values()), default=100.0),
    }

    if llm is None:
        note = _fallback_note()
    else:
        try:
            note = llm(features)
            if not isinstance(note, OrientNote):
                note = _fallback_note()
        except Exception:
            note = _fallback_note()

    out: dict = {"orient_note": note}
    out.update(apply_advice(state, note))       # monotone band raise only
    return out
