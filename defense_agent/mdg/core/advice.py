"""apply_advice / tighten_only — monotone merge of LLM advice (PA-5).

LLM notes may only TIGHTEN (raise impact band up by severity_bump, magnitude<=1).
Downgrades are forbidden (assert new_band >= old_band). risk downgrade, legal-set
expansion, escalation downgrade are all impossible here. Notes NEVER enter edge
functions — apply_advice only mutates impact.band upward, and edges read the band.
"""
from __future__ import annotations

from .scoring import bump_band
from .state import ImpactObj, MDGState, OrientNote

_BAND_ORDER = ["Green", "Yellow", "Red"]


def _rank(band: str) -> int:
    return _BAND_ORDER.index(band)


def tighten_only(old_band: str, severity_bump: int) -> str:
    """Raise-only band merge. severity_bump in {0,1}; downgrade impossible."""
    bump = 1 if severity_bump >= 1 else 0
    new_band = bump_band(old_band, bump)
    assert _rank(new_band) >= _rank(old_band), "tighten_only violated: downgrade attempted"
    return new_band


def apply_advice(state: MDGState, note: OrientNote) -> dict:
    """Pure monotone merge. Returns a channel update dict (impact only).

    Only impact.band moves, and only upward. If Green tick ended before orient this
    is never called (routing already routed to END)."""
    impact: ImpactObj = state.get("impact") or ImpactObj()
    old_band = impact.band
    new_band = tighten_only(old_band, note.severity_bump)
    if new_band == old_band:
        return {}
    updated = impact.model_copy(deep=True)
    updated.band = new_band                                  # type: ignore[assignment]
    updated.confidence_margin = max(updated.confidence_margin, float(note.severity_bump))
    return {"impact": updated}
