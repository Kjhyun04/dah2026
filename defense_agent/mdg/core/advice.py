"""apply_advice / tighten_only — LLM advice 의 단조(monotone) 병합 (PA-5).

LLM note 는 오직 TIGHTEN 만 가능하다(impact band 를 severity_bump 만큼 상향, magnitude<=1).
강등은 금지된다(assert new_band >= old_band). risk 강등, legal-set 확장,
escalation 강등은 여기서 전부 불가능하다. note 는 절대 edge 함수에 들어가지 않는다 —
apply_advice 는 impact.band 를 상향으로만 변경하고, edge 는 그 band 를 읽는다.
"""
from __future__ import annotations

from .scoring import bump_band
from .state import ImpactObj, MDGState, OrientNote

_BAND_ORDER = ["Green", "Yellow", "Red"]


def _rank(band: str) -> int:
    return _BAND_ORDER.index(band)


def tighten_only(old_band: str, severity_bump: int) -> str:
    """상향 전용 band 병합. severity_bump 는 {0,1}; 강등 불가."""
    bump = 1 if severity_bump >= 1 else 0
    new_band = bump_band(old_band, bump)
    assert _rank(new_band) >= _rank(old_band), "tighten_only violated: downgrade attempted"
    return new_band


def apply_advice(state: MDGState, note: OrientNote) -> dict:
    """순수 단조 병합. 채널 업데이트 dict(impact 만)를 반환한다.

    impact.band 만, 그것도 상향으로만 움직인다. Green 틱이 orient 이전에 끝났다면 이 함수는
    호출되지 않는다(routing 이 이미 END 로 라우팅함)."""
    impact: ImpactObj = state.get("impact") or ImpactObj()
    old_band = impact.band
    new_band = tighten_only(old_band, note.severity_bump)
    if new_band == old_band:
        return {}
    updated = impact.model_copy(deep=True)
    updated.band = new_band                                  # type: ignore[assignment]
    updated.confidence_margin = max(updated.confidence_margin, float(note.severity_bump))
    return {"impact": updated}
