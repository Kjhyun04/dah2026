"""orient (LLM1, PA-5/PS-7) — temp=0 구조화 조언, 강화 전용(tighten-only).

프롬프트 입력은 파생 수치/열거 값만(counts/band/bools) — 원시
wire/telemetry 자유 텍스트는 절대 아님(PS-7 인젝션 게이트). OrientNote 를 생성(상향 전용).
apply_advice 는 단조 병합한다(band 상향만). 렌더/빈값/스키마 오류 ->
결정론 폴백(G6): bump 없는 OrientNote(). 엣지는 노트를 절대 읽지 않는다.
"""
from __future__ import annotations

from ..advice import apply_advice
from ..state import MDGState, OrientNote


def _fallback_note() -> OrientNote:
    return OrientNote(rationale="fallback: deterministic", severity_bump=0)


def orient(state: MDGState, llm=None) -> dict:
    """llm: 그래프가 주입하는 callable(features)->OrientNote; 기본값 = 폴백(G6)."""
    impact = state.get("impact")
    trust = state.get("trust", {})
    incidents = state.get("incidents", [])

    # 파생 피처만(PS-7): 원시 문자열 없음
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
    out.update(apply_advice(state, note))       # 단조 band 상향만
    return out
