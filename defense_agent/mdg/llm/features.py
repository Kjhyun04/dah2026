"""피처 소독(PS-7 인젝션 게이트) — 파생(DERIVED) 수치/열거만.

orient/decide 노드가 이미 파생 피처 dict 를 만든다; 이것은 심층 방어(defense-in-depth)다:
피처가 프롬프트 템플릿에 닿기 전에 닫힌 화이트리스트를 통과해야 한다. raw
자유텍스트, 초과 크기 문자열, 잘못된 타입, 또는 열거 밖 값은 LLMUnavailable 를 raise 한다
(fail-safe -> 노드는 결정론 테이블로 폴백, G6). 여분 키는
드롭된다(결코 전달 안 함), 따라서 주입된 wire 문자열이 프롬프트로 올라탈 수 없다.
"""
from __future__ import annotations

from .render import LLMUnavailable

_MAX_ENUM_LEN = 32

# schema 값은 frozenset(허용 열거 문자열) 또는 타입(int/float/bool) 중 하나.
ORIENT_FEATURES: dict[str, object] = {
    "impact_band": frozenset({"Green", "Yellow", "Red"}),
    "impact_score": int,
    "n_incidents": int,
    "min_trust": float,
}

DECIDE_FEATURES: dict[str, object] = {
    "impact_band": frozenset({"Green", "Yellow", "Red"}),
    "risk": frozenset({"LOW", "MED", "HIGH"}),
    "reversible": bool,
    "has_action": bool,
}


def _as_int(v: object) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise LLMUnavailable(f"expected int, got {type(v).__name__}")
    return v


def _as_float(v: object) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise LLMUnavailable(f"expected number, got {type(v).__name__}")
    return float(v)


def _as_bool(v: object) -> bool:
    if not isinstance(v, bool):
        raise LLMUnavailable(f"expected bool, got {type(v).__name__}")
    return v


def sanitize(features: dict, schema: dict[str, object]) -> dict:
    """features 를 schema 에 투영한다(닫힌 화이트리스트). 화이트리스트 키만
    살아남고; 모든 값은 타입/열거 검사된다. 누락이거나 부적합 -> LLMUnavailable."""
    out: dict = {}
    for key, rule in schema.items():
        if key not in features:
            raise LLMUnavailable(f"missing feature: {key}")
        v = features[key]
        if isinstance(rule, frozenset):
            if not isinstance(v, str) or len(v) > _MAX_ENUM_LEN or v not in rule:
                raise LLMUnavailable(f"bad enum {key}={v!r}")
            out[key] = v
        elif rule is bool:
            out[key] = _as_bool(v)
        elif rule is int:
            out[key] = _as_int(v)
        elif rule is float:
            out[key] = _as_float(v)
        else:  # pragma: no cover - schema 작성 오류
            raise LLMUnavailable(f"unknown schema rule for {key}")
    return out
