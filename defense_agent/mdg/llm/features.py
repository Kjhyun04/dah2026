"""Feature sanitization (PS-7 injection gate) — DERIVED numeric/enum only.

The orient/decide nodes already build derived feature dicts; this is defense-in-depth:
before a feature reaches a prompt template it must pass a closed whitelist. Any raw
free-text, oversized string, wrong type, or out-of-enum value raises LLMUnavailable
(fail-safe -> the node falls back to the deterministic table, G6). Extra keys are
dropped (never forwarded), so an injected wire string cannot ride into the prompt.
"""
from __future__ import annotations

from .render import LLMUnavailable

_MAX_ENUM_LEN = 32

# schema value is either a frozenset (allowed enum strings) or a type (int/float/bool).
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
    """Project ``features`` onto ``schema`` (closed whitelist). Only whitelisted keys
    survive; every value is type/enum-checked. Missing or invalid -> LLMUnavailable."""
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
        else:  # pragma: no cover - schema authoring error
            raise LLMUnavailable(f"unknown schema rule for {key}")
    return out
