"""litellm structured-completion wrapper (FRAMEWORK_STACK §0/§6 · PA-5 · P3-Q6).

Single narrow surface onto litellm. Enforced invariants:
  * temperature = 0 for sampling-accepting model families (forced here, not trusted from
    config) — replay determinism. Reject-sampling families (Opus 4.8/4.7, Sonnet 5, Fable/
    Mythos) 400 on any `temperature`; for those the field is OMITTED (their fixed decoding
    already satisfies determinism). See `_emit_temperature`. `drop_params=True` is the
    second safety net for any model this gate misclassifies (P3-Q6 ADD-3/FIX-4).
  * `num_retries=0` — litellm may otherwise retry internally, which (a) blows the 5s wall so
    `timeout_s` stops being a true deadline and (b) injects nondeterministic multi-call
    behavior. The hand-rolled `for model in models` loop is the ONLY fallback mechanism.
  * timeout (models.yaml timeout_s, default 5s) per attempt; on timeout/error the caller
    raises -> node deterministic fallback (G6/E13).
  * structured output: response_format=json_schema (a best-effort provider constraint on the
    anthropic provider; bare json_object is only weakly emulated). The AUTHORITATIVE gate is
    the local `model_cls.model_validate_json` under strict bounds (extra='forbid' + constr/
    Literal, PA-5). A raw-byte cap runs BEFORE parse to bound parse-side DoS. Provider-side
    enforcement is never the security control — parse failure -> LLMUnavailable.

Secrets (PS-3): ANTHROPIC_API_KEY is read by litellm from the process env — it is NEVER
placed in messages, State, or logs. Prompts carry derived features only (PS-7).
"""
from __future__ import annotations

import os
from typing import Type

from pydantic import BaseModel

from ..config import loader
from .render import LLMUnavailable

# Anthropic families that REJECT `temperature`/sampling params with HTTP 400 (current-gen:
# Opus 4.8/4.7, Sonnet 5, Fable/Mythos). Emitting temperature=0 to these is a silent
# kill-switch -> permanent G6 fallback. Substring-matched on the litellm model id.
_REJECT_SAMPLING = ("opus-4-8", "opus-4-7", "sonnet-5", "fable", "mythos")

# Anthropic families KNOWN to ACCEPT `temperature` (older sampling decoders). An Anthropic
# model in NEITHER list is treated as reject-sampling (FAIL-SAFE): the newest generations
# reject sampling, so an unlisted FUTURE Anthropic model must not be sent temperature — a
# 400 would silently and permanently fall it back. Omitting only forgoes the determinism=0 nudge.
_ACCEPT_SAMPLING = ("sonnet-4-5", "haiku-4-5")

# Hard cap on the raw response string fed to model_validate_json (parse-side DoS bound;
# pydantic field limits run AFTER the parse). thresholds.yaml override -> constant default.
_DEFAULT_MAX_BYTES = 16384


def litellm_available() -> bool:
    try:
        import litellm  # noqa: F401
        return True
    except Exception:
        return False


def has_api_key() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def _emit_temperature(model: str) -> bool:
    """True iff we should send `temperature=0` to `model`.

    Reject-sampling Anthropic family -> False (omit; else HTTP 400). Known sampling-
    accepting Anthropic family -> True (emit 0 for determinism). UNKNOWN Anthropic model
    -> False (FAIL-SAFE: assume newest-gen reject-sampling; omit rather than 400-and-die).
    Non-Anthropic provider -> True (accepts temperature; emit 0 for determinism)."""
    m = (model or "").lower()
    if any(fam in m for fam in _REJECT_SAMPLING):
        return False
    if any(fam in m for fam in _ACCEPT_SAMPLING):
        return True
    return not (("anthropic" in m) or ("claude" in m))


def _response_max_bytes() -> int:
    try:
        thr = loader.thresholds()
        if isinstance(thr, dict) and "llm_response_max_bytes" in thr:
            return int(thr["llm_response_max_bytes"])
    except Exception:
        pass
    return _DEFAULT_MAX_BYTES


def _extract_json(content: str) -> str:
    """Strip an optional ```json ... ``` fence some models emit around JSON."""
    s = (content or "").strip()
    if s.startswith("```"):
        s = s[3:]
        nl = s.find("\n")
        if nl != -1 and s[:nl].strip().lower() in ("json", ""):
            s = s[nl + 1:]
        if "```" in s:
            s = s[: s.rfind("```")]
    return s.strip()


def _parse_capped(content: str, model_cls: Type[BaseModel]) -> BaseModel:
    """Byte-cap the raw response, then local validate (authoritative gate). Oversized or
    unparseable -> raises (caught by the caller's fallback loop)."""
    raw = content or ""
    cap = _response_max_bytes()
    if len(raw.encode("utf-8", "ignore")) > cap:
        raise ValueError(f"response exceeds {cap}-byte cap")
    return model_cls.model_validate_json(_extract_json(raw))


def _schema_response_format(model_cls: Type[BaseModel]) -> dict:
    """json_schema response_format (best-effort provider constraint; local parse is the
    real gate). drop_params=True drops it if the route rejects it."""
    return {
        "type": "json_schema",
        "json_schema": {"name": model_cls.__name__, "schema": model_cls.model_json_schema()},
    }


def complete_structured(role_cfg: dict, system: str, user: str,
                        model_cls: Type[BaseModel], timeout_s: float = 5.0) -> BaseModel:
    """Call litellm with the role's model chain and parse into ``model_cls``.

    Raises LLMUnavailable if litellm is absent, no model is configured, or every model
    in the chain errors/times out / returns unparseable/oversized output. The orient/decide
    node catches this and falls back deterministically (G6)."""
    if not litellm_available():
        raise LLMUnavailable("litellm not installed")
    import litellm

    models = [role_cfg.get("model")] + list(role_cfg.get("fallback", []) or [])
    models = [m for m in models if m]
    if not models:
        raise LLMUnavailable("no model configured for role")
    max_tokens = int(role_cfg.get("max_tokens", 1024))
    response_format = _schema_response_format(model_cls)

    last_exc: Exception | None = None
    for model in models:
        try:
            kwargs = dict(
                model=model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                max_tokens=max_tokens,
                timeout=timeout_s,
                num_retries=0,               # 5s deadline is real; loop is the ONLY fallback
                drop_params=True,            # provider-unsupported params dropped, not 400
                response_format=response_format,
            )
            if _emit_temperature(model):
                kwargs["temperature"] = 0    # FORCED for sampling-accepting families
            resp = litellm.completion(**kwargs)
            content = resp["choices"][0]["message"]["content"]
            return _parse_capped(content, model_cls)     # byte-cap + authoritative local parse
        except Exception as exc:                     # network/timeout/parse/schema/cap
            last_exc = exc
            continue
    raise LLMUnavailable(f"all models failed for {model_cls.__name__}: {last_exc}")
