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


def has_api_key(api_key_env: str | None = None) -> bool:
    """LLM 크리덴셜 존재 여부. provider 를 하드코딩하지 않는다 — models.yaml 의 최상위
    ``api_key_env`` (없으면 ANTHROPIC_API_KEY) 가 가리키는 환경변수를 확인한다. OpenRouter 경유
    운영 시 운영자는 models.yaml 에 ``api_key_env: OPENROUTER_API_KEY`` 를 두면 된다."""
    return bool(os.environ.get(api_key_env or "ANTHROPIC_API_KEY"))


def resolve_api_key(models_cfg: dict | None = None) -> str | None:
    """Resolve the key VALUE from the env NAME in models.yaml (api_key_env), to pass
    EXPLICITLY to litellm so ANY provider authenticates from the operator's single .env key
    even under a non-conventional env name (e.g. MDG_LLM_API_KEY). None => unset (caller is
    already gated by has_api_key). Never logged / never placed in messages/State (PS-3)."""
    name = models_cfg.get("api_key_env") if isinstance(models_cfg, dict) else None
    return os.environ.get(name or "ANTHROPIC_API_KEY") or None


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
                        model_cls: Type[BaseModel], timeout_s: float = 5.0,
                        api_key: str | None = None) -> BaseModel:
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
            )
            if api_key:
                kwargs["api_key"] = api_key   # provider-agnostic: 운영자의 단일 .env 키를 명시 주입
            # json_schema response_format 는 Anthropic 직결(anthropic/*)에서만 신뢰성 있게
            # 지원된다. OpenRouter 등 경유 라우팅(openrouter/*)은 이 파라미터를 Anthropic 백엔드로
            # 그대로 전달하지 못해 400/타입위반을 유발하므로 anthropic/* 모델에만 첨부한다. 응답
            # 파싱은 _parse_capped 의 model_validate_json 이 authoritative 게이트라 생략해도 안전.
            if str(model).lower().startswith("anthropic/"):
                kwargs["response_format"] = response_format
            if _emit_temperature(model):
                kwargs["temperature"] = 0    # FORCED for sampling-accepting families
            resp = litellm.completion(**kwargs)
            content = resp["choices"][0]["message"]["content"]
            return _parse_capped(content, model_cls)     # byte-cap + authoritative local parse
        except Exception as exc:                     # network/timeout/parse/schema/cap
            last_exc = exc
            continue
    raise LLMUnavailable(f"all models failed for {model_cls.__name__}: {last_exc}")
