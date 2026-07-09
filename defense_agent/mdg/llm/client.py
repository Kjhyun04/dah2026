"""litellm 구조화 컴플리션 래퍼 (FRAMEWORK_STACK §0/§6 · PA-5 · P3-Q6).

litellm 위의 단일 좁은 표면. 강제 불변식:
  * 샘플링을 수용하는 모델 계열에는 temperature = 0 (config 를 신뢰하지 않고 여기서
    강제) — 리플레이 결정론. reject-sampling 계열(Opus 4.8/4.7, Sonnet 5, Fable/
    Mythos)은 어떤 `temperature` 에도 400 을 낸다; 그런 계열에는 이 필드를 생략한다(고정 디코딩이
    이미 결정론을 만족). `_emit_temperature` 참조. `drop_params=True` 는 이 게이트가
    오분류하는 모든 모델에 대한 2차 안전망이다(P3-Q6 ADD-3/FIX-4).
  * `num_retries=0` — 그러지 않으면 litellm 이 내부적으로 재시도할 수 있는데, 이는 (a) 5s 벽을 넘겨
    `timeout_s` 가 진짜 데드라인이 아니게 만들고 (b) 비결정적 다중호출
    동작을 주입한다. 손수 짠 `for model in models` 루프가 유일한 폴백 메커니즘이다.
  * 시도마다 timeout(models.yaml timeout_s, 기본 5s); 타임아웃/에러 시 호출자가
    raise -> 노드 결정론 폴백(G6/E13).
  * 구조화 출력: response_format=json_schema (anthropic provider 상의 best-effort provider
    제약; 맨 json_object 는 약하게만 흉내낸다). authoritative 게이트는 엄격한 경계 하의
    로컬 `model_cls.model_validate_json` 이다(extra='forbid' + constr/
    Literal, PA-5). raw-byte 상한이 파싱 전에 돌아 parse-side DoS 를 제한한다. provider 측
    강제는 결코 보안 통제가 아니다 — 파싱 실패 -> LLMUnavailable.

시크릿(PS-3): ANTHROPIC_API_KEY 는 litellm 이 프로세스 env 에서 읽는다 — 결코 메시지·State·로그에
넣지 않는다. 프롬프트는 파생 피처만 실어 나른다(PS-7).
"""
from __future__ import annotations

import os
from typing import Type

from pydantic import BaseModel

from ..config import loader
from .render import LLMUnavailable

# HTTP 400 으로 `temperature`/샘플링 파라미터를 거부(REJECT)하는 Anthropic 계열(현세대:
# Opus 4.8/4.7, Sonnet 5, Fable/Mythos). 이들에 temperature=0 을 보내는 것은 조용한
# kill-switch -> 영구 G6 폴백이다. litellm 모델 id 에 부분문자열 매칭한다.
_REJECT_SAMPLING = ("opus-4-8", "opus-4-7", "sonnet-5", "fable", "mythos")

# `temperature` 를 수용(ACCEPT)한다고 알려진 Anthropic 계열(구형 샘플링 디코더). 두 목록 어디에도
# 없는 Anthropic 모델은 reject-sampling 으로 취급한다(FAIL-SAFE): 최신 세대는 샘플링을
# 거부하므로, 목록에 없는 미래(FUTURE) Anthropic 모델에는 temperature 를 보내면 안 된다 —
# 400 이 조용히 영구적으로 폴백시킬 것이다. 생략은 determinism=0 넛지를 포기할 뿐이다.
_ACCEPT_SAMPLING = ("sonnet-4-5", "haiku-4-5")

# model_validate_json 에 넣는 raw 응답 문자열의 하드 상한(parse-side DoS 경계;
# pydantic 필드 제한은 파싱 후에 돈다). thresholds.yaml 오버라이드 -> 상수 기본값.
_DEFAULT_MAX_BYTES = 16384


def litellm_available() -> bool:
    try:
        import litellm  # noqa: F401
        return True
    except Exception:
        return False


# P4 단일 설정원: api_key_env 미지정 시의 기본 env 이름을 한 곳에서만 정의한다(has_api_key/
#   resolve_api_key 두 곳의 리터럴 중복 제거 → 드리프트 방지). provider 는 models.yaml api_key_env 로 선택.
_DEFAULT_API_KEY_ENV = "ANTHROPIC_API_KEY"


def has_api_key(api_key_env: str | None = None) -> bool:
    """LLM 크리덴셜 존재 여부. provider 를 하드코딩하지 않는다 — models.yaml 의 최상위
    ``api_key_env`` (없으면 _DEFAULT_API_KEY_ENV) 가 가리키는 환경변수를 확인한다. OpenRouter 경유
    운영 시 운영자는 models.yaml 에 ``api_key_env: OPENROUTER_API_KEY`` 를 두면 된다."""
    return bool(os.environ.get(api_key_env or _DEFAULT_API_KEY_ENV))


def resolve_api_key(models_cfg: dict | None = None) -> str | None:
    """models.yaml 의 env 이름(api_key_env)에서 키 값(VALUE)을 해석해, litellm 에 명시적으로
    전달한다 — 관례를 벗어난 env 이름(예: MDG_LLM_API_KEY)에서도 어떤 provider 든 운영자의 단일
    .env 키로 인증하도록. None => 미설정(호출자는 이미 has_api_key 로 게이트됨). 결코 로그에
    남기지 않고 / 메시지·State 에 넣지 않는다(PS-3)."""
    name = models_cfg.get("api_key_env") if isinstance(models_cfg, dict) else None
    return os.environ.get(name or _DEFAULT_API_KEY_ENV) or None


def _emit_temperature(model: str) -> bool:
    """`model` 에 `temperature=0` 을 보내야 하면(iff) True.

    reject-sampling Anthropic 계열 -> False(생략; 아니면 HTTP 400). 샘플링을 수용한다고
    알려진 Anthropic 계열 -> True(결정론 위해 0 방출). 알 수 없는(UNKNOWN) Anthropic 모델
    -> False(FAIL-SAFE: 최신세대 reject-sampling 으로 가정; 400 으로 죽기보다 생략).
    non-Anthropic provider -> True(temperature 수용; 결정론 위해 0 방출)."""
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
    """일부 모델이 JSON 주위에 내는 선택적 ```json ... ``` 펜스를 벗겨낸다."""
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
    """raw 응답을 byte-cap 한 뒤 로컬 검증(authoritative 게이트). 초과 크기이거나
    파싱 불가 -> raise(호출자의 폴백 루프가 잡음)."""
    raw = content or ""
    cap = _response_max_bytes()
    if len(raw.encode("utf-8", "ignore")) > cap:
        raise ValueError(f"response exceeds {cap}-byte cap")
    return model_cls.model_validate_json(_extract_json(raw))


def _schema_response_format(model_cls: Type[BaseModel]) -> dict:
    """json_schema response_format(best-effort provider 제약; 로컬 파싱이 진짜
    게이트). 라우트가 거부하면 drop_params=True 가 이를 드롭한다."""
    return {
        "type": "json_schema",
        "json_schema": {"name": model_cls.__name__, "schema": model_cls.model_json_schema()},
    }


def complete_structured(role_cfg: dict, system: str, user: str,
                        model_cls: Type[BaseModel], timeout_s: float = 5.0,
                        api_key: str | None = None) -> BaseModel:
    """role 의 모델 체인으로 litellm 을 호출해 ``model_cls`` 로 파싱한다.

    litellm 이 없거나, 설정된 모델이 없거나, 체인의 모든 모델이 에러/타임아웃 /
    파싱불가·초과크기 출력을 반환하면 LLMUnavailable 를 raise 한다. orient/decide
    노드가 이를 잡아 결정론적으로 폴백한다(G6)."""
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
                num_retries=0,               # 5s 데드라인은 실효적; 루프가 유일한 폴백
                drop_params=True,            # provider 미지원 파라미터는 400 대신 드롭
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
            return _parse_capped(content, model_cls)     # byte-cap + authoritative 로컬 파싱
        except Exception as exc:                     # 네트워크/타임아웃/파싱/스키마/cap
            last_exc = exc
            continue
    raise LLMUnavailable(f"all models failed for {model_cls.__name__}: {last_exc}")
