"""프롬프트 렌더링 (PA-5/PS-7 · P3 llm/prompts) — Jinja StrictUndefined + 가드.

LLM 조언 경로는 선택적(OPTIONAL)이다. jinja2(또는 litellm, 또는 API 키)가 없으면
팩토리는 None 을 반환하고 orient/decide 노드는 결정론 테이블로 폴백한다
(G6). 이 모듈은 모델과 무관하게 성립하는 두 가드를 소유한다:

  * StrictUndefined  — 누락된 템플릿 변수는 raise(조용한 빈 프롬프트 없음).
  * guard_nonempty   — 비었거나 공백뿐인 프롬프트는 결코 모델에 닿지 않는다.

템플릿은 파생(DERIVED) 수치/열거 컨텍스트만 받는다(features.py 에서 소독); raw
wire/텔레메트리 자유텍스트는 결코 보간되지 않는다(PS-7 인젝션 게이트).
"""
from __future__ import annotations

import os
from typing import Any

_PROMPT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prompts")


class LLMUnavailable(RuntimeError):
    """LLM 조언 경로가 실행될 수 없음(의존성/키/템플릿 누락, 렌더/공백 가드,
    또는 모델 에러). orient/decide 노드가 이를 잡아 결정론 결정
    테이블로 폴백한다(G6). 결코 라우팅으로 전파되지 않는다(불변식1.)."""


def jinja_available() -> bool:
    try:
        import jinja2  # noqa: F401
        return True
    except Exception:
        return False


def _env():
    import jinja2
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(_PROMPT_DIR),
        undefined=jinja2.StrictUndefined,   # 누락 변수 -> UndefinedError(빈 값 없음)
        autoescape=False,                   # HTML 아닌 평문 프롬프트
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=False,
    )


def guard_nonempty(text: str) -> str:
    """빈 프롬프트 가드: 비었거나 공백뿐인 프롬프트는 결코 모델에 닿아선 안 된다."""
    if text is None or not str(text).strip():
        raise LLMUnavailable("empty prompt after render (guard)")
    return text


def render(template_name: str, context: dict[str, Any]) -> str:
    """StrictUndefined + 빈 프롬프트 가드로 프롬프트 템플릿을 렌더한다.

    jinja2 없음, 템플릿 없음, 정의되지 않은 변수, 또는 빈 출력 시 LLMUnavailable 를
    raise 한다 — 그러면 노드는 결정론적으로 폴백한다(G6)."""
    if not jinja_available():
        raise LLMUnavailable("jinja2 not installed")
    try:
        tmpl = _env().get_template(template_name)
        text = tmpl.render(**context)
    except LLMUnavailable:
        raise
    except Exception as exc:  # UndefinedError, TemplateNotFound, ...
        raise LLMUnavailable(f"render failed for {template_name}: {exc}") from exc
    return guard_nonempty(text)
