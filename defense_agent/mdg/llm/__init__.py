"""mdg.llm — 2단계 advice LLM 패키지(P3, PA-4/PA-5/PS-3/PS-7).

graph가 orient/decide node에 ``llm_orient`` / ``llm_decide``로 주입하는, litellm 기반의
두 callable(models.yaml에 따라 orient=Sonnet, decide=Opus). 둘 다 temperature=0,
구조화됨(pydantic OrientNote/DecideNote), advice-only(raise-only), 그리고 edge-invisible이다.
프롬프트는 empty-prompt 가드가 있는 Jinja StrictUndefined이며 DERIVED된 numeric/enum
피처만 받는다(PS-7). 시크릿(ANTHROPIC_API_KEY)은 litellm 클라이언트의 프로세스 env에만
존재한다 — State/JSONL/프롬프트에는 결코 담기지 않는다(PS-3).

우아한 성능 저하(graceful degradation): litellm/jinja2/API key가 없으면 팩토리는 None을
반환하고 node는 결정론적 fallback을 사용한다(G6). 이 패키지는 mdg.core 바깥에 있으므로
결정론적 core는 선택적 LLM/egress 표면을 결코 import하지 않는다.
"""
from __future__ import annotations

from .apply_advice import apply_advice, tighten_only
from .decide import make_decide_llm
from .orient import make_orient_llm
from .render import LLMUnavailable

__all__ = [
    "make_orient_llm", "make_decide_llm", "build_llm_deps",
    "apply_advice", "tighten_only", "LLMUnavailable",
]


def build_llm_deps(models_cfg: dict | None = None) -> dict:
    """Launcher 헬퍼: graph.build_graph(deps)가 소비하는 ``{'llm_orient','llm_decide'}``
    dep slice를 만든다. LLM 경로를 사용할 수 없으면 값은 None이다(결정론적 fallback, G6) —
    어느 경우든 graph는 완전히 동작한다."""
    return {
        "llm_orient": make_orient_llm(models_cfg),
        "llm_decide": make_decide_llm(models_cfg),
    }
