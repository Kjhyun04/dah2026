"""mdg.llm — the 2-phase advice LLM package (P3, PA-4/PA-5/PS-3/PS-7).

Two litellm-backed callables (orient=Sonnet, decide=Opus per models.yaml) that the
graph injects into the orient/decide nodes as ``llm_orient`` / ``llm_decide``. Both are
temperature=0, structured (pydantic OrientNote/DecideNote), advice-only (raise-only), and
edge-invisible. Prompts are Jinja StrictUndefined with an empty-prompt guard and receive
DERIVED numeric/enum features only (PS-7). Secrets (ANTHROPIC_API_KEY) live only in the
litellm client's process env — never in State/JSONL/prompts (PS-3).

Graceful degradation: when litellm/jinja2/API key are absent, the factories return None
and the nodes use their deterministic fallback (G6). This package lives OUTSIDE mdg.core
so the deterministic core never imports the optional LLM/egress surface.
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
    """Launcher helper: build the ``{'llm_orient','llm_decide'}`` dep slice that
    graph.build_graph(deps) consumes. Values are None when the LLM path is unavailable
    (deterministic fallback, G6) — the graph is fully functional either way."""
    return {
        "llm_orient": make_orient_llm(models_cfg),
        "llm_decide": make_decide_llm(models_cfg),
    }
