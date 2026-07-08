"""Prompt rendering (PA-5/PS-7 · P3 llm/prompts) — Jinja StrictUndefined + guards.

The LLM advice path is OPTIONAL. When jinja2 (or litellm, or the API key) is absent,
the factories return None and the orient/decide nodes fall back to the deterministic
table (G6). This module owns two guards that hold regardless of model:

  * StrictUndefined  — a missing template variable raises (no silent blank prompt).
  * guard_nonempty   — an empty/whitespace prompt never reaches the model.

Templates receive DERIVED numeric/enum context only (sanitized in features.py); no raw
wire/telemetry free text is ever interpolated (PS-7 injection gate).
"""
from __future__ import annotations

import os
from typing import Any

_PROMPT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prompts")


class LLMUnavailable(RuntimeError):
    """The LLM advice path cannot run (missing dep/key/template, render/empty guard,
    or model error). orient/decide nodes CATCH this and fall back to the deterministic
    decision table (G6). Never propagates into routing (불변식①)."""


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
        undefined=jinja2.StrictUndefined,   # missing var -> UndefinedError (no blank)
        autoescape=False,                   # plain-text prompt, not HTML
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=False,
    )


def guard_nonempty(text: str) -> str:
    """Empty-prompt guard: a blank/whitespace prompt must never reach the model."""
    if text is None or not str(text).strip():
        raise LLMUnavailable("empty prompt after render (guard)")
    return text


def render(template_name: str, context: dict[str, Any]) -> str:
    """Render a prompt template with StrictUndefined + empty-prompt guard.

    Raises LLMUnavailable on missing jinja2, missing template, undefined variable, or
    empty output — the node then falls back deterministically (G6)."""
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
