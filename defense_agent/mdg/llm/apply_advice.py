"""tighten_only merge — re-export of the LOCKED implementation (core.advice, PA-5).

DESIGN_DECISIONS PA-5 locks the monotone merge at ``mdg/core/advice.py`` (imported by the
orient node inside the deterministic core, which must not import the optional llm/ deps).
The P3 scope names this file ``llm/apply_advice.py``; it exposes the SAME single
implementation — no divergent copy, no second source of the raise-only formula. The merge
raises impact.band up by severity_bump (<=1) only; ``assert new_band >= old_band`` forbids
any downgrade, so LLM advice can never override the deterministic formula toward leniency.
"""
from __future__ import annotations

from ..core.advice import apply_advice, tighten_only

__all__ = ["apply_advice", "tighten_only"]
