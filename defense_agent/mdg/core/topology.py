"""topology.py (PA-9 lock) — the SINGLE declarative source of the in-graph topology.

Purpose: the 11-node linear spine, the two conditional branch points, and the per-node
dependency-injection recipe used to live in THREE hand-maintained copies —
``core/graph.py`` (the langgraph production build), ``campaign/e2e.py::_TickExecutor``
(the langgraph-free tick interpreter that CI actually runs), and (order-only)
``verifier/verifier.py::_NODE_ORDER`` (an INDEPENDENT trust root). Routing was already
single-sourced in ``edges.py``; the linear order + DI binding were not, and the escalate
``gate=`` binding had already begun to drift (graph.py bound escalate WITHOUT gate while the
executor called it WITH gate). This module collapses the two CORE copies into one datum that
``graph.build_graph`` and ``e2e._TickExecutor`` both consume, so they cannot diverge.

Trust-root isolation (PA-2 / grep0) is preserved: the Verifier still keeps its OWN
``_NODE_ORDER`` and does NOT import this module — ``verify/verify_graph.py`` cross-checks the
two copies by static text equivalence, never by a shared import (a captured core must not be
able to silence its independent checker).

PURE DATA by design: strings and dicts only — NO import of node functions, edges, langgraph,
or pydantic. This keeps the module importable by the dependency-light ``verify/`` scripts.
Branch functions and node functions are referenced BY NAME here and resolved to callables by
each consumer (which already imports ``edges`` and ``nodes``). ``END`` mirrors ``edges.END``
(and the langgraph END sentinel) — verify_graph asserts the two spellings stay equal.

불변식 preservation is structural: this module encodes ONLY node order + branch-point names +
kwarg→dep-key names. It carries NO LLM field, NO secret, NO subprocess — control flow still
routes solely through ``edges.route_after_*`` (numeric/bool), and side effects still live in the
nodes (leak-0). Changing the graph is now a one-file edit both execution paths inherit.
"""
from __future__ import annotations

# END sentinel — mirrors edges.END and the langgraph END constant ("__end__").
# Kept as a local literal (not `from .edges import END`) so this module imports nothing heavy;
# verify_graph.py asserts edges.py declares the identical spelling.
END = "__end__"

# Entry node (START -> ENTRY). recon is boot-only and NOT a graph node (PA-1).
ENTRY = "sense"

# The 11-node in-graph roster (PA-8), in canonical execution/record order.
NODE_ROSTER: tuple[str, ...] = (
    "sense", "correlate", "compute_trust", "compute_impact", "orient",
    "select_policy", "rank_recovery", "decide", "act", "effect_confirm", "escalate",
)

# Static linear successors (the spine). Conditional nodes (compute_impact, decide) are NOT
# keys here — their successor is chosen by COND_EDGES. Terminal nodes point at END.
LINEAR_EDGES: dict[str, str] = {
    "sense": "correlate",
    "correlate": "compute_trust",
    "compute_trust": "compute_impact",
    "orient": "select_policy",
    "select_policy": "rank_recovery",
    "rank_recovery": "decide",
    "act": "effect_confirm",
    "effect_confirm": END,          # loop-back rewired to END (PA-1)
    "escalate": END,
}

# Conditional branch points: node -> (branch_fn_name in edges.py, {branch_label -> target}).
# The interpreter/build resolve the fn NAME via their own edges registry; the label set is
# exactly what edges.route_after_* can return. Control flow reads numeric/bool ONLY (불변식①).
COND_EDGES: dict[str, tuple[str, dict[str, str]]] = {
    "compute_impact": ("route_after_impact", {"orient": "orient", END: END}),
    "decide": ("route_after_decide", {"act": "act", "escalate": "escalate", END: END}),
}

# The ONE dependency-injection recipe: node -> {kwarg_name: dep_key}. Both graph.build_graph
# (functools.partial) and e2e._TickExecutor (kwargs at call) bind from THIS map, so a new dep
# is added in exactly one place. Note kwarg 'llm' maps to distinct slots (llm_orient/llm_decide)
# — verify_models cross-checks that routing. escalate's 'gate' is included here to CLOSE the
# graph.py↔executor divergence (both paths now pass gate=deps['gate']).
BIND: dict[str, dict[str, str]] = {
    "sense": {"inbox": "inbox", "verify": "verify", "clock": "clock",
              "source_domains": "source_domains"},
    "correlate": {"clock": "clock"},
    "compute_trust": {},
    "compute_impact": {},
    "orient": {"llm": "llm_orient"},
    "select_policy": {},
    "rank_recovery": {},
    "decide": {"llm": "llm_decide", "clock": "clock"},
    "act": {"backend": "backend", "ledger": "ledger", "clock": "clock", "smf_table": "smf_table",
            "operator_auto": "operator_auto", "docker": "docker"},
    "effect_confirm": {"observe": "observe"},
    "escalate": {"ledger": "ledger", "clock": "clock", "gate": "gate"},
}


def derive_edges() -> list[tuple[str, str]]:
    """All (src, dst) edges implied by the spec — START->ENTRY, every linear edge, and every
    conditional-edge target — for static topology verification (verify_graph). END/START are
    emitted as the literal strings 'END'/'START' so the checker matches graph.py's sentinels."""
    out: list[tuple[str, str]] = [("START", ENTRY)]
    for s, d in LINEAR_EDGES.items():
        out.append((s, "END" if d == END else d))
    for s, (_fn, mapping) in COND_EDGES.items():
        for target in mapping.values():
            out.append((s, "END" if target == END else target))
    return out


def kwargs_for(node: str, deps: dict) -> dict:
    """Resolve BIND[node] against a deps dict -> {kwarg: deps.get(dep_key)}. The single binder
    both execution paths call so the injected arguments cannot drift."""
    return {kw: deps.get(dep_key) for kw, dep_key in BIND.get(node, {}).items()}
