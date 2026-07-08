"""build_graph (PA-1/PA-8) — LangGraph StateGraph assembly.

Topology (in-graph cycles = 0, all loop-backs -> END):
  START = sense
  sense -> correlate -> compute_trust -> compute_impact
  compute_impact --[band==Green]--> END          (Green tick: no LLM)
  compute_impact --[band in {Yellow,Red}]--> orient
  orient -> select_policy -> rank_recovery -> decide
  decide --[legal ∧ risk in {LOW,MED} ∧ reversible]--> act
  decide --[risk==HIGH]--> escalate
  decide --[chosen_action is None]--> END
  act -> effect_confirm -> END
  escalate -> END

Conditional branch functions live in edges.py and read numeric/bool fields ONLY
(불변식①). recon is boot-only (not a node). recursion_limit=16 is passed at invoke
(driver) as a cycle guard.

SINGLE-SOURCED TOPOLOGY (PA-9): the node roster, the linear spine, the two conditional
branch points, and the per-node dependency-injection recipe all come from ``core.topology``
(pure data). ``e2e._TickExecutor`` (the langgraph-free interpreter) consumes the SAME datum,
so the production graph and the tested executor cannot diverge. This closes the previously
materialized drift where escalate was bound WITHOUT ``gate`` here but called WITH it there.

Dependency injection: nodes that need a queue/backend/ledger/clock/llm are bound with
functools.partial from ``topology.BIND`` so the compiled graph carries no globals.
"""
from __future__ import annotations

from functools import partial
from typing import Any, Optional

from . import edges, topology
from .nodes import NODES
from .state import MDGState

# name -> branch function (resolved here; topology holds only the NAME so it imports nothing heavy)
_BRANCH = {
    "route_after_impact": edges.route_after_impact,
    "route_after_decide": edges.route_after_decide,
}


def build_graph(deps: Optional[dict[str, Any]] = None):
    """Assemble and compile the StateGraph. deps may contain: inbox, verify, clock,
    llm_orient, llm_decide, backend, ledger, observe, source_domains. Returns a compiled
    graph. ``source_domains`` ({source_id -> domain}, from build_source_domains(collectors))
    lets sense attribute a watchdog sensor_loss to a domain for present-set exclusion (P3-Q5).

    Requires langgraph installed (python:3.12-slim image). Raises ImportError with a
    clear message otherwise — verify_graph.py does the static topology check without
    importing langgraph.
    """
    try:
        from langgraph.graph import END, START, StateGraph
    except Exception as exc:  # pragma: no cover
        raise ImportError(
            "langgraph is required to compile the graph "
            "(pip install -r requirements.txt). Static topology is checked by "
            "verify/verify_graph.py without langgraph."
        ) from exc

    d = deps or {}
    # Phase 0 wiring: normalize the sandbox OPER auto-confirm flag to a guaranteed bool so the
    # Phase 1 gate/edge can read it without re-parsing. No routing effect yet — topology.BIND does
    # not reference 'operator_auto' until Phase 1, so control flow is unchanged (불변식① 무손상,
    # 회귀 0). Shallow-copy so the caller's deps dict is not mutated.
    d = {**d, "operator_auto": bool(d.get("operator_auto"))}

    def _node(name: str):
        # bind injected deps from the ONE recipe (topology.BIND) — no globals, no drift.
        return partial(NODES[name], **topology.kwargs_for(name, d))

    def _target(label: str):
        # map the spec's END sentinel to langgraph's END; any other label is a node name.
        return END if label == topology.END else label

    g = StateGraph(MDGState)
    for name in topology.NODE_ROSTER:              # 11-node roster (PA-8), single-sourced
        g.add_node(name, _node(name))

    g.add_edge(START, topology.ENTRY)              # set_entry_point('sense')
    for src, dst in topology.LINEAR_EDGES.items():  # linear spine (loop-backs already -> END)
        g.add_edge(src, _target(dst))
    for src, (fn_name, mapping) in topology.COND_EDGES.items():  # numeric/bool routing only (불변식①)
        g.add_conditional_edges(
            src, _BRANCH[fn_name],
            {label: _target(target) for label, target in mapping.items()},
        )

    return g.compile(checkpointer=d.get("checkpointer"))
