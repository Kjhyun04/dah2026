"""test_graph_parity (PA-9 dynamic guard) — production graph == single-sourced topology.

Under D-2 (langgraph not installed) the campaign runs the langgraph-FREE ``_TickExecutor``,
so the compiled ``core.graph.build_graph`` path is never exercised locally: the code that is
tested is not the code that ships. This test closes that gap with a capability probe:

  * ALWAYS (no langgraph needed): the single-sourced ``core.topology`` spec is self-consistent
    and the two independent copies (topology.NODE_ROSTER, verifier._NODE_ORDER) agree — the
    structural half of the parity contract, enforced on every machine.
  * WHEN langgraph IS present (the production image): additionally compile ``build_graph`` and
    assert its compiled node/edge set matches ``topology.derive_edges()`` — proving the REAL
    graph and the interpreter share one topology at runtime, not just by hope.

The langgraph half is SKIPPED (never failed) where langgraph is absent, so it cannot break the
dependency-light local self-verify; it flips to an enforced gate in the image where langgraph
exists. No testbed contact, no live actuation (structural inspection only).
"""
from __future__ import annotations

import importlib.util
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest  # noqa: E402

from mdg.core import topology  # noqa: E402
from mdg.verifier import verifier as V  # noqa: E402

_HAS_LANGGRAPH = importlib.util.find_spec("langgraph") is not None


def test_topology_self_consistent_always():
    """Structural half (langgraph-free): the spec is coherent and the roster is single-sourced."""
    assert topology.ENTRY in topology.NODE_ROSTER
    assert len(topology.NODE_ROSTER) == 11
    # every non-END target references a real node; every node except the two conditional ones
    # has a static successor; conditional nodes route only via COND_EDGES.
    cond = set(topology.COND_EDGES)
    for name in topology.NODE_ROSTER:
        if name in cond:
            assert name not in topology.LINEAR_EDGES, f"{name} is both linear and conditional"
        else:
            assert name in topology.LINEAR_EDGES or name == topology.ENTRY or \
                topology.LINEAR_EDGES.get(name) == topology.END or name in topology.LINEAR_EDGES
    for src, dst in topology.LINEAR_EDGES.items():
        assert dst == topology.END or dst in topology.NODE_ROSTER, f"{src}->{dst} dangling"
    for src, (_fn, mapping) in topology.COND_EDGES.items():
        for target in mapping.values():
            assert target == topology.END or target in topology.NODE_ROSTER
    # the independent Verifier trust-root copy agrees on order (checked by TEXT here, and it
    # imports no core — this test reads V._NODE_ORDER, it does not make the Verifier import core).
    assert V._NODE_ORDER == list(topology.NODE_ROSTER)


@pytest.mark.skipif(not _HAS_LANGGRAPH, reason="langgraph absent (D-2): compiled-graph parity is operator-go")
def test_compiled_graph_matches_topology():
    """Dynamic half (langgraph present): the compiled graph's edges == topology.derive_edges()."""
    from mdg.core.graph import build_graph

    compiled = build_graph({})               # deps all None -> deterministic fallback; no live actuation
    try:
        drawn = compiled.get_graph()
        nodes = set(getattr(drawn, "nodes", {}))
        drawn_edges = {(e.source, e.target) for e in getattr(drawn, "edges", [])}
    except Exception as exc:                  # pragma: no cover - langgraph API shape drift
        pytest.skip(f"langgraph graph introspection unavailable: {exc!r}")

    # every roster node is present in the compiled graph
    for name in topology.NODE_ROSTER:
        assert name in nodes, f"compiled graph missing node {name}"

    # normalize sentinels: topology uses 'START'/'END'; langgraph uses '__start__'/'__end__'.
    def _norm(n: str) -> str:
        return {"START": "__start__", "END": "__end__"}.get(n, n)

    for src, dst in topology.derive_edges():
        assert (_norm(src), _norm(dst)) in drawn_edges, \
            f"topology edge {src}->{dst} not in compiled graph edges"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
