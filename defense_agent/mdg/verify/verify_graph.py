"""verify_graph — LangGraph topology (PA-1/PA-3/PA-8/PA-9) via static analysis (no langgraph).

Single-sourced topology (PA-9): the authoritative spec is ``core/topology.py`` (pure data).
This checker imports THAT (it is langgraph/pydantic-free) and enforces:
  - exactly 11 node files in core/nodes == topology.NODE_ROSTER
  - derived edges: START->sense, act->effect_confirm->END, escalate->END, both conditional
    branch points carry END, and NO in-graph edge targets 'sense' (in-graph cycle 0)
  - graph.py CONSUMES the spec (iterates topology.NODE_ROSTER / LINEAR_EDGES / COND_EDGES —
    no hand-written per-node topology left) and binds deps from topology.BIND
  - e2e._TickExecutor CONSUMES the same spec (topology.LINEAR_EDGES / COND_EDGES / BIND)
  - the escalate gate divergence is closed: topology.BIND['escalate'] includes 'gate'
  - trust-root isolation (PA-2): verifier.py keeps its OWN _NODE_ORDER and does NOT import
    core; this checker cross-checks that copy against topology by STATIC TEXT equivalence
    (never a shared import — a captured core must not silence its independent checker)
  - topology.END spelling equals edges.END
  - state.py declares operator.add reducers on ledger/decisions/incidents
  - compile() sources checkpointer from deps['checkpointer'] (checkpointer != ledger)
"""
from __future__ import annotations

import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.core import topology  # noqa: E402  (pure data: no langgraph/pydantic)
from mdg.verify._util import CORE, MDG_ROOT, NODES, Report, parse, py_files, read, run  # noqa: E402

EXPECTED_NODES = set(topology.NODE_ROSTER)
CAMPAIGN = os.path.join(MDG_ROOT, "campaign")
VERIFIER = os.path.join(MDG_ROOT, "verifier")


def _assign_str_list(tree: ast.Module, name: str) -> list[str] | None:
    """Extract a module-level ``name = [ "a", "b", ... ]`` list of string constants (AST only,
    no import) — used to read verifier._NODE_ORDER without importing the Verifier."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == name \
                        and isinstance(node.value, (ast.List, ast.Tuple)):
                    vals = []
                    for el in node.value.elts:
                        if isinstance(el, ast.Constant) and isinstance(el.value, str):
                            vals.append(el.value)
                    return vals
    return None


def _check() -> Report:
    rep = Report("verify_graph")

    # 1) node files == the single-sourced roster (11) ----------------------------------------
    node_files = {os.path.basename(p)[:-3] for p in py_files(NODES)}
    rep.check(node_files == EXPECTED_NODES and len(EXPECTED_NODES) == 11,
              f"node files != topology.NODE_ROSTER (11): extra={node_files - EXPECTED_NODES} "
              f"missing={EXPECTED_NODES - node_files}")

    # 2) derived edges satisfy the PA-1 shape (cycle-0, loop-backs -> END) --------------------
    edges = topology.derive_edges()
    rep.check(("START", "sense") in edges, "missing START->sense")
    rep.check(("act", "effect_confirm") in edges, "missing act->effect_confirm")
    rep.check(("effect_confirm", "END") in edges, "effect_confirm must edge to END (loop-back rewired)")
    rep.check(("escalate", "END") in edges, "escalate must edge to END")
    bad = [(s, d) for s, d in edges if d == "sense" and s != "START"]
    rep.check(not bad, f"loop-back to sense found (in-graph cycle): {bad}")
    # both conditional branch points route to END (Green tick / no-legal-action)
    rep.check(topology.END in topology.COND_EDGES["compute_impact"][1].values(),
              "compute_impact conditional edge missing END (Green tick)")
    rep.check(topology.END in topology.COND_EDGES["decide"][1].values(),
              "decide conditional edge missing END (no legal action)")
    rep.check(topology.COND_EDGES["compute_impact"][0] == "route_after_impact"
              and topology.COND_EDGES["decide"][0] == "route_after_decide",
              "conditional branch fns must be route_after_impact / route_after_decide")

    # 3) topology.END spelling == edges.END (they are two hand-written sentinels) -------------
    etree = parse(os.path.join(CORE, "edges.py"))
    edges_end = _assign_str_list(etree, "END")
    # edges.py declares `END = "__end__"` (scalar, not a list) -> read it directly
    edges_end_val = None
    for node in ast.walk(etree):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "END" for t in node.targets) \
                and isinstance(node.value, ast.Constant):
            edges_end_val = node.value.value
    rep.check(edges_end_val == topology.END,
              f"topology.END ({topology.END!r}) must equal edges.END ({edges_end_val!r})")

    # 4) graph.py CONSUMES the spec (no hand-written per-node topology left) -------------------
    gsrc = read(os.path.join(CORE, "graph.py"))
    rep.check("topology.NODE_ROSTER" in gsrc and "add_node" in gsrc,
              "graph.py must iterate topology.NODE_ROSTER for add_node (single-sourced)")
    rep.check("topology.LINEAR_EDGES" in gsrc and "topology.COND_EDGES" in gsrc,
              "graph.py must build edges from topology.LINEAR_EDGES / COND_EDGES")
    rep.check("topology.kwargs_for" in gsrc or "topology.BIND" in gsrc,
              "graph.py must bind deps from topology (BIND/kwargs_for)")
    # no leftover hand-written add_node("<literal>") string topology in graph.py
    gtree = parse(os.path.join(CORE, "graph.py"))
    literal_add_node = [n for n in ast.walk(gtree)
                        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                        and n.func.attr == "add_node" and n.args
                        and isinstance(n.args[0], ast.Constant)
                        and isinstance(n.args[0].value, str)]
    rep.check(not literal_add_node,
              f"graph.py has {len(literal_add_node)} hand-written add_node(\"literal\") call(s) "
              "— topology must be single-sourced (iterate topology.NODE_ROSTER)")
    rep.check("add_conditional_edges" in gsrc,
              "graph.py must emit add_conditional_edges (from topology.COND_EDGES)")

    # 5) e2e._TickExecutor consumes the SAME spec ---------------------------------------------
    esrc = read(os.path.join(CAMPAIGN, "e2e.py"))
    rep.check("topology.ENTRY" in esrc and "topology.LINEAR_EDGES" in esrc
              and "topology.COND_EDGES" in esrc,
              "e2e._TickExecutor must interpret topology (ENTRY/LINEAR_EDGES/COND_EDGES)")
    rep.check("topology.kwargs_for" in esrc or "topology.BIND" in esrc,
              "e2e._TickExecutor must bind deps from topology (BIND/kwargs_for)")

    # 6) escalate gate divergence CLOSED: BIND['escalate'] includes 'gate' ---------------------
    rep.check("gate" in topology.BIND.get("escalate", {}),
              "topology.BIND['escalate'] must include 'gate' (closes graph↔executor drift)")
    # orient/decide llm slots are single-sourced and NOT swapped (verify_models cross-checks too)
    rep.check(topology.BIND["orient"].get("llm") == "llm_orient"
              and topology.BIND["decide"].get("llm") == "llm_decide",
              "topology.BIND orient/decide llm slots swapped or missing")

    # 7) trust-root isolation: verifier._NODE_ORDER == roster, by TEXT (no import) -------------
    vtree = parse(os.path.join(VERIFIER, "verifier.py"))
    vorder = _assign_str_list(vtree, "_NODE_ORDER")
    rep.check(vorder is not None, "verifier.py: _NODE_ORDER list not found (static read)")
    rep.check(vorder == list(topology.NODE_ROSTER),
              f"verifier._NODE_ORDER drifted from topology.NODE_ROSTER: {vorder}")
    # isolation is about IMPORTS, not prose — scan actual import statements (the docstring
    # legitimately mentions 'mdg.core' when explaining WHY it does not import it).
    v_imports: list[str] = []
    for node in ast.walk(vtree):
        if isinstance(node, ast.Import):
            v_imports += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            v_imports.append(node.module or "")
    core_imports = [m for m in v_imports if "mdg.core" in m or "core.topology" in m
                    or m == "topology" or m.endswith(".core")]
    rep.check(not core_imports,
              f"verifier.py must NOT import core/topology (trust-root isolation > DRY, PA-2): "
              f"{core_imports}")

    # 8) PA-3: operator.add reducers on the 3 accumulators ------------------------------------
    ssrc = read(os.path.join(CORE, "state.py"))
    for chan in ("ledger", "decisions", "incidents"):
        rep.check(f"{chan}: Annotated[list[" in ssrc and "operator.add" in ssrc,
                  f"state.py: accumulator '{chan}' missing operator.add reducer")

    # 9) checkpointer(StateGraph persistence) != ledger(durable IntentLedger) -----------------
    rep.check('checkpointer=d.get("checkpointer")' in gsrc,
              "graph.py: compile() must source checkpointer from deps['checkpointer']")
    rep.check('checkpointer=d.get("ledger")' not in gsrc,
              "graph.py: checkpointer must NOT be the ledger dep (checkpointer≠ledger)")
    rep.check(topology.BIND["act"].get("ledger") == "ledger"
              and topology.BIND["escalate"].get("ledger") == "ledger",
              "topology.BIND: act/escalate must source ledger from deps['ledger']")
    return rep


if __name__ == "__main__":
    run(_check)
