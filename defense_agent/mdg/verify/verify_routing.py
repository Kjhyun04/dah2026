"""verify_routing — 불변식1. + PA-7 (static AST of edges.py + nodes).

Enforces:
  - route_after_impact / route_after_decide read ONLY the allowed numeric/bool keys
    (impact.band, chosen_action, chosen_action_risk, chosen_action_reversible) and
    NEVER LLM-derived fields (orient_note, decide_note)
  - no node does a direct time.* call (Clock injection only, PA-7)
  - no async def in any node (sync graph, PA-7)
"""
from __future__ import annotations

import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.verify._util import CORE, NODES, Report, parse, py_files, run  # noqa: E402

ALLOWED_STATE_KEYS = {
    "impact", "band", "chosen_action", "chosen_action_risk", "chosen_action_reversible",
}
FORBIDDEN_KEYS = {"orient_note", "decide_note", "trust", "legal_actions",
                  # P4-Q1/P4-2 — the opaque pivot/containment selectors are DATA-only; no edge may
                  # branch on any of them.
                  "target", "target_kind", "enforce_at",
                  # [B] SensorEv.source — opaque attribution selector carried for correlation/
                  # dispatch only; DATA-only, edge-invisible (no edge may branch on it).
                  "source"}


def _string_consts_in(fn: ast.FunctionDef) -> set[str]:
    out = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            out.add(node.value)
        if isinstance(node, ast.Attribute):
            out.add(node.attr)
    return out


# decision-relevant modules (Q-A regression guard). edges.py route_* functions are PURE
# routing, so the whole function is scanned above. These modules are NODES/gates that mix
# control flow with data plumbing — they LEGITIMATELY carry opaque selectors (target,
# target_kind, enforce_at, legal_actions, source) as DATA (dict values, call args, for-loop
# iterables, return payloads). So the scan here is scoped to control-flow CONDITIONS ONLY,
# i.e. the positions where a value would STEER which branch executes. A data reference never
# false-positives; branching on any forbidden LLM-advisory/trust/opaque-selector key fails.
DECISION_MODULES = ("gate.py", "legality.py", "rank_recovery.py", "select_policy.py")


def _condition_subtrees(tree: ast.AST):
    """Yield every control-flow CONDITION expression: the ``test`` of if/while/ternary plus
    comprehension guard clauses (``for ... if <cond>``). These are the ONLY positions where a
    key influences which branch runs (불변식1. deterministic control flow). Assignments, dict
    values, call args, return payloads and for-loop iterables are deliberately excluded — a
    node may carry a forbidden selector as data without steering on it."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.While, ast.IfExp)):
            yield node.test
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            for gen in node.generators:
                yield from gen.ifs


def _condition_keys_in(tree: ast.AST) -> set[str]:
    out: set[str] = set()
    for cond in _condition_subtrees(tree):
        for sub in ast.walk(cond):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                out.add(sub.value)
            if isinstance(sub, ast.Attribute):
                out.add(sub.attr)
    return out


def _check() -> Report:
    rep = Report("verify_routing")

    etree = parse(os.path.join(CORE, "edges.py"))
    route_fns = [n for n in etree.body if isinstance(n, ast.FunctionDef)
                 and n.name.startswith("route_")]
    rep.check(len(route_fns) >= 2, "expected route_after_impact + route_after_decide")

    for fn in route_fns:
        consts = _string_consts_in(fn)
        # any state-key-looking string that is forbidden -> fail
        for bad in FORBIDDEN_KEYS:
            rep.check(bad not in consts,
                      f"edges.{fn.name} references forbidden LLM-derived key '{bad}'")
        # ensure it references at least one allowed routing key
        rep.check(bool(consts & ALLOWED_STATE_KEYS),
                  f"edges.{fn.name} reads no allowed routing key")

    # Q-A 불변식1. regression guard: the decision-relevant gates/nodes must NEVER branch on a
    # FORBIDDEN (LLM-advisory / trust / opaque-selector) key. Scoped to control-flow conditions
    # only (see _condition_subtrees) so DATA carriage of selectors does not false-positive.
    for base in DECISION_MODULES:
        mpath = os.path.join(NODES if base in {"rank_recovery.py", "select_policy.py"} else CORE,
                             base)
        cond_keys = _condition_keys_in(parse(mpath))
        for bad in FORBIDDEN_KEYS:
            rep.check(bad not in cond_keys,
                      f"{base}: forbidden key '{bad}' steers a control-flow condition "
                      f"(불변식① — decision modules branch on numeric/bool/registry only)")

    # nodes: no direct time.* call, no async def
    for path in py_files(NODES):
        tree = parse(path)
        base = os.path.basename(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef):
                rep.check(False, f"{base}: async def '{node.name}' (nodes must be sync, PA-7)")
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                    and node.value.id == "time":
                rep.check(False, f"{base}: direct time.{node.attr} call (use injected Clock, PA-7)")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    rep.check(alias.name != "time", f"{base}: imports time (use Clock, PA-7)")
    return rep


if __name__ == "__main__":
    run(_check)
