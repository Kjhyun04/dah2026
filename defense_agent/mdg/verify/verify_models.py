"""verify_models — role→model routing alignment (DEFENSE_AGENT_DEV_WORKFLOW line 202:
'verify_models(role→model 라우팅 Orient=Sonnet·Decide=Opus·폴백리스트)').

Static check (no langgraph/pydantic/pyyaml required) that the config side (models.yaml
roles) and the code side (make_orient_llm/make_decide_llm factories + graph llm_orient/
llm_decide slots) agree and are NOT swapped:

  - core.topology.BIND maps the orient node's llm kwarg to slot 'llm_orient' and the decide
    node's to 'llm_decide' (the single recipe both build_graph and e2e._TickExecutor consume,
    PA-9) — the orient slot feeds the orient node, the decide slot the decide node (a swap
    would misroute Sonnet/Opus);
  - build_llm_deps returns exactly {'llm_orient','llm_decide'} via make_orient/decide_llm;
  - the orient factory reads roles['orient'] + OrientNote; decide reads roles['decide'] +
    DecideNote;
  - models.yaml roles.orient -> Sonnet family + OrientNote, roles.decide -> Opus family +
    DecideNote, each with a non-empty fallback list whose head differs from the primary.

Model-ID CURRENCY (opus-4-8 / sonnet-4-5 / haiku-4-5 not retired) is a domain sign-off item
(panel ref-align), NOT decidable statically — this verifier checks ROUTING/WIRING only.
"""
from __future__ import annotations

import ast
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.core import topology  # noqa: E402  (pure data: no langgraph/pydantic)
from mdg.verify._util import MDG_ROOT, Report, parse, read, run  # noqa: E402

CORE = os.path.join(MDG_ROOT, "core")
LLM = os.path.join(MDG_ROOT, "llm")
CONFIG = os.path.join(MDG_ROOT, "config")

# role -> (factory file, factory fn, expected response-model name, expected llm slot,
#          graph node partial'd with that slot, model-family substring)
_ROLE_SPEC = {
    "orient": ("orient.py", "make_orient_llm", "OrientNote", "llm_orient", "orient", "sonnet"),
    "decide": ("decide.py", "make_decide_llm", "DecideNote", "llm_decide", "decide", "opus"),
}


# --------------------------------------------------------------------------- #
# topology.BIND — which llm slot is bound to which node (single-sourced, PA-9)
# --------------------------------------------------------------------------- #
def _graph_slot_map() -> dict[str, str]:
    """{node_name -> llm slot string} for each node whose BIND recipe binds kwarg 'llm'.

    Since PA-9 the llm slot binding lives in the ONE recipe ``core.topology.BIND`` that both
    ``graph.build_graph`` and ``e2e._TickExecutor`` consume — so checking BIND checks BOTH
    execution paths at once (previously this AST-scanned graph.py's hand-written partials)."""
    return {node: b["llm"] for node, b in topology.BIND.items() if "llm" in b}


def _fn_source(path: str, fn_name: str) -> str:
    """Return the source text of a top-level function (const/name scan target)."""
    tree = parse(path)
    src = read(path)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == fn_name:
            return ast.get_source_segment(src, node) or ""
    return ""


# --------------------------------------------------------------------------- #
# models.yaml — role facts (pyyaml if present, else a small indentation scan)
# --------------------------------------------------------------------------- #
def _role_facts_yaml() -> dict:
    try:
        import yaml  # type: ignore
    except Exception:
        return {}
    path = os.path.join(CONFIG, "models.yaml")
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    roles = data.get("roles", {}) or {}
    out: dict = {}
    for role, r in roles.items():
        out[role] = {
            "model": str(r.get("model", "")),
            "response_model": str(r.get("response_model", "")),
            "fallback": list(r.get("fallback", []) or []),
        }
    return out


def _role_facts_scan() -> dict:
    """pyyaml-free fallback: read model/response_model/fallback under each role block."""
    text = read(os.path.join(CONFIG, "models.yaml"))
    out: dict = {}
    for role in _ROLE_SPEC:
        # capture the role block: '  <role>:' up to the next 2-space-indented key or EOF
        m = re.search(rf"^  {role}:\s*$(?P<body>.*?)(?=^\S|^  \w|\Z)", text,
                      re.MULTILINE | re.DOTALL)
        body = m.group("body") if m else ""
        model = re.search(r'^\s*model:\s*"([^"]+)"', body, re.MULTILINE)
        resp = re.search(r"response_model:\s*\"?([A-Za-z]+)\"?", body)
        fb = re.search(r"fallback:\s*\[([^\]]*)\]", body)
        fbs = [s.strip().strip('"').strip("'") for s in (fb.group(1).split(",") if fb else [])
               if s.strip()]
        out[role] = {
            "model": (model.group(1).strip() if model else ""),
            "response_model": (resp.group(1) if resp else ""),
            "fallback": fbs,
        }
    return out


def _check() -> Report:
    rep = Report("verify_models")

    slot_map = _graph_slot_map()
    deps_src = _fn_source(os.path.join(LLM, "__init__.py"), "build_llm_deps")
    facts = _role_facts_yaml() or _role_facts_scan()

    for role, (ffile, ffn, note, slot, node, family) in _ROLE_SPEC.items():
        # 1) topology.BIND binds the RIGHT slot to the RIGHT node (not swapped); both graph.py
        #    and e2e._TickExecutor consume this single recipe (PA-9).
        rep.check(slot_map.get(node) == slot,
                  f"topology.BIND['{node}'] must map llm -> '{slot}' "
                  f"(got {slot_map.get(node)!r})")

        # 2) build_llm_deps exposes this slot via the matching factory
        rep.check(f'"{slot}"' in deps_src or f"'{slot}'" in deps_src,
                  f"build_llm_deps must expose '{slot}'")
        rep.check(ffn in deps_src, f"build_llm_deps must call {ffn}()")

        # 3) the factory reads roles['<role>'] and returns the matching note type
        fsrc = _fn_source(os.path.join(LLM, ffile), ffn)
        rep.check(f'"{role}"' in fsrc or f"'{role}'" in fsrc,
                  f"{ffile}:{ffn} must look up roles['{role}']")
        rep.check(note in fsrc, f"{ffile}:{ffn} must produce {note}")

        # 4) models.yaml role facts: family routing + response_model + fallback list
        f = facts.get(role, {})
        rep.check(family in f.get("model", "").lower(),
                  f"models.yaml roles.{role}.model must be the {family} family "
                  f"(got {f.get('model')!r})")
        rep.check(f.get("response_model") == note,
                  f"models.yaml roles.{role}.response_model must be {note} "
                  f"(got {f.get('response_model')!r})")
        fb = f.get("fallback", [])
        rep.check(len(fb) >= 1, f"models.yaml roles.{role} must declare a fallback list")
        rep.check(bool(fb) and fb[0] != f.get("model"),
                  f"models.yaml roles.{role} fallback head must differ from primary model")

    return rep


def test_verify_models_alignment():
    """pytest entry: config↔code role→model routing must align (no swap)."""
    rep = _check()
    assert not rep.fails, "; ".join(rep.fails)


if __name__ == "__main__":
    run(_check)
