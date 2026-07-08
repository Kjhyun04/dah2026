"""verify_grep0 — Verifier separation (PA-2 · DESIGN §부록A).

Enforces (static):
  - no mdg.core.* module imports mdg.verifier.* (core ↛ verifier)
  - 'verifier_truth' channel/symbol absent from state.py (and all of core)
  - 'Truth' type not referenced in core (core cannot import a verdict store)
  - no core module imports docker sdk / socket path / proxy URL (PS-1 overlap)
  - NO hardcoded target literals in core CODE (GATE2 targets-0, finding P2-3/A-1):
    IPv4 literals, INPUT_SPEC container/role name tokens, and INPUT_SPEC port ints
    are forbidden as code-level constants; allowed ONLY in comments/docstrings. The
    forbidden set is sourced from config.INPUT_SPEC (loader), not a 2nd hardcoded copy,
    so the guard tracks the declared topology. This is what would have caught the
    select_policy.py enforce_at container-literal regression.
"""
from __future__ import annotations

import ast
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.config import loader  # noqa: E402
from mdg.verify._util import CORE, MDG_ROOT, Report, parse, read, run  # noqa: E402


def _core_files() -> list[str]:
    out = []
    for root, _dirs, files in os.walk(CORE):
        for f in files:
            if f.endswith(".py"):
                out.append(os.path.join(root, f))
    return out


def _imports(tree: ast.Module) -> list[str]:
    mods = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            mods.append(node.module or "")
    return mods


FORBIDDEN_IMPORT_SUBSTR = ["verifier", "docker", "socket"]
FORBIDDEN_LITERALS = ["/var/run/docker.sock", "docker-socket-proxy", "verifier_truth"]

# IPv4 dotted-quad (word-bounded so a regex-pattern string like r"\d{1,3}\.\d{1,3}" — which has no
# literal quad — does not false-positive; only actual a.b.c.d literals match).
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _forbidden_target_literals() -> tuple[dict[str, re.Pattern], set[int]]:
    """Topology tokens that must NEVER appear as CODE-LEVEL literals in core — sourced from
    config.INPUT_SPEC (NOT a second hardcoded copy). Returns (name-token -> word-bounded regex,
    forbidden port ints). Container/role names (incl. log-tail containers) + declared ports and
    the :port on nf metric endpoints."""
    spec = loader.input_spec()
    tokens: set[str] = set()
    for r in spec.get("roles", []) or []:
        for k in ("role", "container"):
            v = r.get(k)
            if v:
                tokens.add(str(v))
    for v in (spec.get("log_containers", {}) or {}).values():
        if v:
            tokens.add(str(v))
    ports: set[int] = set()
    for v in (spec.get("ports", {}) or {}).values():
        try:
            ports.add(int(v))
        except (TypeError, ValueError):
            pass
    for ep in (spec.get("nf_endpoints", {}) or {}).values():
        m = re.search(r":(\d+)\b", str(ep))
        if m:
            ports.add(int(m.group(1)))
    return {t: re.compile(r"\b" + re.escape(t) + r"\b") for t in tokens}, ports


def _docstring_const_ids(tree: ast.Module) -> set[int]:
    """id() of every Constant node used as a module/class/function docstring — topology tokens are
    allowed there (prose), so those nodes are exempt from the literal scan. Comments are not in the
    AST at all, so they are exempt implicitly."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
                and body and isinstance(body[0], ast.Expr) \
                and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            ids.add(id(body[0].value))
    return ids


def _scan_hardcoded_targets(rep: Report) -> None:
    """Fail-closed AST scan: any IPv4 / container-role token / declared-port literal in core CODE
    (outside comments & docstrings) is a GATE2 targets-0 violation (finding P2-3/A-1)."""
    token_res, ports = _forbidden_target_literals()
    for path in _core_files():
        tree = parse(path)
        base = os.path.relpath(path, MDG_ROOT)
        doc_ids = _docstring_const_ids(tree)
        hits: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or id(node) in doc_ids:
                continue
            val = node.value
            if isinstance(val, str):
                if _IPV4_RE.search(val):
                    hits.append(f"L{node.lineno} IPv4 literal '{val}'")
                for tok, rx in token_res.items():
                    if rx.search(val):
                        hits.append(f"L{node.lineno} container/role token '{tok}'")
            elif isinstance(val, int) and not isinstance(val, bool) and val in ports:
                hits.append(f"L{node.lineno} declared-port literal {val}")
        rep.check(not hits,
                  f"{base}: hardcoded target literal(s) in core CODE (GATE2 targets-0; source from "
                  f"INPUT_SPEC): {'; '.join(hits)}")


def _check() -> Report:
    rep = Report("verify_grep0")

    for path in _core_files():
        src = read(path)
        tree = parse(path)
        base = os.path.relpath(path, MDG_ROOT)
        for mod in _imports(tree):
            rep.check("verifier" not in mod,
                      f"{base}: core imports verifier module '{mod}' (grep0 violation)")
            rep.check(not (mod == "docker" or mod.startswith("docker.")),
                      f"{base}: core imports docker sdk '{mod}' (PS-1)")
        # literal scans
        rep.check("verifier_truth" not in src,
                  f"{base}: 'verifier_truth' symbol present (PA-2 requires absence)")
        for lit in ("/var/run/docker.sock", "docker-socket-proxy"):
            rep.check(lit not in src, f"{base}: forbidden sock/proxy literal '{lit}' (PS-1)")

    # Truth type not referenced in core
    for path in _core_files():
        src = read(path)
        base = os.path.relpath(path, MDG_ROOT)
        # allow the word inside comments about absence; check for symbol usage patterns
        rep.check("import Truth" not in src and "Truth(" not in src and ": Truth" not in src
                  and "list[Truth]" not in src,
                  f"{base}: references Truth type (core must not import verdict store)")

    # GATE2 targets-0: no hardcoded IPv4/container/port literals in core CODE (finding P2-3/A-1).
    _scan_hardcoded_targets(rep)
    return rep


if __name__ == "__main__":
    run(_check)
