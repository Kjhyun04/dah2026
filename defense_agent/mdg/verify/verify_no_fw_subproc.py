"""verify_no_fw_subproc — 불변식② (static AST).

Enforces: graph nodes + core modules NEVER spawn a subprocess directly. Nodes must
route all side effects through Backend.run.

Scope note (accurate): this gate scans ONLY core/* — it forbids subprocess there, it
does NOT globally forbid subprocess outside core/. On the single-spawn path,
safe_exec/backend.py owns the primary spawn (subprocess.Popen in Backend.run) and
safe_exec/safeexec.py also imports subprocess for the R1~R6 teardown/reap primitives
that back that same spawn path. The positive assertion below only checks that
backend.py owns the subprocess import; it is not a whole-tree "only importer" proof.
(Widening the scan root beyond core/ is a separate behavioral change — see
CODE_AUDIT_20260708:45.)

Forbidden anywhere in core/*: import subprocess/os.system/os.popen/pty/os.exec*,
subprocess.* calls, os.system(...) calls.
"""
from __future__ import annotations

import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.verify._util import CORE, MDG_ROOT, Report, parse, run  # noqa: E402

FORBIDDEN_IMPORTS = {"subprocess", "pty"}
FORBIDDEN_OS_ATTRS = {"system", "popen", "execv", "execve", "execl", "execlp", "spawnv", "fork"}


def _core_files() -> list[str]:
    out = []
    for root, _d, files in os.walk(CORE):
        for f in files:
            if f.endswith(".py"):
                out.append(os.path.join(root, f))
    return out


def _check() -> Report:
    rep = Report("verify_no_fw_subproc")

    for path in _core_files():
        tree = parse(path)
        base = os.path.relpath(path, MDG_ROOT)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    rep.check(a.name not in FORBIDDEN_IMPORTS,
                              f"{base}: imports '{a.name}' (node subprocess forbidden, 불변식②)")
            if isinstance(node, ast.ImportFrom):
                rep.check(node.module not in FORBIDDEN_IMPORTS,
                          f"{base}: from '{node.module}' import (subprocess forbidden)")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                v = node.func.value
                if isinstance(v, ast.Name) and v.id == "os" and node.func.attr in FORBIDDEN_OS_ATTRS:
                    rep.check(False, f"{base}: os.{node.func.attr}(...) call (use safe_exec.Backend.run)")
                if isinstance(v, ast.Name) and v.id == "subprocess":
                    rep.check(False, f"{base}: subprocess.{node.func.attr}(...) call (불변식②)")

    # positive: safe_exec/backend.py IS the single subprocess owner
    be = parse(os.path.join(MDG_ROOT, "safe_exec", "backend.py"))
    imports_subproc = any(
        (isinstance(n, ast.Import) and any(a.name == "subprocess" for a in n.names))
        for n in ast.walk(be)
    )
    rep.check(imports_subproc, "safe_exec/backend.py must own the subprocess import (single path)")
    return rep


if __name__ == "__main__":
    run(_check)
