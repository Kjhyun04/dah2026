"""verify_no_fw_subproc — 불변식2. (정적 AST).

강제: graph 노드 + core 모듈은 절대 서브프로세스를 직접 spawn 하지 않는다. 노드는 모든
부작용을 Backend.run 을 통해 라우팅해야 한다.

범위 주의(정확히): 이 게이트는 core/* 만 스캔한다 — 거기서 subprocess 를 금지할 뿐,
core/ 외부의 subprocess 를 전역적으로 금지하지는 않는다. 단일 spawn 경로에서
safe_exec/backend.py 가 주 spawn 을 소유하며(Backend.run 의 subprocess.Popen),
safe_exec/safeexec.py 도 그 동일한 spawn 경로를 뒷받침하는 R1~R6 teardown/reap
프리미티브를 위해 subprocess 를 import 한다. 아래의 긍정 단언(assertion)은
backend.py 가 subprocess import 를 소유하는지만 검사할 뿐, 트리 전체의 "유일 importer"
증명은 아니다.
(스캔 루트를 core/ 너머로 넓히는 것은 별도의 동작 변경이다 —
CODE_AUDIT_20260708:45 참조.)

core/* 어디에서도 금지: import subprocess/os.system/os.popen/pty/os.exec*,
subprocess.* 호출, os.system(...) 호출.
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

    # 긍정: safe_exec/backend.py 가 유일한 subprocess 소유자다
    be = parse(os.path.join(MDG_ROOT, "safe_exec", "backend.py"))
    imports_subproc = any(
        (isinstance(n, ast.Import) and any(a.name == "subprocess" for a in n.names))
        for n in ast.walk(be)
    )
    rep.check(imports_subproc, "safe_exec/backend.py must own the subprocess import (single path)")
    return rep


if __name__ == "__main__":
    run(_check)
