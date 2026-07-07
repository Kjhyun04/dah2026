"""verify_grep0 — 완전분리(grep0) 불변식 검증 (doc17 §3·§8).

★ 방어심층(defense-in-depth) 게이트 — 완전성 증명은 아니다. 공격 agent(core/**)가 감독
  (supervisor) **모듈을 import** 하거나 **산출(evaluation.json/supervisor.jsonl)을 read** 하지
  않음을 정적·동적 양면으로 강제:
  1. core/**/*.py 어느 것도 `supervisor` 를 import 하지 않는다 —
     정적(`import supervisor`/`from supervisor…`/`from . import supervisor`) +
     **동적**(`importlib.import_module('supervisor…')`/`__import__('supervisor…')`) AST 탐지.
  2. **전 core 모듈**을 import 해도 sys.modules 에 supervisor* 부재(순서의존 제거).
  3. core 소스가 감독 sink 리터럴('evaluation.json'/'supervisor.jsonl')을 참조하지 않는다.
  ※ core.common.config 의 SupervisorSpec(감독 **기동 config**: enabled/tap_container/aria_key_env
     =env 이름)은 허용 — 감독 산출을 읽는 게 아니라 운영자가 감독을 켜는 파라미터일 뿐.
통과 시 exit 0.
"""
from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_CORE = _ROOT / "core"
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_fail = 0


def check(label: str, cond: bool) -> None:
    global _fail
    if not cond:
        _fail += 1
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def _str_arg(node: ast.AST):
    """ast.Call 첫 인자가 문자열 리터럴이면 그 값(아니면 None)."""
    if isinstance(node, ast.Call) and node.args:
        a = node.args[0]
        if isinstance(a, ast.Constant) and isinstance(a.value, str):
            return a.value
    return None


# 1. AST: core 가 supervisor 를 정적/동적 import 안 함
bad: list[str] = []
for py in _CORE.rglob("*.py"):
    try:
        tree = ast.parse(py.read_text(encoding="utf-8"))
    except Exception:
        continue
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] == "supervisor":
                    bad.append(f"{py.name}: import {a.name}")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] == "supervisor":
                bad.append(f"{py.name}: from {node.module}")
            # from . import supervisor  (module 상대·None → names 확인)
            for a in node.names:
                if a.name == "supervisor":
                    bad.append(f"{py.name}: from . import supervisor")
        elif isinstance(node, ast.Call):
            fn = node.func
            fname = (
                fn.attr if isinstance(fn, ast.Attribute)
                else fn.id if isinstance(fn, ast.Name) else ""
            )
            if fname in ("import_module", "__import__"):
                s = _str_arg(node)
                if s and s.split(".")[0] == "supervisor":
                    bad.append(f"{py.name}: dynamic import {s!r}")
check(f"core 가 supervisor 정적/동적 import 안 함 (위반 {len(bad)})", not bad)
for b in bad:
    print("      ", b)

# 2. 전 core 모듈 import 후 sys.modules 에 supervisor* 부재(순서의존 제거)
loaded_err: list[str] = []
for py in _CORE.rglob("*.py"):
    if py.name == "__init__.py":
        continue
    rel = py.relative_to(_ROOT).with_suffix("")
    mod = ".".join(rel.parts)
    try:
        importlib.import_module(mod)
    except Exception as e:  # import 자체 실패는 분리 판정과 무관(기록만)
        loaded_err.append(f"{mod}: {type(e).__name__}")
leaked = [m for m in sys.modules if m.split(".")[0] == "supervisor"]
check(f"전 core 모듈 import 후 supervisor* 미로드 (leaked {len(leaked)})", not leaked)
for m in leaked:
    print("      leaked:", m)

# 3. core 소스가 감독 sink 리터럴 미참조
refs: list[str] = []
for py in _CORE.rglob("*.py"):
    src = py.read_text(encoding="utf-8")
    for lit in ("evaluation.json", "supervisor.jsonl"):
        if lit in src:
            refs.append(f"{py.name}: {lit}")
check(f"core 가 감독 sink 리터럴 미참조 (위반 {len(refs)})", not refs)
for r in refs:
    print("      ", r)

print("=" * 60)
if _fail == 0:
    print("GREP0 SEPARATION VERIFIED (defense-in-depth, 0 failures)")
    sys.exit(0)
print(f"{_fail} CHECK(S) FAILED")
sys.exit(1)
