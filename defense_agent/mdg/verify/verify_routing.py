"""verify_routing — 불변식1. + PA-7 (edges.py + nodes 의 정적 AST).

강제:
  - route_after_impact / route_after_decide 는 허용된 numeric/bool 키만 읽음
    (impact.band, chosen_action, chosen_action_risk, chosen_action_reversible) 그리고
    LLM-파생 필드(orient_note, decide_note)는 절대 읽지 않음
  - 어떤 노드도 직접 time.* 호출을 하지 않음 (Clock 주입만, PA-7)
  - 어떤 노드에도 async def 없음 (동기 graph, PA-7)
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
                  # P4-Q1/P4-2 — opaque pivot/containment 셀렉터는 DATA-only; 어떤 edge 도
                  # 이들 중 무엇으로도 분기 불가.
                  "target", "target_kind", "enforce_at",
                  # [B] SensorEv.source — correlation/dispatch 용으로만 운반되는 opaque attribution
                  # 셀렉터; DATA-only, edge-invisible (어떤 edge 도 이것으로 분기 불가).
                  "source"}


def _string_consts_in(fn: ast.FunctionDef) -> set[str]:
    out = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            out.add(node.value)
        if isinstance(node, ast.Attribute):
            out.add(node.attr)
    return out


# 결정 관련 모듈 (Q-A 회귀 가드). edges.py route_* 함수는 순수 라우팅이므로 함수 전체를
# 위에서 스캔한다. 이 모듈들은 제어 흐름과 데이터 배관을 섞는 NODES/게이트로 — opaque 셀렉터
# (target, target_kind, enforce_at, legal_actions, source)를 DATA(dict 값, 호출 인자, for-loop
# iterable, return 페이로드)로 정당하게 운반한다. 그래서 여기 스캔은 제어-흐름 CONDITION 에만
# 한정된다. 즉 값이 어느 분기를 실행할지 STEER 하는 위치들. 데이터 참조는 절대 오탐하지
# 않으며, 금지된 LLM-advisory/trust/opaque-셀렉터 키로 분기하면 실패한다.
DECISION_MODULES = ("gate.py", "legality.py", "rank_recovery.py", "select_policy.py")


def _condition_subtrees(tree: ast.AST):
    """모든 제어-흐름 CONDITION 표현식을 yield: if/while/ternary 의 test 및 comprehension
    가드 절(for ... if <cond>). 이들이 키가 어느 분기를 실행할지 영향을 주는 유일한
    위치다(불변식1. 결정론적 제어 흐름). 할당, dict 값, 호출 인자, return 페이로드, for-loop
    iterable 은 의도적으로 제외 — 노드는 금지 셀렉터를 steer 하지 않고 데이터로 운반 가능."""
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
        # 금지된, state-key 처럼 보이는 문자열 -> 실패
        for bad in FORBIDDEN_KEYS:
            rep.check(bad not in consts,
                      f"edges.{fn.name} references forbidden LLM-derived key '{bad}'")
        # 최소 하나의 허용 라우팅 키를 참조하는지 확인
        rep.check(bool(consts & ALLOWED_STATE_KEYS),
                  f"edges.{fn.name} reads no allowed routing key")

    # Q-A 불변식1. 회귀 가드: 결정 관련 게이트/노드는 FORBIDDEN(LLM-advisory / trust /
    # opaque-셀렉터) 키로 절대 분기해서는 안 된다. 제어-흐름 CONDITION 에만 한정(_condition_subtrees
    # 참고)하여 셀렉터의 DATA 운반이 오탐하지 않게 한다.
    for base in DECISION_MODULES:
        mpath = os.path.join(NODES if base in {"rank_recovery.py", "select_policy.py"} else CORE,
                             base)
        cond_keys = _condition_keys_in(parse(mpath))
        for bad in FORBIDDEN_KEYS:
            rep.check(bad not in cond_keys,
                      f"{base}: forbidden key '{bad}' steers a control-flow condition "
                      f"(불변식① — decision modules branch on numeric/bool/registry only)")

    # nodes: 직접 time.* 호출 없음, async def 없음
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
