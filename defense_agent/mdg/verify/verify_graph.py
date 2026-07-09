"""verify_graph — 정적 분석으로 검사하는 LangGraph topology(PA-1/PA-3/PA-8/PA-9)(langgraph 없이).

단일 출처 topology(PA-9): 권위 있는 spec 은 ``core/topology.py``(순수 데이터)다.
이 checker 는 그것을 import 하고(langgraph/pydantic 비의존) 다음을 강제한다:
  - core/nodes 안의 node 파일이 정확히 11개 == topology.NODE_ROSTER
  - 파생 edge: START->sense, act->effect_confirm->END, escalate->END, 두 조건부
    분기점이 모두 END 를 지님, 그리고 어떤 in-graph edge 도 'sense' 를 타깃하지 않음(in-graph cycle 0)
  - graph.py 가 spec 을 소비함(topology.NODE_ROSTER / LINEAR_EDGES / COND_EDGES 를 순회 —
    손으로 쓴 node별 topology 잔재 없음) 그리고 topology.BIND 로부터 deps 를 바인딩함
  - e2e._TickExecutor 가 동일한 spec 을 소비함(topology.LINEAR_EDGES / COND_EDGES / BIND)
  - escalate gate 발산이 닫힘: topology.BIND['escalate'] 가 'gate' 를 포함
  - 신뢰-루트 격리(PA-2): verifier.py 는 자신의 _NODE_ORDER 를 유지하고 core 를 import 하지
    않음; 이 checker 는 그 복사본을 topology 와 정적 텍스트 동등성으로 교차확인함
    (절대 공유 import 아님 — 포획된 core 가 자신의 독립 checker 를 침묵시켜선 안 됨)
  - topology.END 표기가 edges.END 와 동일
  - state.py 가 ledger/decisions/incidents 에 operator.add reducer 를 선언
  - compile() 이 checkpointer 를 deps['checkpointer'] 에서 취함(checkpointer != ledger)
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
    """모듈 수준 ``name = [ "a", "b", ... ]`` 문자열 상수 리스트를 추출한다(AST 만,
    import 없음) — Verifier 를 import 하지 않고 verifier._NODE_ORDER 를 읽는 데 사용."""
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

    # 1) node 파일 == 단일 출처 roster(11) ----------------------------------------
    node_files = {os.path.basename(p)[:-3] for p in py_files(NODES)}
    rep.check(node_files == EXPECTED_NODES and len(EXPECTED_NODES) == 11,
              f"node files != topology.NODE_ROSTER (11): extra={node_files - EXPECTED_NODES} "
              f"missing={EXPECTED_NODES - node_files}")

    # 2) 파생 edge 가 PA-1 형태를 충족(cycle-0, loop-back -> END) --------------------
    edges = topology.derive_edges()
    rep.check(("START", "sense") in edges, "missing START->sense")
    rep.check(("act", "effect_confirm") in edges, "missing act->effect_confirm")
    rep.check(("effect_confirm", "END") in edges, "effect_confirm must edge to END (loop-back rewired)")
    rep.check(("escalate", "END") in edges, "escalate must edge to END")
    bad = [(s, d) for s, d in edges if d == "sense" and s != "START"]
    rep.check(not bad, f"loop-back to sense found (in-graph cycle): {bad}")
    # 두 조건부 분기점이 모두 END 로 라우팅(Green tick / no-legal-action)
    rep.check(topology.END in topology.COND_EDGES["compute_impact"][1].values(),
              "compute_impact conditional edge missing END (Green tick)")
    rep.check(topology.END in topology.COND_EDGES["decide"][1].values(),
              "decide conditional edge missing END (no legal action)")
    rep.check(topology.COND_EDGES["compute_impact"][0] == "route_after_impact"
              and topology.COND_EDGES["decide"][0] == "route_after_decide",
              "conditional branch fns must be route_after_impact / route_after_decide")

    # 3) topology.END 표기 == edges.END(둘은 손으로 쓴 두 개의 sentinel) -------------
    etree = parse(os.path.join(CORE, "edges.py"))
    edges_end = _assign_str_list(etree, "END")
    # edges.py 는 `END = "__end__"` 를 선언(리스트가 아닌 스칼라) -> 직접 읽음
    edges_end_val = None
    for node in ast.walk(etree):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "END" for t in node.targets) \
                and isinstance(node.value, ast.Constant):
            edges_end_val = node.value.value
    rep.check(edges_end_val == topology.END,
              f"topology.END ({topology.END!r}) must equal edges.END ({edges_end_val!r})")

    # 4) graph.py 가 spec 을 소비(손으로 쓴 node별 topology 잔재 없음) -------------------
    gsrc = read(os.path.join(CORE, "graph.py"))
    rep.check("topology.NODE_ROSTER" in gsrc and "add_node" in gsrc,
              "graph.py must iterate topology.NODE_ROSTER for add_node (single-sourced)")
    rep.check("topology.LINEAR_EDGES" in gsrc and "topology.COND_EDGES" in gsrc,
              "graph.py must build edges from topology.LINEAR_EDGES / COND_EDGES")
    rep.check("topology.kwargs_for" in gsrc or "topology.BIND" in gsrc,
              "graph.py must bind deps from topology (BIND/kwargs_for)")
    # graph.py 에 손으로 쓴 add_node("<literal>") 문자열 topology 잔재 없음
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

    # 5) e2e._TickExecutor 가 동일한 spec 을 소비 ---------------------------------------------
    esrc = read(os.path.join(CAMPAIGN, "e2e.py"))
    rep.check("topology.ENTRY" in esrc and "topology.LINEAR_EDGES" in esrc
              and "topology.COND_EDGES" in esrc,
              "e2e._TickExecutor must interpret topology (ENTRY/LINEAR_EDGES/COND_EDGES)")
    rep.check("topology.kwargs_for" in esrc or "topology.BIND" in esrc,
              "e2e._TickExecutor must bind deps from topology (BIND/kwargs_for)")

    # 6) escalate gate 발산이 닫힘: BIND['escalate'] 가 'gate' 를 포함 ---------------------
    rep.check("gate" in topology.BIND.get("escalate", {}),
              "topology.BIND['escalate'] must include 'gate' (closes graph↔executor drift)")
    # orient/decide llm 슬롯은 단일 출처이고 뒤바뀌지 않음(verify_models 도 교차확인)
    rep.check(topology.BIND["orient"].get("llm") == "llm_orient"
              and topology.BIND["decide"].get("llm") == "llm_decide",
              "topology.BIND orient/decide llm slots swapped or missing")

    # 7) 신뢰-루트 격리: verifier._NODE_ORDER == roster, 텍스트 기준(import 없음) -------------
    vtree = parse(os.path.join(VERIFIER, "verifier.py"))
    vorder = _assign_str_list(vtree, "_NODE_ORDER")
    rep.check(vorder is not None, "verifier.py: _NODE_ORDER list not found (static read)")
    rep.check(vorder == list(topology.NODE_ROSTER),
              f"verifier._NODE_ORDER drifted from topology.NODE_ROSTER: {vorder}")
    # 격리는 서술이 아니라 IMPORT 에 관한 것 — 실제 import 문을 스캔한다(docstring 은
    # 왜 import 하지 않는지 설명할 때 'mdg.core' 를 정당하게 언급함).
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

    # 8) PA-3: 3개 accumulator 에 operator.add reducer ------------------------------------
    ssrc = read(os.path.join(CORE, "state.py"))
    for chan in ("ledger", "decisions", "incidents"):
        rep.check(f"{chan}: Annotated[list[" in ssrc and "operator.add" in ssrc,
                  f"state.py: accumulator '{chan}' missing operator.add reducer")

    # 9) checkpointer(StateGraph 영속성) != ledger(durable IntentLedger) -----------------
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
