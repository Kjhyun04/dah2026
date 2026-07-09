"""build_graph (PA-1/PA-8) — LangGraph StateGraph 조립.

Topology (그래프 내 사이클 = 0, 모든 loop-back -> END):
  START = sense
  sense -> correlate -> compute_trust -> compute_impact
  compute_impact --[band==Green]--> END          (Green 틱: LLM 없음)
  compute_impact --[band in {Yellow,Red}]--> orient
  orient -> select_policy -> rank_recovery -> decide
  decide --[legal ∧ risk in {LOW,MED} ∧ reversible]--> act
  decide --[risk==HIGH]--> escalate
  decide --[chosen_action is None]--> END
  act -> effect_confirm -> END
  escalate -> END

조건부 분기 함수는 edges.py 에 있으며 숫자/불리언 필드만 읽는다
(불변식1.). recon 은 boot 전용이다 (노드 아님). recursion_limit=16 은 invoke 시
(driver) 사이클 가드로 전달된다.

SINGLE-SOURCED TOPOLOGY (PA-9): 노드 로스터, 선형 스파인, 두 조건부
분기점, 노드별 dependency-injection 레시피가 모두 ``core.topology``
(순수 데이터)에서 온다. ``e2e._TickExecutor`` (langgraph 없는 인터프리터)가 동일한 datum 을 소비하므로,
프로덕션 그래프와 테스트 대상 executor 가 발산할 수 없다. 이로써 이전에 실체화되었던
드리프트(escalate 가 여기서는 ``gate`` 없이 바인딩되었으나 저기서는 함께 호출되던)를 닫는다.

Dependency injection: queue/backend/ledger/clock/llm 이 필요한 노드는 ``topology.BIND`` 의
functools.partial 로 바인딩되어 컴파일된 그래프가 전역을 지니지 않는다.
"""
from __future__ import annotations

from functools import partial
from typing import Any, Optional

from . import edges, topology
from .nodes import NODES
from .state import MDGState

# name -> 분기 함수 (여기서 해석; topology 는 NAME 만 지녀 무거운 것을 import 하지 않음)
_BRANCH = {
    "route_after_impact": edges.route_after_impact,
    "route_after_decide": edges.route_after_decide,
}


def build_graph(deps: Optional[dict[str, Any]] = None):
    """StateGraph 를 조립하고 컴파일한다. deps 는 다음을 포함할 수 있다: inbox, verify, clock,
    llm_orient, llm_decide, backend, ledger, observe, source_domains. 컴파일된
    그래프를 반환한다. ``source_domains`` ({source_id -> domain}, build_source_domains(collectors) 유래)는
    sense 가 watchdog sensor_loss 를 present-set 제외를 위해 도메인에 귀속시키게 한다 (P3-Q5).

    langgraph 설치를 요구한다 (python:3.12-slim 이미지). 그렇지 않으면 명확한
    메시지와 함께 ImportError 를 발생시킨다 — verify_graph.py 는 langgraph 를
    import 하지 않고 정적 topology 검사를 수행한다.
    """
    try:
        from langgraph.graph import END, START, StateGraph
    except Exception as exc:  # pragma: no cover
        raise ImportError(
            "langgraph is required to compile the graph "
            "(pip install -r requirements.txt). Static topology is checked by "
            "verify/verify_graph.py without langgraph."
        ) from exc

    d = deps or {}
    # Phase 0 배선: sandbox OPER auto-confirm 플래그를 보장된 불리언으로 정규화하여
    # Phase 1 gate/edge 가 재파싱 없이 읽게 한다. 아직 라우팅 영향 없음 — topology.BIND 는
    # Phase 1 전까지 'operator_auto' 를 참조하지 않으므로 제어 흐름은 불변이다 (불변식1. 무손상,
    # 회귀 0). caller 의 deps dict 가 변형되지 않도록 shallow-copy 한다.
    d = {**d, "operator_auto": bool(d.get("operator_auto"))}

    def _node(name: str):
        # 단일 레시피(topology.BIND)에서 주입 deps 를 바인딩 — 전역 없음, 드리프트 없음.
        return partial(NODES[name], **topology.kwargs_for(name, d))

    def _target(label: str):
        # spec 의 END 센티널을 langgraph 의 END 로 매핑; 그 외 라벨은 노드 이름이다.
        return END if label == topology.END else label

    g = StateGraph(MDGState)
    for name in topology.NODE_ROSTER:              # 11-노드 로스터 (PA-8), single-sourced
        g.add_node(name, _node(name))

    g.add_edge(START, topology.ENTRY)              # set_entry_point('sense')
    for src, dst in topology.LINEAR_EDGES.items():  # 선형 스파인 (loop-back 은 이미 -> END)
        g.add_edge(src, _target(dst))
    for src, (fn_name, mapping) in topology.COND_EDGES.items():  # 숫자/불리언 라우팅만 (불변식1.)
        g.add_conditional_edges(
            src, _BRANCH[fn_name],
            {label: _target(target) for label, target in mapping.items()},
        )

    return g.compile(checkpointer=d.get("checkpointer"))
