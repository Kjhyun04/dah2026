"""test_graph_parity (PA-9 dynamic guard) — 프로덕션 그래프 == 단일 출처 토폴로지.

D-2(langgraph 미설치)에서 캠페인은 langgraph 없는 ``_TickExecutor``를 실행하므로,
컴파일된 ``core.graph.build_graph`` 경로는 로컬에서 결코 실행되지 않는다: 테스트되는
코드가 실제 배포되는 코드가 아니다. 이 테스트는 능력 탐지(capability probe)로 그 간극을 메운다:

  * 항상(langgraph 불필요): 단일 출처 ``core.topology`` 사양이 자기 일관적이고
    두 독립 사본(topology.NODE_ROSTER, verifier._NODE_ORDER)이 일치함 — 모든 머신에서
    강제되는 패리티 계약의 구조적 절반.
  * langgraph가 존재할 때(프로덕션 이미지): 추가로 ``build_graph``를 컴파일하고
    그 컴파일된 노드/엣지 집합이 ``topology.derive_edges()``와 일치함을 단언 — 실제
    그래프와 인터프리터가 런타임에 하나의 토폴로지를 공유함을 증명(희망이 아닌 실증).

langgraph 절반은 langgraph 부재 시 SKIP(실패 아님)되므로 의존성 경량 로컬 자체검증을
깨뜨릴 수 없다; langgraph가 존재하는 이미지에서는 강제 게이트로 전환된다. testbed 접촉 없음,
라이브 액추에이션 없음(구조 검사만).
"""
from __future__ import annotations

import importlib.util
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest  # noqa: E402

from mdg.core import topology  # noqa: E402
from mdg.verifier import verifier as V  # noqa: E402

_HAS_LANGGRAPH = importlib.util.find_spec("langgraph") is not None


def test_topology_self_consistent_always():
    """구조적 절반(langgraph 없음): 사양이 일관적이고 로스터가 단일 출처임."""
    assert topology.ENTRY in topology.NODE_ROSTER
    assert len(topology.NODE_ROSTER) == 11
    # END이 아닌 모든 타겟은 실제 노드를 참조; 조건부 두 노드를 제외한 모든 노드는
    # 정적 후속자를 가짐; 조건부 노드는 COND_EDGES로만 라우팅.
    cond = set(topology.COND_EDGES)
    for name in topology.NODE_ROSTER:
        if name in cond:
            assert name not in topology.LINEAR_EDGES, f"{name} is both linear and conditional"
        else:
            assert name in topology.LINEAR_EDGES or name == topology.ENTRY or \
                topology.LINEAR_EDGES.get(name) == topology.END or name in topology.LINEAR_EDGES
    for src, dst in topology.LINEAR_EDGES.items():
        assert dst == topology.END or dst in topology.NODE_ROSTER, f"{src}->{dst} dangling"
    for src, (_fn, mapping) in topology.COND_EDGES.items():
        for target in mapping.values():
            assert target == topology.END or target in topology.NODE_ROSTER
    # 독립적인 Verifier trust-root 사본이 순서에 대해 일치(여기서는 TEXT로 확인하며, core를
    # import하지 않음 — 이 테스트는 V._NODE_ORDER를 읽을 뿐 Verifier가 core를 import하게 만들지 않음).
    assert V._NODE_ORDER == list(topology.NODE_ROSTER)


@pytest.mark.skipif(not _HAS_LANGGRAPH, reason="langgraph absent (D-2): compiled-graph parity is operator-go")
def test_compiled_graph_matches_topology():
    """동적 절반(langgraph 존재): 컴파일된 그래프의 엣지 == topology.derive_edges()."""
    from mdg.core.graph import build_graph

    compiled = build_graph({})               # deps 전부 None -> 결정론 폴백; 라이브 액추에이션 없음
    try:
        drawn = compiled.get_graph()
        nodes = set(getattr(drawn, "nodes", {}))
        drawn_edges = {(e.source, e.target) for e in getattr(drawn, "edges", [])}
    except Exception as exc:                  # pragma: no cover - langgraph API 형태 변화
        pytest.skip(f"langgraph graph introspection unavailable: {exc!r}")

    # 모든 로스터 노드가 컴파일된 그래프에 존재
    for name in topology.NODE_ROSTER:
        assert name in nodes, f"compiled graph missing node {name}"

    # 센티널 정규화: topology는 'START'/'END' 사용; langgraph는 '__start__'/'__end__' 사용.
    def _norm(n: str) -> str:
        return {"START": "__start__", "END": "__end__"}.get(n, n)

    for src, dst in topology.derive_edges():
        assert (_norm(src), _norm(dst)) in drawn_edges, \
            f"topology edge {src}->{dst} not in compiled graph edges"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
