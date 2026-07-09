"""topology.py (PA-9 lock) — in-graph 토폴로지의 단일 선언적 소스.

목적: 11-노드 linear spine, 두 개의 조건부 분기점, 노드별
dependency-injection 레시피는 손으로 유지되는 세 벌의 복사본에 존재했다 —
``core/graph.py`` (langgraph 프로덕션 빌드), ``campaign/e2e.py::_TickExecutor``
(CI 가 실제로 돌리는 langgraph-free 틱 인터프리터), 그리고 (순서만)
``verifier/verifier.py::_NODE_ORDER`` (독립 trust root). 라우팅은 이미
``edges.py`` 에 단일 소스화되어 있었으나; linear 순서 + DI binding 은 아니었고, escalate
``gate=`` binding 은 이미 어긋나기 시작 (graph.py 는 escalate 를 gate 없이 bind 한 반면
executor 는 gate 와 함께 호출). 이 모듈은 두 CORE 복사본을
``graph.build_graph`` 과 ``e2e._TickExecutor`` 이 둘 다 소비하는 하나의 데이터로 접어, 발산할 수 없게 한다.

Trust-root 격리 (PA-2 / grep0) 는 보존됨: Verifier 는 여전히 자신의
``_NODE_ORDER`` 를 유지하며 이 모듈을 import 하지 않는다 — ``verify/verify_graph.py`` 가
두 복사본을 정적 텍스트 동등성으로 교차검증, 공유 import 로는 절대 안 함 (캡처된 core 가 자신의
독립 checker 를 침묵시킬 수 있으면 안 됨).

설계상 PURE DATA: 문자열과 dict 뿐 — node 함수, edges, langgraph,
pydantic 을 import 하지 않음. 이로써 의존성이 가벼운 ``verify/`` 스크립트가 모듈을 import 가능.
분기 함수와 node 함수는 여기서 이름으로 참조되며 각 소비자 (이미 ``edges`` 와 ``nodes`` 를
import 함) 가 callable 로 해석한다. ``END`` 는 ``edges.END``
(및 langgraph END sentinel) 를 미러 — verify_graph 가 두 표기가 동일하게 유지됨을 assert.

불변식 보존은 구조적: 이 모듈은 node 순서 + 분기점 이름 +
kwarg-to-dep-key 이름만 인코딩. LLM 필드 없음, 비밀 없음, subprocess 없음 — 제어 흐름은 여전히
``edges.route_after_*`` (numeric/bool) 로만 라우팅되고, side effect 는 여전히
node 에 존재 (leak-0). 그래프 변경은 이제 두 실행 경로가 모두 상속하는 one-file 편집이다.
"""
from __future__ import annotations

# END sentinel — edges.END 와 langgraph END 상수 ("__end__") 를 미러.
# 로컬 리터럴로 유지 (`from .edges import END` 아님) 하여 이 모듈이 무거운 것을 import 하지 않게;
# verify_graph.py 가 edges.py 가 동일 표기를 선언함을 assert.
END = "__end__"

# Entry 노드 (START -> ENTRY). recon 은 boot 전용이며 그래프 노드 아님 (PA-1).
ENTRY = "sense"

# 11-노드 in-graph 로스터 (PA-8), 정본 실행/기록 순서.
NODE_ROSTER: tuple[str, ...] = (
    "sense", "correlate", "compute_trust", "compute_impact", "orient",
    "select_policy", "rank_recovery", "decide", "act", "effect_confirm", "escalate",
)

# 정적 linear successor (spine). 조건부 노드 (compute_impact, decide) 는 여기
# 키가 아님 — 그 successor 는 COND_EDGES 로 선택됨. 종단 노드는 END 를 가리킨다.
LINEAR_EDGES: dict[str, str] = {
    "sense": "correlate",
    "correlate": "compute_trust",
    "compute_trust": "compute_impact",
    "orient": "select_policy",
    "select_policy": "rank_recovery",
    "rank_recovery": "decide",
    "act": "effect_confirm",
    "effect_confirm": END,          # loop-back 이 END 로 재배선 (PA-1)
    "escalate": END,
}

# 조건부 분기점: node -> (edges.py 의 branch_fn_name, {branch_label -> target}).
# 인터프리터/빌드는 fn 이름을 자신의 edges 레지스트리로 해석; label 집합은
# edges.route_after_* 가 반환할 수 있는 것과 정확히 일치. 제어 흐름은 numeric/bool 만 읽음 (불변식1.).
COND_EDGES: dict[str, tuple[str, dict[str, str]]] = {
    "compute_impact": ("route_after_impact", {"orient": "orient", END: END}),
    "decide": ("route_after_decide", {"act": "act", "escalate": "escalate", END: END}),
}

# 단일 dependency-injection 레시피: node -> {kwarg_name: dep_key}. graph.build_graph
# (functools.partial) 과 e2e._TickExecutor (호출 시 kwargs) 둘 다 이 맵에서 bind 하므로, 새 dep 은
# 정확히 한 곳에서 추가됨. kwarg 'llm' 은 서로 다른 슬롯 (llm_orient/llm_decide) 에 매핑됨에 주의
# — verify_models 가 그 라우팅을 교차검증. escalate 의 'gate' 는 여기 포함되어
# graph.py<->executor 발산을 CLOSE (이제 두 경로 모두 gate=deps['gate'] 전달).
BIND: dict[str, dict[str, str]] = {
    "sense": {"inbox": "inbox", "verify": "verify", "clock": "clock",
              "source_domains": "source_domains"},
    "correlate": {"clock": "clock"},
    "compute_trust": {},
    "compute_impact": {},
    "orient": {"llm": "llm_orient"},
    "select_policy": {},
    "rank_recovery": {},
    "decide": {"llm": "llm_decide", "clock": "clock"},
    "act": {"backend": "backend", "ledger": "ledger", "clock": "clock", "smf_table": "smf_table",
            "operator_auto": "operator_auto", "docker": "docker"},
    "effect_confirm": {"observe": "observe"},
    "escalate": {"ledger": "ledger", "clock": "clock", "gate": "gate"},
}


def derive_edges() -> list[tuple[str, str]]:
    """스펙이 함의하는 모든 (src, dst) edge — START->ENTRY, 모든 linear edge, 모든
    conditional-edge target — 정적 토폴로지 검증용 (verify_graph). END/START 는
    리터럴 문자열 'END'/'START' 로 방출되어 checker 가 graph.py 의 sentinel 과 일치하게 한다."""
    out: list[tuple[str, str]] = [("START", ENTRY)]
    for s, d in LINEAR_EDGES.items():
        out.append((s, "END" if d == END else d))
    for s, (_fn, mapping) in COND_EDGES.items():
        for target in mapping.values():
            out.append((s, "END" if target == END else target))
    return out


def kwargs_for(node: str, deps: dict) -> dict:
    """BIND[node] 를 deps dict 에 대해 해석 -> {kwarg: deps.get(dep_key)}. 두 실행 경로가
    모두 호출하는 단일 binder 이므로 주입된 인자가 발산할 수 없다."""
    return {kw: deps.get(dep_key) for kw, dep_key in BIND.get(node, {}).items()}
