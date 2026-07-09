"""run_driver (PA-1/PA-7) — loop-back 을 소유하는 그래프 외부(OUT-OF-GRAPH) while 루프.

각 반복 = 정확히 ONE graph 실행 = 1 tick. 한 틱은 단일
graph.stream(inp, cfg, stream_mode='updates') 패스로 구동된다: 스트림이 곧 실행이며, 그
update 는 기록되고(PS-3 redact), 그 결과 틱 상태는 graph.get_state(cfg) 로 checkpointer 에서
다시 읽는다. 별도의 graph.invoke() 는 없다 — 둘 다 실행하면 반복당 act 노드의 부작용이 두 번
발화되어(불변식2. 누수-0 위반) 기록된 틱과 루프 조건 상태가 어긋난다(불변식1. 위반).

틱 연속성(수정됨 — S-2 라이브 발견): 모든 틱의 그래프는 END 에서 종료된다
(위상상 모든 loop-back -> END). LangGraph 에서 END 에 도달한 스레드는 대기 작업이 없으므로
그 위에서 ``graph.stream(None, cfg)`` 는 update 0 개를 내고 재실행하지 않는다 — 앞선
"fixed thread_id + stream(None)" 방식은 tick 0 이후 조용히 멈췄다
(tick_i 가 전진하지 않음 -> break 조건 미충족 -> 무한 no-op 루프). 따라서 연속성은
RE-SEEDING 으로 이어진다: 각 틱은 FRESH per-tick thread_id 에서 FULL 그래프 실행을 돌리고,
이전 틱의 read-back 상태를 입력으로 seed 한다. fresh thread_id 는
Annotated[list, operator.add] 채널(ledger/decisions/incidents)이 carried 값 위로 정확히 한 번
reduce 되게 한다(검증: 이중 누적 없음); 동일 스레드를 재-seed 하면 이들이 두 배가 되며, 그래서
이전에는 입력을 보류했다. driver 는 카운터를 읽기만 한다(증가는 노드가 소유). recursion_limit=16 은
우발적 in-graph 사이클을 방지한다.

기록 훅(PS-3): 스트림된 각 update -> 레코드 생성 시점의 redact() ->
run.jsonl append. secret 은 State 에서 구조적으로 부재하며, redact() 는 추가로 잔여 secret
패턴을 scrub 한다.
"""
from __future__ import annotations

from typing import Any, Optional

from ..config import defaults as D
from ..redact_patterns import SECRET_PATTERNS as _SECRET_PATTERNS
from .state import MDGState

# 잔여-secret scrub 패턴(PS-3) — 구조적 부재 위의 이중 안전장치.
# 문자열 LEAF 에만 적용한다(직렬화된 JSON 에는 절대 안 함) 그래야 구조가 유효하게 유지된다.
# 패턴 리스트는 공유 단일 소스(mdg.redact_patterns)이므로 여기 record-time
# scrub 과 viewer load-time 스캔이 어긋날 수 없다.


def _scrub_str(s: str) -> str:
    for pat in _SECRET_PATTERNS:
        s = pat.sub("[REDACTED]", s)
    return s


def redact(record):
    """레코드 생성(RECORD CREATION) 시점에 잔여 secret 패턴을 scrub 한다(viewer 시점 아님).
    구조를 재귀 순회하며 문자열 leaf 만 scrub 한다(PS-3)."""
    if isinstance(record, str):
        return _scrub_str(record)
    if isinstance(record, dict):
        return {k: redact(v) for k, v in record.items()}
    if isinstance(record, list):
        return [redact(v) for v in record]
    return record


def run_driver(graph, run_id: str, cfg: Optional[dict] = None, state0: Optional[MDGState] = None,
               jsonl_path: str = "", max_iters: Optional[int] = None,
               max_pivots: Optional[int] = None, k_dry: Optional[int] = None,
               forever: bool = False, tick_interval_s: float = 0.0) -> MDGState:
    """컴파일된 그래프를 구동한다. 최종 상태를 반환한다. Break 조건(PA-1):
    goal_reached ∨ tick_i>=max_iters ∨ pivots>=max_pivots ∨ dry_streak>=k_dry.
    안전한 operator LAND 는 예산 면제(G10) — escalate 틱을 dry 로 세지 않음으로써 강제된다
    (escalate 는 dry_streak 을 증가시키지 않는다).

    forever (24/7 감시 모드): True 면 위 break 조건을 전부 무시하고 KeyboardInterrupt/프로세스
    종료까지 계속 관측한다 — 평시(quiescence)에 멈추지 않는 상시 탐지 데몬. tick_interval_s>0 이면
    매 틱 사이에 그만큼 대기(collector interval 에 맞춰 CPU 스핀 방지). 배치/replay(demo·campaign)는
    forever=False 기본이라 결정론·바이트동일 재생이 무손상(불변식1. 무영향). Green 평시 틱은 조기 END 라
    incident/decision 채널이 누적하지 않아(operator.add([]) = 무증가) 상시런 메모리는 실제 사건 수로 유계."""
    budgets = D.DRIVER_BUDGETS
    max_iters = max_iters if max_iters is not None else budgets["max_iters"]
    max_pivots = max_pivots if max_pivots is not None else budgets["max_pivots"]
    k_dry = k_dry if k_dry is not None else budgets["k_dry"]
    rlimit = budgets["recursion_limit"]

    def _thread_id(tick: int) -> str:
        # 단일 소스 per-tick thread id(_cfg 와 P3 pruner 가 함께 사용하므로 서로
        # 어긋날 수 없다). 결정론적(run_id-t<tick>)이라 replay 가 byte-identical 로 유지된다.
        return f"{run_id}-t{tick}"

    def _cfg(tick: int) -> dict:
        # 틱마다 FRESH thread_id (S-2): 각 틱은 END 에서 종료되는 하나의 full 그래프 실행이다;
        # fresh 스레드는 carried 상태가 operator.add 채널을 정확히 한 번 re-seed 하게 한다.
        # thread_id 는 결정론적(run_id-t<tick>)이라 replay 가 byte-identical 로 유지된다(GATE2).
        # recursion_limit 은 우발적 in-graph 사이클을 방지한다.
        return {"configurable": {"thread_id": _thread_id(tick)}, "recursion_limit": rlimit}

    # tick 0: state0 에서 seed. seq 는 틱을 가로질러 이어지는 단조 node-update 인덱스라
    # 정규 run.jsonl 이 byte-identical(GATE2)하다: 동일한 결정론 실행마다
    # seq=0 부터 동일한 {seq,node,patch} 시퀀스를 낸다.
    state, seq = _tick(graph, state0, _cfg(0), jsonl_path, 0)

    tick = 1
    while True:
        if not forever and (state.get("goal_reached") or int(state.get("tick_i", 0)) >= max_iters
                or int(state.get("pivots", 0)) >= max_pivots
                or int(state.get("dry_streak", 0)) >= k_dry):
            break
        if tick_interval_s and tick_interval_s > 0:
            import time as _t
            _t.sleep(tick_interval_s)              # 상시 감시: collector interval 에 맞춰 관측(스핀 방지)
        # 이전 틱의 read-back 상태로 FRESH 스레드에서 re-seed(stream(None) 이 아님,
        # 그것은 END 로 종료된 스레드에서 no-op). full 상태를 앞으로 이어가면
        # tick_i 가 전진하고 ledger/decisions/incidents 가 정확히 한 번 누적된다.
        state, seq = _tick(graph, state, _cfg(tick), jsonl_path, seq)
        # P3 pruning: 이번 틱의 post-state 는 이제 read back 되어 다음 seed 로 이어졌으므로,
        # 방금 대체된 이전 스레드(t{tick-1})는 루프가 아직 필요로 하는 것을 아무것도 갖지
        # 않는다(replay 는 checkpointer 가 아니라 run.jsonl 을 읽는다). 이를 버려서
        # InMemorySaver 를 O(ticks x state) 대신 O(1) 스레드로 유계화한다. 삭제해도
        # 기록된 스트림, 현재/다음 틱(fresh 스레드, 값으로 seed), run_driver 의 반환에
        # 영향을 주지 않는다 -> replay 는 byte-identical, 틱 진행은 불변.
        _prune_thread(graph, _thread_id(tick - 1))
        tick += 1
    return state


def _prune_thread(graph, thread_id: str) -> None:
    """대체된 per-tick 스레드를 삭제하여 checkpointer 메모리를 유계화한다(감사 P3).

    delete_thread(thread_id) 는 langgraph-checkpoint >= 2.0.25 에서만 BaseCheckpointSaver/
    InMemorySaver 에 정의된다(검증: 2.0.24 까지 부재, 2.0.25/2.0.26 에 존재;
    InMemorySaver 는 이를 오버라이드하여 해당 스레드의 storage/writes/blobs 를 버린다). langgraph==0.2.60
    은 langgraph-checkpoint ^2.0.4 (>=2.0.4,<3.0.0)을 고정하고 requirements.txt 는
    checkpoint 하위 패키지를 고정하지 않으므로, 더 오래된 해석 빌드에는 이 메서드가 없을 수 있다. 기능 탐지 후
    없으면 no-op — fail-safe: >=2.0.25 에서는 메모리가 유계, 더 오래된 빌드에서도 루프는 여전히
    올바르게 동작한다(단지 이전처럼 pruning 안 됨). 컴파일된 그래프는 saver 를
    공개 ``.checkpointer`` 속성으로 노출한다(Pregel 필드; 없이 컴파일되면 None, 예:
    테스트). 모든 pruning 오류는 삼켜진다: pruning 은 best-effort 이며 틱을 절대 크래시시키면 안 된다.
    leak-0 은 불변(subprocess 없음; delete_thread 는 순수 in-memory dict 삭제)."""
    saver = getattr(graph, "checkpointer", None)
    if saver is None:
        return
    delete_thread = getattr(saver, "delete_thread", None)
    if not callable(delete_thread):
        return
    try:
        delete_thread(thread_id)
    except Exception:
        pass


def _tick(graph, inp: Any, invoke_cfg: dict, jsonl_path: str,
          seq_start: int = 0) -> tuple[MDGState, int]:
    """정확히 ONE graph 실행(1 tick)을 돌린다; ``(final_state, next_seq)`` 를 반환한다.

    단일 graph.stream() 패스가 곧 실행이다(불변식2.: act 부작용은 틱당 한 번 실행,
    절대 두 번 아님). 기록은 replay.record.record_update 로 위임된다 —
    유일한 정규 recorder(project -> redact -> 정규 sort_keys 직렬화 -> 최종
    scrub), 따라서 production driver 와 테스트된 recorder 는 정규 {seq,node,patch} 스키마를
    내는 단일 byte-identical 계약이다(레거시 {node:patch} 아님).
    기록 실패는 driver 를 절대 크래시시키지 않는다. 틱의 최종 상태는
    checkpointer 에서 read back 된다(graph.get_state) 그래야 기록된 틱과 루프 조건 상태가
    하나의 동일한 실행이 된다(불변식1.).
    """
    # 지연 import: record.py 가 driver(redact/_scrub_str)를 import 하므로, 모듈
    # 로드 시 import 하면 사이클이 생긴다. 여기서는 import-safe(langgraph/fastapi 의존 없음).
    from ..replay.record import record_update

    seq = seq_start
    fh = None
    if jsonl_path:
        try:
            fh = open(jsonl_path, "a", encoding="utf-8")
        except Exception:
            fh = None
    try:
        # 스트림을 소비하면 그래프가 정확히 한 번 구동된다; 각 update 를 기록한다.
        for update in graph.stream(inp, invoke_cfg, stream_mode="updates"):
            if not isinstance(update, dict):
                continue
            if fh is not None:
                seq = record_update(fh, seq, update)   # 정규, byte-identical
            else:
                seq += len(update)                     # I/O 없이도 seq 를 단조 유지
    finally:
        if fh is not None:
            try:
                fh.close()
            except Exception:
                pass
    # checkpointer 가 post-tick 상태를 보유한다; 이를 read back(단일 진실원)
    snap = graph.get_state(invoke_cfg)
    return snap.values, seq
