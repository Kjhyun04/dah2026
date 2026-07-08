"""run_driver (PA-1/PA-7) — the OUT-OF-GRAPH while loop that owns the loop-back.

Each iteration = exactly ONE graph execution = 1 tick. A tick is driven by a single
graph.stream(inp, cfg, stream_mode='updates') pass: the stream IS the execution, its
updates are recorded (PS-3 redact), and the resulting tick state is read back from the
checkpointer via graph.get_state(cfg). There is NO separate graph.invoke() — running
both would fire the act node's side effect TWICE per iteration (violates 불변식② 누수-0)
and desync the recorded tick from the loop-condition state (violates 불변식①).

Tick continuity (CORRECTED — S-2 live finding): every tick's graph terminates at END
(all loop-backs -> END, by topology). In LangGraph a thread that reached END has NO
pending work, so ``graph.stream(None, cfg)`` on it yields ZERO updates and does not
re-run — the earlier "fixed thread_id + stream(None)" scheme silently froze after tick 0
(tick_i never advanced -> break condition never met -> infinite no-op loop). Continuity is
therefore carried by RE-SEEDING: each tick runs a FULL graph execution on a FRESH
per-tick thread_id, seeded with the prior tick's read-back state as input. A fresh
thread_id makes the Annotated[list, operator.add] channels (ledger/decisions/incidents)
reduce onto the carried value EXACTLY ONCE (verified: no double-accumulation); re-seeding
the SAME thread would double them, which is why input was previously withheld. The driver
READS counters only (nodes own the increments). recursion_limit=16 guards against any
accidental in-graph cycle.

Recording hook (PS-3): each streamed update -> redact() at record creation time ->
run.jsonl append. Secrets are structurally absent from State, and redact() additionally
scrubs any residual secret pattern.
"""
from __future__ import annotations

from typing import Any, Optional

from ..config import defaults as D
from ..redact_patterns import SECRET_PATTERNS as _SECRET_PATTERNS
from .state import MDGState

# residual-secret scrub patterns (PS-3) — belt-and-suspenders over structural absence.
# Applied to string LEAVES only (never to serialized JSON) so structure stays valid.
# The pattern list is the shared single source (mdg.redact_patterns) so the record-time
# scrub here and the viewer load-time scan cannot drift.


def _scrub_str(s: str) -> str:
    for pat in _SECRET_PATTERNS:
        s = pat.sub("[REDACTED]", s)
    return s


def redact(record):
    """Scrub residual secret patterns at RECORD CREATION time (not viewer time).
    Recurses over the structure and scrubs string leaves only (PS-3)."""
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
    """Drive the compiled graph. Returns the final state. Break conditions (PA-1):
    goal_reached ∨ tick_i>=max_iters ∨ pivots>=max_pivots ∨ dry_streak>=k_dry.
    Safe operator LAND is budget-exempt (G10) — enforced by not counting escalate
    ticks as dry (escalate does not increment dry_streak).

    forever (24/7 감시 모드): True 면 위 break 조건을 전부 무시하고 KeyboardInterrupt/프로세스
    종료까지 계속 관측한다 — 평시(quiescence)에 멈추지 않는 상시 탐지 데몬. tick_interval_s>0 이면
    매 틱 사이에 그만큼 대기(collector interval 에 맞춰 CPU 스핀 방지). 배치/replay(demo·campaign)는
    forever=False 기본이라 결정론·바이트동일 재생이 무손상(불변식① 무영향). Green 평시 틱은 조기 END 라
    incident/decision 채널이 누적하지 않아(operator.add([]) = 무증가) 상시런 메모리는 실제 사건 수로 유계."""
    budgets = D.DRIVER_BUDGETS
    max_iters = max_iters if max_iters is not None else budgets["max_iters"]
    max_pivots = max_pivots if max_pivots is not None else budgets["max_pivots"]
    k_dry = k_dry if k_dry is not None else budgets["k_dry"]
    rlimit = budgets["recursion_limit"]

    def _thread_id(tick: int) -> str:
        # single-sourced per-tick thread id (used by both _cfg and the P3 pruner so they
        # cannot drift). deterministic (run_id-t<tick>) so replay stays byte-identical.
        return f"{run_id}-t{tick}"

    def _cfg(tick: int) -> dict:
        # FRESH thread_id per tick (S-2): each tick is one full graph run terminating at
        # END; a fresh thread lets the carried state re-seed the operator.add channels
        # exactly once. thread_id is deterministic (run_id-t<tick>) so replay stays
        # byte-identical (GATE2). recursion_limit guards accidental in-graph cycles.
        return {"configurable": {"thread_id": _thread_id(tick)}, "recursion_limit": rlimit}

    # tick 0: seed from state0. seq is a monotonic node-update index carried ACROSS ticks so
    # the canonical run.jsonl is byte-identical (GATE2): every identical deterministic run
    # yields the same {seq,node,patch} sequence from seq=0.
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
        # re-seed with the prior tick's read-back state on a FRESH thread (NOT stream(None),
        # which is a no-op on an END-terminated thread). Carrying the full state forward
        # advances tick_i and accumulates ledger/decisions/incidents exactly once.
        state, seq = _tick(graph, state, _cfg(tick), jsonl_path, seq)
        # P3 pruning: this tick's post-state is now read back and carried into the next
        # seed, so the just-superseded prior thread (t{tick-1}) holds nothing the loop still
        # needs (replay reads run.jsonl, not the checkpointer). Drop it to bound the
        # InMemorySaver at O(1) threads instead of O(ticks x state). Deleting it does NOT
        # touch the recorded stream, the current/next tick (fresh thread, seeded by value),
        # or run_driver's return -> replay stays byte-identical, tick progression unchanged.
        _prune_thread(graph, _thread_id(tick - 1))
        tick += 1
    return state


def _prune_thread(graph, thread_id: str) -> None:
    """Bound checkpointer memory (audit P3) by deleting a superseded per-tick thread.

    delete_thread(thread_id) is defined on BaseCheckpointSaver/InMemorySaver only in
    langgraph-checkpoint >= 2.0.25 (verified: absent through 2.0.24, present 2.0.25/2.0.26;
    InMemorySaver overrides it to drop storage/writes/blobs for that thread). langgraph==0.2.60
    pins langgraph-checkpoint ^2.0.4 (>=2.0.4,<3.0.0) and requirements.txt does not pin the
    checkpoint sub-package, so an older resolved build may lack the method. Feature-detect and
    no-op if absent — fail-safe: on >=2.0.25 memory is bounded, on older builds the loop still
    runs correctly (just unpruned, as before). The compiled graph exposes the saver as the
    public ``.checkpointer`` attribute (Pregel field; None when compiled without one, e.g.
    tests). Any pruning error is swallowed: pruning is best-effort and must never crash a tick.
    leak-0 is untouched (no subprocess; delete_thread is a pure in-memory dict delete)."""
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
    """Run EXACTLY ONE graph execution (1 tick); return ``(final_state, next_seq)``.

    The single graph.stream() pass IS the execution (불변식②: the act side effect runs
    once per tick, never twice). Recording is DELEGATED to replay.record.record_update —
    the ONE canonical recorder (project→redact→canonical sort_keys serialization→final
    scrub), so the production driver and the tested recorder are a single byte-identical
    contract emitting the canonical {seq,node,patch} schema (not the legacy {node:patch}).
    Recording failures never crash the driver. The tick's final state is read back from the
    checkpointer (graph.get_state) so the recorded tick and the loop-condition state are one
    and the same execution (불변식①).
    """
    # Lazy import: record.py imports driver (redact/_scrub_str), so importing it at module
    # load would form a cycle. It is import-safe here (no langgraph/fastapi dependency).
    from ..replay.record import record_update

    seq = seq_start
    fh = None
    if jsonl_path:
        try:
            fh = open(jsonl_path, "a", encoding="utf-8")
        except Exception:
            fh = None
    try:
        # consuming the stream drives the graph exactly once; record each update.
        for update in graph.stream(inp, invoke_cfg, stream_mode="updates"):
            if not isinstance(update, dict):
                continue
            if fh is not None:
                seq = record_update(fh, seq, update)   # canonical, byte-identical
            else:
                seq += len(update)                     # keep seq monotonic even without I/O
    finally:
        if fh is not None:
            try:
                fh.close()
            except Exception:
                pass
    # the checkpointer holds the post-tick state; read it back (single source of truth)
    snap = graph.get_state(invoke_cfg)
    return snap.values, seq
