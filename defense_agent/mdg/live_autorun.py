"""live_autorun (P2) — 운영용 자율 live 런처.

scratchpad 임시 스크립트를 관측자 lifecycle 을 소유하는 실제 모듈로 대체한다. 순서는 정확히:

    recon_boot  (그래프 밖: read-only 역할/IP 해석 + seq/ledger boot 복구)
      -> build_collectors(start)  (표준 6-set, recon PID 로부터 netns 브리지)
      -> build_graph              (결정론 StateGraph; LLM advisory, checkpointer)
      -> run_driver               (그래프 밖 tick 루프; tick 별 run.jsonl)

그리고 종료 경로에서 관측자를 항상 회수하는 try/finally(audit P2: 종료 시 관측자 미회수).
``_shutdown`` 은 모든 collector 를 stop 하고 join(유계)한 다음 ``Backend.teardown()`` 을 호출해
labelled crash-orphan subprocess 를 reap 한다(R4). 각 단계는 개별적으로 guard 되어 한 실패가
나머지를 좌초시킬 수 없다 -> shutdown 누수-0(불변식2.).

불변식 규율:
  - 불변식2. (누수-0): 유일한 subprocess 경로는 주입된 ``Backend``(safe-exec R1~R6)다.
    이 모듈은 직접 아무것도 spawn 하지 않는다 — netns PID 를 해석하는 boot ``docker inspect`` 조차
    ``Backend.run``(``_SafeExecDocker``)을 경유하므로 spawn 지점은 정확히 하나다. 종료 시
    ``_shutdown`` 은 collector 가 stop/join 되고 labelled orphan 이 reap 됨을 보장한다.
  - operator-go (allow_live 기본 False): ``allow_live`` 는 ``MDG_ALLOW_LIVE`` 에서 오며 기본
    False(운영 제약 유보)다. non-allow_live Backend 는 모든 상태변경 actuation 을 DRY 로 유지한다;
    ``docker inspect``(read-only fast-path 아님) 역시 DRY 로 남아, 해석된 PID 가 필요한 netns tap 은
    operator 가 플래그를 뒤집기 전까지 inert 로 동작한다. netns 무관 collector(NetworkMetric :9090
    httpx / Mongo ``docker logs`` / Mission)는 allow_live=False 에서도 여전히 관측한다.

진입점: ``python -m mdg.live_autorun --out <dir> --run-id <id> [--max-iters N]``.
langgraph 는 LAZY 하게 import 되므로(``build_graph`` 와 saver factory 내부) 이 모듈 —
그리고 그 단위 테스트 — 은 langgraph 없이 import 된다.
"""
from __future__ import annotations

import argparse
import os
import queue as _queue
import secrets
import sys
import time
from typing import Any, Callable, Optional

from .collector import build_collectors, build_epc_collectors, build_source_domains
from .collector.ingest import Keyring, envelope_to_ev, verify_envelope
from .core.clock import Clock, RealClock
from .core.driver import run_driver
from .core.graph import build_graph
from .core.recon import recon_boot
from .ledger.intent_ledger import IntentLedger, SeqWatermark
from .llm import build_llm_deps
from .safe_exec.backend import Backend, ExecRequest
from .safe_exec.nsenter_helper import build_netns_prefix_map
from .safe_exec.observer import make_effect_observer

# 유계 관측 큐 (DoS 상한: collector 는 Full 시 drop, 절대 증가하지 않음 — base.py push()).
_QUEUE_MAX = 20000
# MDG_ALLOW_LIVE 용 env truthy 어휘 (operator-go 전환).
_TRUE = frozenset({"1", "true", "yes", "on"})


def parse_allow_live(env) -> bool:
    """operator-go 게이트: allow_live 는 MDG_ALLOW_LIVE 가 명시적 truthy 토큰일 때만 True.
    부재/공백/그 외 -> False(운영 제약 유보 default). 절대 추론하지 않음."""
    return str(env.get("MDG_ALLOW_LIVE", "")).strip().lower() in _TRUE


def parse_operator_auto(env) -> bool:
    """sandbox OPER 자동승인 게이트: operator_auto 는 MDG_OPERATOR_AUTO 가 명시적 truthy 토큰일 때만
    True(allow_live 와 동일 어휘). 부재/공백/그 외 -> False(안전 기본: OPER 티어는 사람 대기/escalate).
    SITL/데모 전용 — Phase 1 이 이 값을 gate/edge 로 소비해 OPER 대응을 자동승인·집행한다.
    결정론(불변식1.): env 입력만으로 분기 결정, LLM 불가시."""
    return str(env.get("MDG_OPERATOR_AUTO", "")).strip().lower() in _TRUE


def parse_operator_pick(env) -> str:
    """1. operator-select 입력: operator 가 적법 후보 집합에서 명시적으로 고른 recovery_type 또는
    tool_id(env MDG_OPERATOR_PICK). strip 된 토큰을 반환하고, 미설정/공백 시 "" 를 반환한다.
    설정되고 적법 Action 과 매칭되면 rank_recovery 가 이를 chosen_action 으로 승격한다(send_signed_mode
    를 가역 blockade 아래로 영구 강등하는 자율 랭킹을 override); 공백/비매칭 값은 자율 랭킹을 그대로
    둔다(fail-safe). allow_live/operator_auto 와 달리 이는 boolean 게이트가 아니라 — 값을 실어 나른다 —
    _TRUE 를 거치지 않는다. 결정론(불변식1.): env 문자열만으로 결정, LLM 불가시."""
    return str(env.get("MDG_OPERATOR_PICK", "")).strip()


def _make_keyring(run_id: str) -> tuple[Keyring, str]:
    """run 별 임시 HMAC keyring. collector 가 서명하고 ``verify`` 가 동일 프로세스에서 검증하므로,
    새 랜덤 키는 영속화가 필요 없고 source 나 State 를 절대 건드리지 않는다(PS-3: 키는 Keyring 에만
    존재). 하드코딩된 키는 커밋된 secret 이 될 것이다."""
    kid = f"live-{run_id}"
    return Keyring(keys={kid: secrets.token_bytes(32)}), kid


def _make_verify(keyring: Keyring, seqwm: SeqWatermark) -> Callable[[Any], tuple[bool, str, Any]]:
    """``sense`` 가 drain 시 호출하는 ``verify(env) -> (ok, reason, SensorEv)`` 클로저 생성:
    HMAC+seq 검사(ingest.verify_envelope) 후 SensorEv 로 투영(tamper=not ok)."""
    def verify(env):
        ok, reason = verify_envelope(env, keyring, seqwm)
        return ok, reason, envelope_to_ev(env, ok)
    return verify


class _SafeExecDocker:
    """duck-typed ``docker`` backend(``inspect_pid`` / ``inspect_networks``)으로, 이 런처가 직접
    subprocess 지점을 0 으로 유지하도록 safe-exec ``Backend`` 를 경유한다(불변식2.).

    ``docker inspect`` 는 READ-ONLY docker-daemon 메타데이터 읽기다(resolve.py stage-1: 컨테이너
    존재 + ``.State.Pid`` + cellular IP — netns 진입 아님, 상태변경 아님). 따라서 ``read_only=True``
    로 전송되고 allow_live=False 에서 실행된다(recon 이 pid 를 해석 -> netns collector 가 관측 =
    operator-go 없이 read-only 탐지 동작). 이는 ss/tcpdump collector(역시 read-only)를 반영한다.
    stage-2 tun-scan(nsenter 경유 ``ip -4 addr show``)은 operator-go 로 남으므로(whitelist 아님)
    UE-pool role_verified — 따라서 DROP 결정 — 은 여전히 allow_live 창을 요구한다. 단일 ``Backend._spawn``
    지점을 통해 spawn 한다(R1~R6 teardown). ``.State.Pid`` / ``.NetworkSettings.Networks[*].IPAddress``
    만 파싱한다(PS-3: 절대 ``.Config.Env`` 아님).
    """

    def __init__(self, backend: Backend):
        self.backend = backend

    def _inspect(self, container: str, fmt: str) -> Optional[str]:
        try:
            res = self.backend.run(ExecRequest(
                argv=["docker", "inspect", "-f", fmt, container], timeout_s=8.0, read_only=True))
        except Exception:
            return None
        if res is None or getattr(res, "dry_run", False) or not getattr(res, "ok", False):
            return None                                  # operator-go DRY / 실패 -> inert
        return (res.stdout or "").strip()

    def inspect_pid(self, container: str) -> Optional[int]:
        out = self._inspect(container, "{{.State.Pid}}")
        if out and out.lstrip("-").isdigit() and int(out) > 0:
            return int(out)
        return None

    def inspect_networks(self, container: str) -> dict[str, str]:
        fmt = "{{range $k,$v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}"
        out = self._inspect(container, fmt)
        if not out:
            return {}
        return {t.split("=", 1)[0]: t.split("=", 1)[1] for t in out.split() if "=" in t}

    def pause(self, container: str) -> ExecResult:
        """Phase 4 S1 actuator: 공격자 컨테이너를 freeze(``docker pause``). 이는 상태변경
        (read_only=False)이므로 backend 에서 allow_live 가 뒤집힐 때까지 operator-go DRY 로 남는다 —
        netns DROP 과 동일한 actuation 게이트. ``docker unpause`` 로 가역(revert_cmd 로 기록).
        단일 Backend._spawn 지점을 경유한다(불변식2.)."""
        return self.backend.run(ExecRequest(
            argv=["docker", "pause", container], timeout_s=8.0, reversible=True,
            revert_cmd=f"docker unpause {container}"))

    def unpause(self, container: str) -> ExecResult:
        """``pause`` 의 revert(de-escalation / recover-on-boot). 상태변경 -> allow_live 게이트."""
        return self.backend.run(ExecRequest(
            argv=["docker", "unpause", container], timeout_s=8.0, reversible=True))

    def inspect_paused(self, container: str) -> Optional[bool]:
        """Phase 4 effect-confirm probe: 컨테이너의 ``.State.Paused``(read-only inspect).

        메타데이터 읽기가 성공하면 True/False 를, DRY/실패/미해석 시 None 을 반환하여 observer 가
        불확정 읽기를 UNCONFIRMED 로 취급하게 한다(가짜 recovery-confirm 절대 없음). pid/network
        해석과 동일한 single-spawn, read-only ``inspect`` 경로(불변식2.)."""
        out = self._inspect(container, "{{.State.Paused}}")
        if out is None:
            return None
        return out.strip().lower() == "true"


def _default_saver():
    """driver 의 tick 별 스레드용 LangGraph checkpointer(lazy import 되어 이 모듈은 langgraph
    없이 로드됨). InMemorySaver 가 현재 이름이고 MemorySaver 는 구 별칭 — fallback 하며, langgraph
    부재 시 None 으로(그러면 build_graph 가 자체 명확한 ImportError 로 실패 지점이 됨)."""
    try:
        from langgraph.checkpoint.memory import InMemorySaver
        return InMemorySaver()
    except Exception:
        try:
            from langgraph.checkpoint.memory import MemorySaver
            return MemorySaver()
        except Exception:
            return None


def _shutdown(collectors, backend, join_timeout: float = 10.0) -> None:
    """예외 안전 관측자 회수(audit P2, 불변식2. 종료 누수-0).

    순서: 먼저 모든 collector 를 stop()(대기 전에 전체 roster 에 신호를 보내 총 대기가 합이 아닌
    ~max(interval) 이 되도록), 그다음 각각을 유계 timeout 으로 join(), 그다음 Backend.teardown() 으로
    labelled crash-orphan subprocess 를 reap(R4 — mode=='mock' 에서만 gate 되므로 read-only 관측자가
    실제로 spawn 하는 allow_live=False 에서도 실행됨). 각 단계는 개별적으로 guard 된다: 예외를
    던지거나 시작되지 않은 collector 가 나머지의 stop 이나 backend teardown 을 막을 수 없다."""
    for c in collectors or []:
        try:
            c.stop()
        except Exception:
            pass
    for c in collectors or []:
        try:
            c.join(timeout=join_timeout)                 # 시작되지 않은 스레드 join 은 예외 -> guard
        except Exception:
            pass
    if backend is not None:
        try:
            backend.teardown()
        except Exception:
            pass


def run(out_dir: str, run_id: str, *, allow_live: bool = False, operator_auto: bool = False,
        operator_pick: str = "", docker=None,
        backend: Optional[Backend] = None, max_iters: Optional[int] = None,
        forever: bool = False, tick_interval_s: float = 0.0,
        clock: Optional[Clock] = None, keyring: Optional[Keyring] = None,
        kid: Optional[str] = None, seqwm: Optional[SeqWatermark] = None,
        ledger=None, join_timeout: float = 10.0,
        collector_builder: Callable = build_collectors,
        epc_builder: Optional[Callable] = build_epc_collectors,
        graph_builder: Callable = build_graph,
        driver_fn: Callable = run_driver,
        saver_factory: Callable = _default_saver,
        source_domains_fn: Callable = build_source_domains) -> Any:
    """Boot -> collectors(start) -> graph -> driver, 관측자를 항상 회수하는 try/finally 와 함께(P2).
    driver 의 최종 state 를 반환한다. ``*_builder``/``*_fn``/factory seam 은 실제 함수를 기본값으로
    가지며, lifecycle(shutdown 경로 포함)이 langgraph 나 live 스레드 없이 단위 테스트 가능하도록
    존재한다."""
    run_out = os.path.join(out_dir, run_id)
    os.makedirs(run_out, exist_ok=True)
    jsonl_path = os.path.join(run_out, "run.jsonl")

    clock = clock or RealClock()
    if backend is None:
        backend = Backend(allow_live=allow_live, mode="local")
    if keyring is None:
        keyring, kid = _make_keyring(run_id)
    if seqwm is None:
        seqwm = SeqWatermark(path=os.path.join(run_out, "seqwm.json"))
    if ledger is None:
        ledger = IntentLedger(os.path.join(run_out, "intents.jsonl"))

    # -- boot (그래프 밖): 역할/IP 해석(read-only) + seq/ledger 복구(PS-6/G3) -- #
    state0 = recon_boot(cfg=None, seqwm=seqwm, ledger=ledger, docker=docker, backend=backend)
    # Phase 1 env->STATE 배선: route_after_decide(edges.py)는 OPER 경로를 자동승인하려 ``operator_auto``
    # STATE 채널을 읽지만, recon_boot/initial_state 는 이를 절대 설정하지 않고 어떤 노드도 반환하지 않는다
    # — deps 는 이를 ACT 노드 kwarg 로만 바인드한다(노드 kwarg 는 state 채널이 아니다).
    # 조건부 edge 가 실제로 읽을 수 있도록 여기서 state0 에 시드한다. LastValue 채널이며 driver 가 매 tick
    # state 를 앞으로 나른다(재시드)므로 이는 모든 tick 에서 유지된다.
    # 부재/False 는 레거시 escalate 자세를 유지(회귀 0). 결정론(불변식1.): env bool 만.
    state0["operator_auto"] = bool(operator_auto)
    # 1. operator-select: 선택된 recovery_type/tool_id 를 rank_recovery 가 읽는 STATE 채널에 시드한다
    # (operator_auto 와 동일한 seed-once-carry-each-tick 패턴 — LastValue, 어떤 노드도 반환 안 함).
    # 공백 -> 자율 랭킹(회귀 0). 결정론(env 문자열만, 불변식1.).
    state0["operator_pick"] = str(operator_pick or "")
    world = state0.get("worldstate")
    pidmap = dict(getattr(world, "pid", {}) or {})
    netns_prefix_map = build_netns_prefix_map(pidmap)     # container -> nsenter prefix (미해석 시 inert)

    inbox = _queue.Queue(maxsize=_QUEUE_MAX)
    verify_fn = _make_verify(keyring, seqwm)
    collectors = collector_builder(inbox, keyring, kid, backend=backend, clock=clock,
                                   netns_prefix_map=netns_prefix_map)
    # P4: EPC log-tail(SmfSession)이 LIVE SmfSessionTable 을 공급하여, act-path stale-binding guard 의
    # (b) 교차확인이 집행 시점에 drop-source IP 를 그 IMSI 로 재귀속한다(재할당된 UE-pool IP -> inert,
    # 무고한 UE self-DoS 없음). Read-only docker-logs tail. Fail-safe: EPC builder 가 부재/예외면
    # smf_table 은 None 으로 남아 guard 가 best-effort (a) 로 degrade 된다.
    smf_table = None
    if epc_builder is not None:
        try:
            epc_collectors, smf_table = epc_builder(inbox, keyring, kid, backend=backend, clock=clock)
            collectors = list(collectors) + list(epc_collectors)
        except Exception:
            smf_table = None
    # Phase 4: effect-confirm observer(read-only 회복 관측) -> effect_confirm(observe=...).
    # 적용된 각 rule 을 그 response_tool 로 해석하고 READ-ONLY probe 로 확인한다:
    # docker_pause->inspect .State.Paused / nsenter_input_drop->ss (대상 netns 에 5762 ESTAB 없음) /
    # send_signed_mode->telemetry rel_alt 30m 회복. 모든 probe 는 단일 Backend 를 경유한다
    # (불변식2.). 이전엔 None 이었음(effect_confirm 이 항상 confirmed=False -> 회복 신호 없음).
    # Phase 5: AirTelemetryTap(14560/14550 디코드)의 live 비행상태 snapshot 을 observer 에 배선하여
    # send_signed_mode(S2 signed_guided 30m 복귀)가 실제로 CONFIRM 할 수 있게 한다.
    # ``snapshot`` 으로 duck-typed 되므로 커스텀/부재 collector_builder 는 단순히 telemetry 를
    # None 으로 둔다(signed 경로는 UNCONFIRMED 로 남음, 안전 — Phase 4 자세 무변경). Read-only snapshot.
    telemetry_fn = None
    for c in collectors:
        snap = getattr(c, "snapshot", None)
        if getattr(c, "source_id", None) == "air_telemetry_tap" and callable(snap):
            telemetry_fn = snap
            break
    observe = make_effect_observer(
        docker=docker, netns_prefix_map=netns_prefix_map, backend=backend, telemetry=telemetry_fn)
    deps = {
        "inbox": inbox, "verify": verify_fn, "clock": clock, "backend": backend,
        "ledger": ledger, "observe": observe, "gate": None,
        # Phase 4: duck-typed docker backend, operator_auto docker_pause 가 act_host.pause 를 통해
        # 집행되도록(S1 회복). None -> operator-go DRY(fail-safe). effect-observer 가 쓰는 것과 동일한
        # read-only inspect backend; ``pause`` 는 상태변경 -> allow_live 게이트(2.).
        "docker": docker,
        # Phase 0: sandbox OPER 자동승인 플래그 -> build_graph 가 gate/edge 로 넘길 배선(실사용 Phase 1).
        # 기본 False 유지 시 기존 escalate 경로 무변경(회귀 0). 결정론(불변식1.): env 입력만으로 결정.
        "operator_auto": operator_auto,
        # 1. operator-select: 선택된 토큰을 deps 로도 통과시킴(rank_recovery 는 시드된 STATE 채널에서
        # 읽음; deps 는 operator_auto / 향후 binder 와의 parity 를 위해 이를 나른다).
        "operator_pick": str(operator_pick or ""),
        # LLM advisory(orient/decide): ANTHROPIC_API_KEY + litellm/jinja2 있으면 활성, 없으면 {None,None}
        # 결정론 폴백(G6). LLM 은 edge-invisible(라우팅/집행 불가시)이라 켜져도 불변식1. 무손상.
        **build_llm_deps(),
        "smf_table": smf_table,                           # P4 stale-binding guard (b) live 재귀속
        "source_domains": source_domains_fn(collectors),  # liveness 용 {source_id -> domain} (P3-Q5)
        "checkpointer": saver_factory(),                  # tick 별 스레드; driver 가 t-1 을 prune (P3)
    }

    # 여기서 collector 는 스레드 OBJECT 다(아직 실행 전); graph build 부터 driver 까지 모두 finally
    # 아래에서 실행되므로 어디서 예외가 나도 여전히 관측자를 회수한다.
    try:
        graph = graph_builder(deps)
        for c in collectors:
            c.start()
        return driver_fn(graph, run_id, state0=state0, jsonl_path=jsonl_path,
                         max_iters=max_iters, forever=forever, tick_interval_s=tick_interval_s)
    finally:
        _shutdown(collectors, backend, join_timeout)


def _emit_live_banner(operator_auto: bool) -> None:
    """Issue#2(b): allow_live 가 켜지면 stderr 로 굵은 fail-open 경고. 배포되는 .env.example 은
    MDG_ALLOW_LIVE=1 로 나가므로(SITL 데모 기본) fail-closed 서사가 더 이상 암묵적이지 않다 —
    이 배너는 매 기동 시 실제 blast radius 를 명시한다."""
    bar = "=" * 72
    lines = [
        "", bar,
        "  *** LIVE ACTUATION ON (MDG_ALLOW_LIVE=1) — SITL/샌드박스 전용, 실기체 금지 ***",
        "  상태변경(가역 DROP/pause 등)이 실집행될 수 있음. blast radius 확인 필수.",
    ]
    if operator_auto:
        lines.append(
            "  *** OPER 자동승인 ON (MDG_OPERATOR_AUTO=1) — 고위험/비가역 명령도 사람 승인 없이 자동집행 ***")
    lines += [bar, ""]
    print("\n".join(lines), file=sys.stderr, flush=True)


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="mdg.live_autorun",
        description="MDG autonomous live launcher (recon -> collectors -> graph -> driver).")
    p.add_argument("--out", default="./live_out", help="output root dir (run dir = <out>/<run-id>)")
    p.add_argument("--run-id", default=None, help="run id (default: run-<UTC timestamp>)")
    p.add_argument("--max-iters", type=int, default=None, help="driver tick budget (default: config)")
    p.add_argument("--allow-live", action="store_true", default=False,
                   help="operator-go: AUTO 티어 실집행 창 개방(플래그). env MDG_ALLOW_LIVE 와 OR 병합 "
                        "(run_autonomous.sh 가 ALLOW_LIVE=1 시 이 플래그를 전달). 미지정 시 env 가 유일 소스.")
    p.add_argument("--forever", action="store_true",
                   help="24/7 상시 감시 모드 — quiescence/max_iters 무시하고 KeyboardInterrupt 까지 계속 관측.")
    p.add_argument("--interval", type=float, default=2.0,
                   help="상시 감시 모드의 틱 간격(초, --forever 시). collector interval 에 맞춰 CPU 스핀 방지.")
    args = p.parse_args(argv)

    run_id = args.run_id or time.strftime("run-%Y%m%d-%H%M%S", time.gmtime())
    # operator-go: --allow-live 플래그(run_autonomous.sh 경로) OR env(dah.sh monitor/autorun 경로).
    # 둘 다 없으면 default False(운영 제약 유보). env 파서가 여전히 유일 truthy 소스, 플래그는 그 위 OR.
    allow_live = bool(args.allow_live) or parse_allow_live(os.environ)
    operator_auto = parse_operator_auto(os.environ)       # sandbox OPER 자동승인: 기본 False
    operator_pick = parse_operator_pick(os.environ)       # 1. operator-select 토큰: 기본 "" (off)

    if allow_live:
        # Issue#2(b): allow_live=1 이면 monitor/autorun 기동 시 stderr 로 굵은 경고 배너 강제 출력.
        # 이 경로가 monitor 와 autorun 을 모두 관통하는 단일 chokepoint 다(둘 다 live_autorun 경유).
        _emit_live_banner(operator_auto)

    backend = Backend(allow_live=allow_live, mode="local")
    docker = _SafeExecDocker(backend)                     # 단일 spawn 지점을 통한 boot netns 해석
    try:
        run(args.out, run_id, allow_live=allow_live, operator_auto=operator_auto,
            operator_pick=operator_pick, docker=docker, backend=backend,
            max_iters=args.max_iters, forever=args.forever,
            tick_interval_s=(args.interval if args.forever else 0.0))
    except KeyboardInterrupt:
        print("\n감시 종료(KeyboardInterrupt) — 관측자 회수.")   # _shutdown 은 run() 의 finally 가 수행
    return 0


if __name__ == "__main__":
    sys.exit(main())
