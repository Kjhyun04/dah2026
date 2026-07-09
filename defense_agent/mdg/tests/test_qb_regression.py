"""test_qb_regression — 관심 그룹 Q-B 회귀 커버리지(동작 고정 전용).

이 테스트들은 추가(ADDITIVE) 성격이다. G-A / G-C / G-D 가 확립한(그리고 자율 DROP 경로가
의존하는) 동작을 고정하여, 이후 리팩터가 이를 조용히 회귀시키지 못하게 한다.
프로덕션 코드는 수정하지 않으며, 모든 assert 는 현재 트리에 대해 통과한다.

커버 범위(Q-B 기준):
  1. safe_exec/backend.is_read_only_argv — read_only 신뢰경계 허용목록
     (관측 바이너리 + 금지된 write/exec/rotate 플래그 + docker->logs/inspect 만 허용,
     nsenter 언랩, ip 는 설계상 read-only 아님).
  2. Backend.run read_only 세마포어 분리 — read_only 는 allow_live=False 에서도 pool=1
     세마포어 없이 spawn; 상태 변경 요청은 DRY 로 유지.
  3. core/driver.run_driver — 틱별 신규 thread_id (run_id-t<tick>), 틱당 정확히
     한 번(single stream 통과, invoke 이중 발화 없음)의 operator.add 누적, 그리고
     이전 thread 프루닝 시도.
  4. core/nodes/correlate — Port_5762_State -> BACKDOOR_5762 kind + target=e.source;
     5762 아닌 트립 신호는 전용 kind 를 절대 받지 않음.
  5. collector/web.parse_ss_peer — 4열(State 필터링) 및 5열 ss 행 모두
     피어 IP 를 산출; 비정상/빈 입력은 ""로 fail-closed.
  6. G-A verify_routing 스코프 확장('source' 금지 + 제어흐름 조건
     스코핑) 및 G-C 수정(mongo dedupe 타임버킷 재발행, air_side band 매핑).

실행: ``python mdg/tests/test_qb_regression.py`` (pytest / langgraph 불필요).
"""
from __future__ import annotations

import ast
import os
import queue
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.collector.air_side import AirCommandTap, AirTelemetryTap          # noqa: E402
from mdg.collector.ingest import Keyring                                   # noqa: E402
from mdg.collector.mongo import MongoLogCollector                          # noqa: E402
from mdg.collector.web import parse_ss_peer                                # noqa: E402
from mdg.core.driver import run_driver                                     # noqa: E402
from mdg.core.nodes.correlate import correlate                            # noqa: E402
from mdg.core.state import SensorEv                                        # noqa: E402
from mdg.safe_exec.backend import (Backend, ExecRequest, ExecResult,       # noqa: E402
                                   PrioritySemaphore, is_read_only_argv)

_KID = "kid-2026"
_KEY = b"unit-test-hmac-key-32-bytes-long!"
_NSPREFIX = ["nsenter", "--target", "4242", "--net", "--"]   # recon 주입 netns 접두


def _kr() -> Keyring:
    return Keyring(keys={_KID: _KEY})


class _FixedClock:
    """설정 가능한 상수를 반환하는 결정론적 clock(stream 소비 없음)으로,
    clock.now() 에서 파생된 타임버킷을 틱 전반에 걸쳐 정확히 제어할 수 있다."""
    def __init__(self, t: float = 0.0):
        self.t = t

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds


def _drain(q: "queue.Queue") -> list:
    out = []
    while True:
        try:
            out.append(q.get_nowait())
        except queue.Empty:
            break
    return out


# =========================================================================== #
# 1. is_read_only_argv — read_only 신뢰경계 허용목록(backend.py 미러)
# =========================================================================== #
def test_is_read_only_argv_accepts_known_observers():
    # nsenter ... ss ... (표준 WebProbe 5762 프로브) — read-only 관측
    ss = _NSPREFIX + ["ss", "-H", "-tan", "state", "established",
                      "( sport = :5762 or dport = :5762 )"]
    assert is_read_only_argv(ss) is True
    # nsenter ... tcpdump 에 -w/-W/-G/-z 플래그 전무 — air-side 탭
    tcp = _NSPREFIX + ["tcpdump", "-l", "-n", "-q", "-c", "20", "-i", "eth0",
                       "udp", "port", "14556"]
    assert is_read_only_argv(tcp) is True
    # nsenter ... docker logs (proxy 경유) — read-only 서브커맨드
    assert is_read_only_argv(_NSPREFIX + ["docker", "logs", "--since", "3s", "epc_mongo"]) is True
    # 단독(non-nsenter) docker inspect — recon 1단계 메타데이터 읽기
    assert is_read_only_argv(["docker", "inspect", "uav_ue"]) is True
    # 단독 ss (non-nsenter) 도 인식
    assert is_read_only_argv(["ss", "-H", "-tan"]) is True


def test_is_read_only_argv_rejects_mutating_and_write_forms():
    # tcpdump -w <file> 은 캡처파일 WRITE -> read-only 아님
    assert is_read_only_argv(_NSPREFIX + ["tcpdump", "-w", "/tmp/cap.pcap", "-i", "eth0"]) is False
    # 금지된 tcpdump 플래그 전부(write / filecount / rotate-seconds / postrotate-exec)
    for bad in ("-w", "-W", "-G", "-z"):
        assert is_read_only_argv(_NSPREFIX + ["tcpdump", bad, "x"]) is False, bad
    # 붙은 형태(-wfile) 도 startswith 검사로 포착
    assert is_read_only_argv(_NSPREFIX + ["tcpdump", "-w/tmp/x"]) is False
    # 변경성 docker 동사는 계속 차단(logs/inspect 만 통과)
    for verb in ("run", "rm", "exec", "pause", "stop", "ps", "kill", "restart"):
        assert is_read_only_argv(_NSPREFIX + ["docker", verb, "uav_ue"]) is False, verb
    # `--` 종료자 없는 nsenter -> [] -> read-only 아님(fail-closed, argv 오독 없음)
    assert is_read_only_argv(["nsenter", "--target", "1", "--net"]) is False
    # ip -4 addr show 는 설계상 OPERATOR-GO 예약 => read-only 아님(ip 는 관측자 아님)
    assert is_read_only_argv(_NSPREFIX + ["ip", "-4", "addr", "show", "tun0"]) is False
    assert is_read_only_argv(["ip", "-4", "addr", "show"]) is False
    # 빈 argv -> False
    assert is_read_only_argv([]) is False


# =========================================================================== #
# 2. Backend.run read_only 세마포어 분리(가짜 _spawn; 실제 subprocess 없음)
# =========================================================================== #
class _CountingSem(PrioritySemaphore):
    """진입(획득) 횟수를 기록하는 pool=1 세마포어."""
    def __init__(self):
        super().__init__(1)
        self.enters = 0

    def __enter__(self):
        self.enters += 1
        return super().__enter__()


class _SpawnProbeBackend(Backend):
    """유일한 spawn 지점을 스텁 처리한 Backend 로, subprocess 를 전혀 건드리지 않고
    run() 라우팅을 관측할 수 있다(leak-0 유지: _spawn 은 실제로 도달하지 않음)."""
    def __init__(self, **kw):
        super().__init__(**kw)
        self.spawned: list[ExecRequest] = []

    def _spawn(self, req: ExecRequest) -> ExecResult:
        self.spawned.append(req)
        return ExecResult(ok=True, code=0, stdout="", dry_run=False)


_SS_ARGV = _NSPREFIX + ["ss", "-H", "-tan"]                       # 검증된 read-only
_DROP_ARGV = _NSPREFIX + ["iptables", "-I", "INPUT", "-s", "10.45.0.13", "-j", "DROP"]  # 변경성


def test_read_only_request_spawns_without_semaphore_even_when_not_live():
    sem = _CountingSem()
    be = _SpawnProbeBackend(allow_live=False, mode="local", semaphore=sem)
    res = be.run(ExecRequest(argv=_SS_ARGV, read_only=True))
    assert res.dry_run is False                # 관측은 자유롭게 허용(RUNBOOK §2)
    assert len(be.spawned) == 1                # 실제로 spawn 됨
    assert sem.enters == 0                     # pool=1 세마포어 미획득(경합 없음)


def test_state_change_request_stays_dry_when_not_live():
    sem = _CountingSem()
    be = _SpawnProbeBackend(allow_live=False, mode="local", semaphore=sem)
    res = be.run(ExecRequest(argv=_DROP_ARGV, read_only=False))
    assert res.dry_run is True and res.ok is True and "operator-go" in res.note
    assert be.spawned == []                    # DRY: operator-go 유보 하에서 spawn 없음
    assert sem.enters == 0


def test_state_change_request_acquires_semaphore_when_live():
    sem = _CountingSem()
    be = _SpawnProbeBackend(allow_live=True, mode="local", semaphore=sem)
    res = be.run(ExecRequest(argv=_DROP_ARGV, read_only=False))
    assert res.dry_run is False
    assert len(be.spawned) == 1                # 작동 spawn(allow_live)
    assert sem.enters == 1                     # 자원 단일성 위해 pool=1 획득


def test_read_only_claim_failing_argv_validation_is_downgraded():
    # 호출자가 read_only=True 를 주장하지만 argv 는 변경성 tcpdump -w 캡처: 그
    # 주장은 강등되어(is_read_only_argv False), allow_live=False 하에서 DRY 로 유지되고
    # 고속경로 spawn 을 절대 취하지 않는다 — 미검증 신뢰경계를 닫는다.
    sem = _CountingSem()
    be = _SpawnProbeBackend(allow_live=False, mode="local", semaphore=sem)
    res = be.run(ExecRequest(argv=_NSPREFIX + ["tcpdump", "-w", "/tmp/x.pcap"], read_only=True))
    assert res.dry_run is True                 # 강등 -> 일반 상태변경 경로 -> DRY
    assert be.spawned == [] and sem.enters == 0


# =========================================================================== #
# 3. run_driver — 틱별 신규 thread_id + 틱당 1회 operator.add + prune
# =========================================================================== #
class _FakeSaver:
    def __init__(self):
        self.deleted: list[str] = []

    def delete_thread(self, thread_id):
        self.deleted.append(thread_id)


class _AccumGraph:
    """가짜 컴파일 그래프. stream() 1회 통과 == 1틱: ledger 항목을 정확히 하나
    추가(operator.add 채널 1회 리듀스)하고 tick_i 를 전진시킨다. 틱별 thread_id 를
    검증할 수 있도록 모든 cfg 를 기록; P3 프루닝 관측을 위해 .checkpointer 를 보유."""
    def __init__(self, saver=None, goal_at=3):
        self.stream_calls = 0
        self.cfgs: list[dict] = []
        self.checkpointer = saver
        self._goal_at = goal_at
        self._ledger: list[str] = []
        self._tick_i = 0

    def stream(self, inp, cfg, stream_mode="updates"):
        assert stream_mode == "updates"
        self.stream_calls += 1
        self.cfgs.append(cfg)
        self._tick_i += 1
        self._ledger.append(f"e{self._tick_i}")     # operator.add: 틱당 하나
        yield {"sense": {"tick_i": self._tick_i}}

    def get_state(self, cfg):
        class _S:
            pass
        s = _S()
        s.values = {"tick_i": self._tick_i, "ledger": list(self._ledger),
                    "goal_reached": self._tick_i >= self._goal_at,
                    "pivots": 0, "dry_streak": 0}
        return s


def _thread_ids(g: _AccumGraph) -> list[str]:
    return [cfg["configurable"]["thread_id"] for cfg in g.cfgs]


def test_run_driver_fresh_thread_id_and_single_accumulation_per_tick():
    saver = _FakeSaver()
    g = _AccumGraph(saver, goal_at=3)
    final = run_driver(g, "run", max_iters=10, max_pivots=10, k_dry=10)
    # 틱 3 에서 목표 도달
    assert final["tick_i"] == 3 and final["goal_reached"] is True
    # 틱별 신규·결정론적 thread id: run-t0, run-t1, run-t2
    assert _thread_ids(g) == ["run-t0", "run-t1", "run-t2"]
    # operator.add 는 틱당 정확히 1회 누적(invoke 이중 발화 없음): 틱당 stream 1회
    # 통과, ledger 는 틱당 정확히 한 항목씩 증가.
    assert g.stream_calls == 3
    assert final["ledger"] == ["e1", "e2", "e3"]
    assert len(final["ledger"]) == g.stream_calls        # 틱당 1회, 이중화 없음
    # 대체된 각 thread 에 대해 이전 thread 프루닝 시도(현재/마지막은 제외)
    assert saver.deleted == ["run-t0", "run-t1"]


def test_run_driver_prune_is_best_effort_when_no_delete_thread():
    # delete_thread 가 없는 checkpointer 는 루프를 중단시키면 안 되고(fail-safe),
    # 틱당 1회 누적은 변하지 않는다.
    class _NoDelete:
        pass
    g = _AccumGraph(_NoDelete(), goal_at=2)
    final = run_driver(g, "run", max_iters=10, max_pivots=10, k_dry=10)
    assert final["tick_i"] == 2 and final["ledger"] == ["e1", "e2"]
    assert _thread_ids(g) == ["run-t0", "run-t1"]


# =========================================================================== #
# 4. correlate — Port_5762_State -> BACKDOOR_5762 직접 유닛
# =========================================================================== #
def test_correlate_5762_yields_backdoor_kind_with_source_target():
    ev = SensorEv(source_id="web_5762_probe", metric="Port_5762_State",
                  value="ESTAB_PRESENT", band="danger", domain="command",
                  source="10.45.0.13")
    out = correlate({"evidence": [ev], "tick_i": 2})
    b = [i for i in out.get("incidents", []) if i.kind == "BACKDOOR_5762"]
    assert len(b) == 1, [i.kind for i in out.get("incidents", [])]
    assert b[0].target == "10.45.0.13"               # target = e.source (피어 IP)
    assert b[0].members == ["Port_5762_State"]


def test_correlate_non_5762_tripped_signal_is_not_backdoor():
    # 트립된(danger) 5762 아닌 메트릭은 single-signal 로 유지되어야 하며 전용
    # BACKDOOR_5762 kind 가 되면 안 됨(uav_ue 5762 DROP 로 라우팅하면 자기 DoS).
    ev = SensorEv(source_id="rtt", metric="RTT_ms", band="critical", source="10.45.0.99")
    out = correlate({"evidence": [ev], "tick_i": 2})
    assert out.get("incidents"), "expected a single-signal incident for the tripped metric"
    assert all(i.kind != "BACKDOOR_5762" for i in out["incidents"])


# =========================================================================== #
# 5. parse_ss_peer — 4열 / 5열 형태 + fail-closed
# =========================================================================== #
def test_parse_ss_peer_four_column_state_filtered():
    # `ss -H -tan state established` 는 State 열을 생략: Recv-Q Send-Q local peer
    row = "0 0 10.45.0.2:5762 10.45.0.13:44321"
    assert parse_ss_peer(row, 5762) == "10.45.0.13"


def test_parse_ss_peer_five_column_state_present():
    # 5열 형태(State 존재) 도 피어를 산출(마지막 두 토큰이 주소)
    row = "ESTAB 0 0 10.45.0.2:5762 10.45.0.13:44321"
    assert parse_ss_peer(row, 5762) == "10.45.0.13"


def test_parse_ss_peer_strips_ipv6_brackets():
    row = "0 0 [fd00::2]:5762 [fd00::13]:44321"
    assert parse_ss_peer(row, 5762) == "fd00::13"


def test_parse_ss_peer_fail_closed_on_malformed():
    assert parse_ss_peer("", 5762) == ""                      # 빈 입력
    assert parse_ss_peer("garbage", 5762) == ""               # 포트 토큰 없음, 열 없음
    assert parse_ss_peer("only :5762 here", 5762) == ""       # <4 열 -> fail-closed
    assert parse_ss_peer("no port token at all here", 5762) == ""


# =========================================================================== #
# 6a. G-A — verify_routing 스코프 확장('source' 금지 + 조건 스코핑)
# =========================================================================== #
def test_gA_verify_routing_source_forbidden_and_decision_modules_green():
    from mdg.verify import verify_routing as VR
    # G-A 는 불투명한 귀속/피벗 셀렉터를 포함하도록 FORBIDDEN_KEYS 를 확장.
    assert {"source", "target", "target_kind", "enforce_at"} <= VR.FORBIDDEN_KEYS
    # 그리고 결정 관련 gate/node 를 스캔해 이들에 대한 제어흐름 분기를 검사.
    assert "gate.py" in VR.DECISION_MODULES and "select_policy.py" in VR.DECISION_MODULES
    # 실제 트리는 GREEN 이어야 함(결정 모듈이 금지 키로 분기하지 않음).
    rep = VR._check()
    assert rep.fails == [], rep.fails
    assert rep.checks > 0


def test_gA_verify_routing_condition_scope_data_vs_branch():
    # 스코프 확장 메커니즘을 고정: 금지 셀렉터의 DATA 운반은 오탐이 아니지만,
    # 이를 제어흐름 CONDITION 에서 사용하면 포착된다.
    from mdg.verify import verify_routing as VR
    data_tree = ast.parse(
        "def f(a):\n"
        "    x = {'target': a.source}\n"                 # dict 값 = DATA
        "    return [i.enforce_at for i in a.items]\n"   # 컴프리헨션 iterable = DATA
    )
    assert VR._condition_keys_in(data_tree) & VR.FORBIDDEN_KEYS == set()
    branch_tree = ast.parse(
        "def f(a):\n"
        "    if a.get('source'):\n"                      # 'source' 에 대한 분기 CONDITION
        "        return 1\n"
        "    return 0\n"
    )
    assert "source" in VR._condition_keys_in(branch_tree)


# =========================================================================== #
# 6b. G-C — mongo dedupe 타임버킷이 이후 윈도우에서 같은 remote 를 재발행
# =========================================================================== #
def test_gC_mongo_dedupe_rebuckets_across_time_window():
    q = queue.Queue()
    line = '{"id":22943,"attr":{"remote":"10.44.0.31:5000"}}'
    be = Backend(mode="mock", mock_table={"docker": line})
    clk = _FixedClock(1.0)
    c = MongoLogCollector(q, _kr(), _KID, backend=be, clock=clk, dedupe_window_s=60.0)
    c.tick_once()
    assert len(_drain(q)) == 1                 # 버킷 0: 첫 수락 발행
    c.tick_once()
    assert len(_drain(q)) == 0                 # 같은 버킷: 중첩 윈도우 dedupe 가 억제
    clk.t = 61.0                               # dedupe 윈도우 지나 전진 -> 버킷 1
    c.tick_once()
    assert len(_drain(q)) == 1                 # 재발행(실제 반복 DB 접근, 마스킹 아님)


# =========================================================================== #
# 6c. G-C — air_side band 매핑(count -> band)
# =========================================================================== #
def test_gC_air_command_tap_band_mapping():
    q = queue.Queue()
    # n == 1 -> warning
    c1 = AirCommandTap(q, _kr(), _KID, backend=Backend(mode="mock", mock_table={"tcpdump": "1 IP a > b"}),
                       clock=_FixedClock(1.0), netns_prefix=_NSPREFIX)
    o1 = c1.collect()
    assert len(o1) == 1 and o1[0]["value"] == 1 and o1[0]["band"] == "warning"
    assert o1[0]["metric"] == "Unauthorized_Command"
    # n >= 2 -> critical
    c2 = AirCommandTap(q, _kr(), _KID,
                       backend=Backend(mode="mock", mock_table={"tcpdump": "1 IP a > b\n2 IP c > d"}),
                       clock=_FixedClock(1.0), netns_prefix=_NSPREFIX)
    o2 = c2.collect()
    assert o2[0]["value"] == 2 and o2[0]["band"] == "critical"
    # n == 0 -> 유휴 기준선, 신호 없음
    c0 = AirCommandTap(q, _kr(), _KID, backend=Backend(mode="mock", mock_table={"tcpdump": ""}),
                       clock=_FixedClock(1.0), netns_prefix=_NSPREFIX)
    assert c0.collect() == []


def test_gC_air_telemetry_tap_band_mapping():
    q = queue.Queue()
    # 패킷 존재 -> Link_Heartbeat / normal
    c = AirTelemetryTap(q, _kr(), _KID, backend=Backend(mode="mock", mock_table={"tcpdump": "1 IP a > b"}),
                        clock=_FixedClock(1.0), netns_prefix=_NSPREFIX)
    o = c.collect()
    assert o[0]["metric"] == "Link_Heartbeat" and o[0]["band"] == "normal"
    # 무음 교차탭 -> Packet_Loss / value 100, 그러나 STATUS 전용 band="normal" (P2): 이 탭은
    # 상시 링크 헬스 상태 소스이며 절대 인시던트 소스가 아니므로, 일시적 공백이 correlate 의
    # single-signal Packet_Loss 를 트립하거나 자율 복구를 구동할 수 없다. 저하된 링크는 여전히
    # 독립 Verifier(메트릭명 키) + 뷰어의 링크 헬스 상태 박스를 통해 노출된다.
    c0 = AirTelemetryTap(q, _kr(), _KID, backend=Backend(mode="mock", mock_table={"tcpdump": ""}),
                         clock=_FixedClock(1.0), netns_prefix=_NSPREFIX)
    o0 = c0.collect()
    assert o0[0]["metric"] == "Packet_Loss" and o0[0]["band"] == "normal" and o0[0]["value"] == 100


def _run_all() -> int:
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"[PASS] {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"[FAIL] {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"[ERROR] {fn.__name__}: {e!r}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
