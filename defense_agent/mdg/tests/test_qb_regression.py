"""test_qb_regression — concern group Q-B regression coverage (locks behavior only).

These tests are ADDITIVE. They lock in behavior that G-A / G-C / G-D established (and
that the autonomous-DROP path depends on) so a later refactor cannot silently regress it.
No production code is modified; every assertion passes against the current tree.

Covers (per Q-B):
  1. safe_exec/backend.is_read_only_argv — the read_only trust-boundary allowlist
     (observer binaries + banned write/exec/rotate flags + docker->logs/inspect only,
     nsenter unwrap, ip NOT read-only by design).
  2. Backend.run read_only semaphore separation — read_only spawns without the pool=1
     semaphore even under allow_live=False; a state-changing request stays DRY.
  3. core/driver.run_driver — fresh per-tick thread_id (run_id-t<tick>), operator.add
     accumulation exactly ONCE per tick (single stream pass, no invoke double-fire), and
     prior-thread pruning attempted.
  4. core/nodes/correlate — Port_5762_State -> BACKDOOR_5762 kind + target=e.source;
     a non-5762 tripped signal never gets the dedicated kind.
  5. collector/web.parse_ss_peer — 4-column (State-filtered) and 5-column ss rows both
     yield the peer IP; malformed/empty fail closed to "".
  6. G-A verify_routing scope expansion ('source' forbidden + control-flow-condition
     scoping) and G-C fixes (mongo dedupe time-bucket re-emit, air_side band mapping).

Run: ``python mdg/tests/test_qb_regression.py`` (no pytest / langgraph needed).
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
_NSPREFIX = ["nsenter", "--target", "4242", "--net", "--"]   # recon-injected netns prefix


def _kr() -> Keyring:
    return Keyring(keys={_KID: _KEY})


class _FixedClock:
    """Deterministic clock returning a settable constant (no stream consumption), so a
    time-bucket derived from clock.now() is exactly controllable across ticks."""
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
# 1. is_read_only_argv — the read_only trust-boundary allowlist (mirrors backend.py)
# =========================================================================== #
def test_is_read_only_argv_accepts_known_observers():
    # nsenter ... ss ... (the canonical WebProbe 5762 probe) — read-only observation
    ss = _NSPREFIX + ["ss", "-H", "-tan", "state", "established",
                      "( sport = :5762 or dport = :5762 )"]
    assert is_read_only_argv(ss) is True
    # nsenter ... tcpdump WITHOUT any -w/-W/-G/-z flag — the air-side taps
    tcp = _NSPREFIX + ["tcpdump", "-l", "-n", "-q", "-c", "20", "-i", "eth0",
                       "udp", "port", "14556"]
    assert is_read_only_argv(tcp) is True
    # nsenter ... docker logs (routed via proxy) — read-only subcommand
    assert is_read_only_argv(_NSPREFIX + ["docker", "logs", "--since", "3s", "epc_mongo"]) is True
    # bare (non-nsenter) docker inspect — recon stage-1 metadata read
    assert is_read_only_argv(["docker", "inspect", "uav_ue"]) is True
    # bare ss (non-nsenter) also recognized
    assert is_read_only_argv(["ss", "-H", "-tan"]) is True


def test_is_read_only_argv_rejects_mutating_and_write_forms():
    # tcpdump -w <file> is a capture-file WRITE -> not read-only
    assert is_read_only_argv(_NSPREFIX + ["tcpdump", "-w", "/tmp/cap.pcap", "-i", "eth0"]) is False
    # every banned tcpdump flag (write / filecount / rotate-seconds / postrotate-exec)
    for bad in ("-w", "-W", "-G", "-z"):
        assert is_read_only_argv(_NSPREFIX + ["tcpdump", bad, "x"]) is False, bad
    # attached form (-wfile) is caught by the startswith check too
    assert is_read_only_argv(_NSPREFIX + ["tcpdump", "-w/tmp/x"]) is False
    # mutating docker verbs stay blocked (only logs/inspect pass)
    for verb in ("run", "rm", "exec", "pause", "stop", "ps", "kill", "restart"):
        assert is_read_only_argv(_NSPREFIX + ["docker", verb, "uav_ue"]) is False, verb
    # nsenter with NO `--` terminator -> [] -> NOT read-only (fail-closed, no argv mis-read)
    assert is_read_only_argv(["nsenter", "--target", "1", "--net"]) is False
    # ip -4 addr show is OPERATOR-GO RESERVED by design => NOT read-only (ip not an observer)
    assert is_read_only_argv(_NSPREFIX + ["ip", "-4", "addr", "show", "tun0"]) is False
    assert is_read_only_argv(["ip", "-4", "addr", "show"]) is False
    # empty argv -> False
    assert is_read_only_argv([]) is False


# =========================================================================== #
# 2. Backend.run read_only semaphore separation (fake _spawn; no real subprocess)
# =========================================================================== #
class _CountingSem(PrioritySemaphore):
    """pool=1 semaphore that records how many times it was entered (acquired)."""
    def __init__(self):
        super().__init__(1)
        self.enters = 0

    def __enter__(self):
        self.enters += 1
        return super().__enter__()


class _SpawnProbeBackend(Backend):
    """Backend whose ONLY-spawn-site is stubbed so we can observe run() routing without
    ever touching subprocess (leak-0 preserved: _spawn is never reached for real)."""
    def __init__(self, **kw):
        super().__init__(**kw)
        self.spawned: list[ExecRequest] = []

    def _spawn(self, req: ExecRequest) -> ExecResult:
        self.spawned.append(req)
        return ExecResult(ok=True, code=0, stdout="", dry_run=False)


_SS_ARGV = _NSPREFIX + ["ss", "-H", "-tan"]                       # validated read-only
_DROP_ARGV = _NSPREFIX + ["iptables", "-I", "INPUT", "-s", "10.45.0.13", "-j", "DROP"]  # mutating


def test_read_only_request_spawns_without_semaphore_even_when_not_live():
    sem = _CountingSem()
    be = _SpawnProbeBackend(allow_live=False, mode="local", semaphore=sem)
    res = be.run(ExecRequest(argv=_SS_ARGV, read_only=True))
    assert res.dry_run is False                # observation permitted freely (RUNBOOK §2)
    assert len(be.spawned) == 1                # it really spawned
    assert sem.enters == 0                     # pool=1 semaphore NOT acquired (no contention)


def test_state_change_request_stays_dry_when_not_live():
    sem = _CountingSem()
    be = _SpawnProbeBackend(allow_live=False, mode="local", semaphore=sem)
    res = be.run(ExecRequest(argv=_DROP_ARGV, read_only=False))
    assert res.dry_run is True and res.ok is True and "operator-go" in res.note
    assert be.spawned == []                    # DRY: no spawn under operator-go 유보
    assert sem.enters == 0


def test_state_change_request_acquires_semaphore_when_live():
    sem = _CountingSem()
    be = _SpawnProbeBackend(allow_live=True, mode="local", semaphore=sem)
    res = be.run(ExecRequest(argv=_DROP_ARGV, read_only=False))
    assert res.dry_run is False
    assert len(be.spawned) == 1                # actuation spawned (allow_live)
    assert sem.enters == 1                     # pool=1 acquired for resource singularity


def test_read_only_claim_failing_argv_validation_is_downgraded():
    # a caller asserts read_only=True but the argv is a mutating tcpdump -w capture: the
    # claim is downgraded (is_read_only_argv False), so under allow_live=False it stays DRY
    # and never takes the fast-path spawn — closing the unvalidated trust boundary.
    sem = _CountingSem()
    be = _SpawnProbeBackend(allow_live=False, mode="local", semaphore=sem)
    res = be.run(ExecRequest(argv=_NSPREFIX + ["tcpdump", "-w", "/tmp/x.pcap"], read_only=True))
    assert res.dry_run is True                 # downgraded -> normal state-changing path -> DRY
    assert be.spawned == [] and sem.enters == 0


# =========================================================================== #
# 3. run_driver — fresh per-tick thread_id + once-per-tick operator.add + prune
# =========================================================================== #
class _FakeSaver:
    def __init__(self):
        self.deleted: list[str] = []

    def delete_thread(self, thread_id):
        self.deleted.append(thread_id)


class _AccumGraph:
    """Fake compiled graph. One stream() pass == one tick: it appends EXACTLY ONE ledger
    entry (an operator.add channel reduced once) and advances tick_i. Records every cfg so
    the per-tick thread_id can be asserted; carries a .checkpointer to observe P3 pruning."""
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
        self._ledger.append(f"e{self._tick_i}")     # operator.add: ONE per tick
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
    # ran to goal at tick 3
    assert final["tick_i"] == 3 and final["goal_reached"] is True
    # fresh, deterministic per-tick thread id: run-t0, run-t1, run-t2
    assert _thread_ids(g) == ["run-t0", "run-t1", "run-t2"]
    # operator.add accumulated EXACTLY ONCE per tick (no invoke double-fire): one stream
    # pass per tick, and the ledger grew by exactly one entry per tick.
    assert g.stream_calls == 3
    assert final["ledger"] == ["e1", "e2", "e3"]
    assert len(final["ledger"]) == g.stream_calls        # once-per-tick, never doubled
    # prior-thread pruning attempted for each superseded thread (never the current/last one)
    assert saver.deleted == ["run-t0", "run-t1"]


def test_run_driver_prune_is_best_effort_when_no_delete_thread():
    # a checkpointer lacking delete_thread must not crash the loop (fail-safe), and the
    # once-per-tick accumulation is unchanged.
    class _NoDelete:
        pass
    g = _AccumGraph(_NoDelete(), goal_at=2)
    final = run_driver(g, "run", max_iters=10, max_pivots=10, k_dry=10)
    assert final["tick_i"] == 2 and final["ledger"] == ["e1", "e2"]
    assert _thread_ids(g) == ["run-t0", "run-t1"]


# =========================================================================== #
# 4. correlate — Port_5762_State -> BACKDOOR_5762 direct unit
# =========================================================================== #
def test_correlate_5762_yields_backdoor_kind_with_source_target():
    ev = SensorEv(source_id="web_5762_probe", metric="Port_5762_State",
                  value="ESTAB_PRESENT", band="danger", domain="command",
                  source="10.45.0.13")
    out = correlate({"evidence": [ev], "tick_i": 2})
    b = [i for i in out.get("incidents", []) if i.kind == "BACKDOOR_5762"]
    assert len(b) == 1, [i.kind for i in out.get("incidents", [])]
    assert b[0].target == "10.45.0.13"               # target = e.source (the peer IP)
    assert b[0].members == ["Port_5762_State"]


def test_correlate_non_5762_tripped_signal_is_not_backdoor():
    # a tripped (danger) NON-5762 metric must stay single-signal, never the dedicated
    # BACKDOOR_5762 kind (routing it to a uav_ue 5762 DROP would be a self-DoS).
    ev = SensorEv(source_id="rtt", metric="RTT_ms", band="critical", source="10.45.0.99")
    out = correlate({"evidence": [ev], "tick_i": 2})
    assert out.get("incidents"), "expected a single-signal incident for the tripped metric"
    assert all(i.kind != "BACKDOOR_5762" for i in out["incidents"])


# =========================================================================== #
# 5. parse_ss_peer — 4-column / 5-column forms + fail-closed
# =========================================================================== #
def test_parse_ss_peer_four_column_state_filtered():
    # `ss -H -tan state established` OMITS the State column: Recv-Q Send-Q local peer
    row = "0 0 10.45.0.2:5762 10.45.0.13:44321"
    assert parse_ss_peer(row, 5762) == "10.45.0.13"


def test_parse_ss_peer_five_column_state_present():
    # the 5-column form (State present) still yields the peer (last two tokens are addrs)
    row = "ESTAB 0 0 10.45.0.2:5762 10.45.0.13:44321"
    assert parse_ss_peer(row, 5762) == "10.45.0.13"


def test_parse_ss_peer_strips_ipv6_brackets():
    row = "0 0 [fd00::2]:5762 [fd00::13]:44321"
    assert parse_ss_peer(row, 5762) == "fd00::13"


def test_parse_ss_peer_fail_closed_on_malformed():
    assert parse_ss_peer("", 5762) == ""                      # empty
    assert parse_ss_peer("garbage", 5762) == ""               # no port token, no columns
    assert parse_ss_peer("only :5762 here", 5762) == ""       # <4 columns -> fail-closed
    assert parse_ss_peer("no port token at all here", 5762) == ""


# =========================================================================== #
# 6a. G-A — verify_routing scope expansion ('source' forbidden + condition scoping)
# =========================================================================== #
def test_gA_verify_routing_source_forbidden_and_decision_modules_green():
    from mdg.verify import verify_routing as VR
    # G-A widened FORBIDDEN_KEYS to include the opaque attribution/pivot selectors.
    assert {"source", "target", "target_kind", "enforce_at"} <= VR.FORBIDDEN_KEYS
    # and scanned the decision-relevant gates/nodes for control-flow branching on them.
    assert "gate.py" in VR.DECISION_MODULES and "select_policy.py" in VR.DECISION_MODULES
    # the real tree must be GREEN (no decision module branches on a forbidden key).
    rep = VR._check()
    assert rep.fails == [], rep.fails
    assert rep.checks > 0


def test_gA_verify_routing_condition_scope_data_vs_branch():
    # locks the scope-expansion mechanic: DATA carriage of a forbidden selector does NOT
    # false-positive, but using it in a control-flow CONDITION is caught.
    from mdg.verify import verify_routing as VR
    data_tree = ast.parse(
        "def f(a):\n"
        "    x = {'target': a.source}\n"                 # dict value = DATA
        "    return [i.enforce_at for i in a.items]\n"   # comprehension iterable = DATA
    )
    assert VR._condition_keys_in(data_tree) & VR.FORBIDDEN_KEYS == set()
    branch_tree = ast.parse(
        "def f(a):\n"
        "    if a.get('source'):\n"                      # branch CONDITION on 'source'
        "        return 1\n"
        "    return 0\n"
    )
    assert "source" in VR._condition_keys_in(branch_tree)


# =========================================================================== #
# 6b. G-C — mongo dedupe time-bucket re-emits the same remote in a later window
# =========================================================================== #
def test_gC_mongo_dedupe_rebuckets_across_time_window():
    q = queue.Queue()
    line = '{"id":22943,"attr":{"remote":"10.44.0.31:5000"}}'
    be = Backend(mode="mock", mock_table={"docker": line})
    clk = _FixedClock(1.0)
    c = MongoLogCollector(q, _kr(), _KID, backend=be, clock=clk, dedupe_window_s=60.0)
    c.tick_once()
    assert len(_drain(q)) == 1                 # bucket 0: first accept emitted
    c.tick_once()
    assert len(_drain(q)) == 0                 # same bucket: overlap-window dedupe suppresses
    clk.t = 61.0                               # advance past the dedupe window -> bucket 1
    c.tick_once()
    assert len(_drain(q)) == 1                 # re-emitted (a real repeated DB access, not masked)


# =========================================================================== #
# 6c. G-C — air_side band mapping (count -> band)
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
    # n == 0 -> idle baseline, no signal
    c0 = AirCommandTap(q, _kr(), _KID, backend=Backend(mode="mock", mock_table={"tcpdump": ""}),
                       clock=_FixedClock(1.0), netns_prefix=_NSPREFIX)
    assert c0.collect() == []


def test_gC_air_telemetry_tap_band_mapping():
    q = queue.Queue()
    # packets present -> Link_Heartbeat / normal
    c = AirTelemetryTap(q, _kr(), _KID, backend=Backend(mode="mock", mock_table={"tcpdump": "1 IP a > b"}),
                        clock=_FixedClock(1.0), netns_prefix=_NSPREFIX)
    o = c.collect()
    assert o[0]["metric"] == "Link_Heartbeat" and o[0]["band"] == "normal"
    # silent cross-tap -> Packet_Loss / warning (value 100)
    c0 = AirTelemetryTap(q, _kr(), _KID, backend=Backend(mode="mock", mock_table={"tcpdump": ""}),
                         clock=_FixedClock(1.0), netns_prefix=_NSPREFIX)
    o0 = c0.collect()
    assert o0[0]["metric"] == "Packet_Loss" and o0[0]["band"] == "warning" and o0[0]["value"] == 100


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
