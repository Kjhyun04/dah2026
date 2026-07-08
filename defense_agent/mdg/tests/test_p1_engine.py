"""test_p1_engine — P1 execution/observation engine self-verify (runnable standalone).

Covers: safe-exec R1/R2/R5 + reap contract, the 6 collectors' parse/emit + HMAC
signing, ingest consumption gate (PS-2 HMAC/seq/ts drop), gRPC envelope codec +
enqueue servicer, watchdog liveness + sensor_loss, ledger boot recovery.

Run: ``python mdg/tests/test_p1_engine.py`` (no pytest / langgraph / grpcio needed).
"""
from __future__ import annotations

import os
import queue
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.collector.air_side import (AirCommandTap, AirTelemetryTap, _count_packets)  # noqa: E402
from mdg.collector.base import BaseCollector  # noqa: E402
from mdg.collector.ingest import Keyring, verify_envelope  # noqa: E402
from mdg.collector.mongo import MongoLogCollector, parse_mongo_line  # noqa: E402
from mdg.collector.network import (NetworkMetricCollector, counter_diff,  # noqa: E402
                                   parse_prometheus)
from mdg.collector.web import WebProbeCollector, parse_ss_established  # noqa: E402
from mdg.collector.mission import MissionConfigCollector  # noqa: E402
from mdg.core.clock import VirtualClock  # noqa: E402
from mdg.ingest.server import EnqueueServicer, decode_envelope, encode_envelope  # noqa: E402
from mdg.ingest.verify import IngestVerifier  # noqa: E402
from mdg.ledger.intent_ledger import IntentLedger, SeqWatermark, boot_recover  # noqa: E402
from mdg.safe_exec import safeexec  # noqa: E402
from mdg.safe_exec.backend import Backend, ExecRequest  # noqa: E402
from mdg.watchdog import Watchdog  # noqa: E402

_KID = "kid-2026"
_KEY = b"unit-test-hmac-key-32-bytes-long!"


def _kr() -> Keyring:
    return Keyring(keys={_KID: _KEY})


def _clock(vals):
    return VirtualClock(ts_stream=list(vals))


# --------------------------------------------------------------------------- #
# safe-exec (R1 timeout, R2 setsid group, R5 secret-via-stdin, reap contract)
# --------------------------------------------------------------------------- #
def _live_backend():
    return Backend(mode="local", allow_live=True)


def test_backend_runs_and_reads_stdin_secret():
    # R5: secret arrives on stdin, never argv. Echo it back to prove delivery.
    code = "import sys;sys.stdout.write('GOT:'+sys.stdin.read())"
    r = _live_backend().run(ExecRequest(argv=[sys.executable, "-c", code],
                                        stdin_secret="s3cr3t", timeout_s=15))
    assert r.code == 0 and "GOT:s3cr3t" in r.stdout


def test_backend_labels_child_env():
    # R3: the child inherits DAH_DEF_LABEL=dah_def for scoped reap discovery.
    code = f"import os;print(os.environ.get('{safeexec.LABEL_ENV}'))"
    r = _live_backend().run(ExecRequest(argv=[sys.executable, "-c", code], timeout_s=15))
    assert r.stdout.strip() == safeexec.LABEL


def test_backend_timeout_is_hard():
    # R1: a process that outlives the deadline is killed and reported as timeout.
    r = _live_backend().run(ExecRequest(argv=[sys.executable, "-c", "import time;time.sleep(30)"],
                                        timeout_s=1))
    assert r.code == 124 and r.note == "timeout"


def test_reap_labelled_is_safe_noop_when_none():
    # Idempotent (R6): reaping with nothing labelled returns [] and never raises.
    assert isinstance(safeexec.reap_labelled("no-such-label"), list)


def test_backend_dry_run_is_operator_go_reserved():
    # operator-go 유보: local backend without allow_live never actuates.
    be = Backend(allow_live=False, mode="local")
    r = be.run(ExecRequest(argv=["tcpdump", "-i", "eth0"]))
    assert r.dry_run and r.ok and "operator-go" in r.note


def test_backend_mock_table():
    be = Backend(mode="mock", mock_table={"tcpdump": "line1 IP a > b\nline2 IP c > d"})
    r = be.run(ExecRequest(argv=["ip", "netns", "exec", "x", "tcpdump", "-i", "eth0"]))
    assert not r.dry_run and _count_packets(r.stdout) == 2


# --------------------------------------------------------------------------- #
# collectors — parse helpers
# --------------------------------------------------------------------------- #
def test_parse_prometheus_sums_labelsets():
    text = (
        "# HELP x\n# TYPE x counter\n"
        'gtp_node_s5c_rx_deletesession{addr="10.50.0.3"} 8\n'
        "s5c_rx_deletesession 8\n"
        "pfcp_sessions_active -8\n"
    )
    p = parse_prometheus(text)
    assert p["s5c_rx_deletesession"] == 8.0
    assert p["pfcp_sessions_active"] == -8.0


def test_counter_diff_semantics():
    assert counter_diff(None, 5) is None          # baseline
    assert counter_diff(5, 8) == 3                 # positive signal
    assert counter_diff(8, 2) is None              # reset -> reseed, not signal


def test_parse_ss_established():
    out = "ESTAB 0 0 172.30.0.10:5762 10.45.0.10:44012\n"
    assert parse_ss_established(out, 5762) == 1
    assert parse_ss_established("", 5762) == 0


def test_parse_mongo_line_ran_only():
    accepted_ran = '{"c":"NETWORK","id":22943,"msg":"Connection accepted","attr":{"remote":"10.44.0.31:59948","connectionCount":3}}'
    accepted_sgi = '{"id":22943,"attr":{"remote":"172.30.0.5:40001"}}'
    ended = '{"id":22944,"attr":{"remote":"10.44.0.31:59948"}}'
    assert parse_mongo_line(accepted_ran)["metric"] == "DB_Access"
    assert parse_mongo_line(accepted_sgi) is None      # sgi side not flagged
    assert parse_mongo_line(ended) is None


# --------------------------------------------------------------------------- #
# collectors — emit signed envelopes that pass the consumption gate
# --------------------------------------------------------------------------- #
def _drain(q):
    out = []
    while True:
        try:
            out.append(q.get_nowait())
        except queue.Empty:
            break
    return out


_NSPREFIX = ["nsenter", "--target", "4242", "--net", "--"]   # recon-injected netns prefix


def test_air_command_tap_emits_signed_signal():
    q = queue.Queue()
    be = Backend(mode="mock", mock_table={"tcpdump": "1 IP a > b\n2 IP c > d\n3 IP e > f"})
    c = AirCommandTap(q, _kr(), _KID, backend=be, clock=_clock([100.0] * 5),
                      netns_prefix=_NSPREFIX)
    n = c.tick_once()
    envs = _drain(q)
    assert n == 1 and len(envs) == 1
    env = envs[0]
    assert env.payload["metric"] == "Unauthorized_Command" and env.payload["value"] == 3
    # HMAC present + verifies with the shared keyring (PS-2 producer side).
    ok, reason = verify_envelope(env, _kr(), SeqWatermark())
    assert ok, reason


def test_network_collector_first_poll_baseline_then_signal():
    c = NetworkMetricCollector(queue.Queue(), _kr(), _KID, clock=_clock([1.0] * 10))
    # inject deterministic texts (bypass httpx): drive _process_text directly
    t1 = c._process_text("smf", ["s5c_rx_deletesession"], "s5c_rx_deletesession 5\n")
    t2 = c._process_text("smf", ["s5c_rx_deletesession"], "s5c_rx_deletesession 9\n")
    assert t1 == []                                    # baseline, no signal
    assert t2 and t2[0]["value"] == 4 and t2[0]["band"] == "danger"


def test_web_probe_pool1_and_estab_signal():
    q = queue.Queue()
    be = Backend(mode="mock", mock_table={"ss": "ESTAB 0 0 172.30.0.10:5762 10.45.0.10:5000\n"})
    c = WebProbeCollector(q, _kr(), _KID, backend=be, clock=_clock([5.0] * 3),
                          netns_prefix=_NSPREFIX)
    c.tick_once()
    envs = _drain(q)
    assert len(envs) == 1 and envs[0].payload["value"] == "ESTAB_PRESENT"


class _CountingBackend:
    """Records whether run() was ever called (to assert collector inert = no exec)."""
    def __init__(self):
        self.calls = 0

    def run(self, req):
        self.calls += 1
        from mdg.safe_exec.backend import ExecResult
        return ExecResult(ok=True, code=0, stdout="1 IP a > b", dry_run=False)


def test_netns_prefix_builder_and_inert_collectors():
    from mdg.safe_exec.nsenter_helper import (build_netns_prefix_map, netns_prefix_for,
                                              resolve_netns_targets)
    # pure prefix builder: canonical nsenter --net --, None when unresolved
    assert netns_prefix_for(4242) == ["nsenter", "--target", "4242", "--net", "--"]
    assert netns_prefix_for(None) is None and netns_prefix_for(0) is None

    class _Docker:
        def inspect_pid(self, c):
            return {"gcs_proxy": 111, "uav_ue": 0}.get(c)   # uav_ue unresolved
    pidmap = resolve_netns_targets(_Docker(), ["gcs_proxy", "uav_ue", "web_backend"])
    assert pidmap == {"gcs_proxy": 111}                      # 0/missing omitted (fail-closed)
    assert resolve_netns_targets(None, ["x"]) == {}          # no docker -> empty (inert)
    prefmap = build_netns_prefix_map({"gcs_proxy": 111, "uav_ue": 0})
    assert prefmap == {"gcs_proxy": ["nsenter", "--target", "111", "--net", "--"]}

    # inert guard: netns_prefix None => collect() returns [] and NEVER touches backend
    for Coll, kwextra in ((AirCommandTap, {}), (AirTelemetryTap, {}), (WebProbeCollector, {})):
        be = _CountingBackend()
        c = Coll(queue.Queue(), _kr(), _KID, backend=be, clock=_clock([1.0] * 3),
                 netns_prefix=None, **kwextra)
        assert c.collect() == [] and be.calls == 0


def test_mongo_collector_dedupe():
    q = queue.Queue()
    line = '{"id":22943,"attr":{"remote":"10.44.0.31:5000"}}'
    be = Backend(mode="mock", mock_table={"docker": line + "\n" + line})
    c = MongoLogCollector(q, _kr(), _KID, backend=be, clock=_clock([1.0] * 3))
    c.tick_once()
    assert len(_drain(q)) == 1                          # deduped within window


def test_mission_collector_edge_triggered():
    q = queue.Queue()
    prof = {"mission_type": "Recon", "mission_phase": "En-route", "mission_priority": "High",
            "config_version": "v"}
    c = MissionConfigCollector(q, _kr(), _KID, clock=_clock([1.0] * 5), profile=prof, refresh_every=100)
    c.tick_once(); first = _drain(q)
    c.tick_once(); second = _drain(q)
    assert len(first) == 1 and len(second) == 0        # emits on change, silent after


# --------------------------------------------------------------------------- #
# ingest — codec, servicer, PS-2 consumption gate
# --------------------------------------------------------------------------- #
def _signed_env(seq=1, ts=100.0):
    from mdg.collector.ingest import SensorEnvelope, compute_hmac
    env = SensorEnvelope(payload={"metric": "PFCP_Delete_Attempt", "value": 3, "band": "danger"},
                         source_id="net_metric", kid=_KID, seq=seq, ts=ts, nonce="abc")
    env.hmac = compute_hmac(env, _KEY)
    return env


def test_grpc_codec_roundtrip_and_servicer():
    env = _signed_env()
    data = encode_envelope(env)
    back = decode_envelope(data)
    assert back.hmac == env.hmac and back.seq == env.seq
    q = queue.Queue()
    s = EnqueueServicer(q)
    assert s.submit(data) == b'{"ok":true}' and s.accepted == 1
    assert s.submit(b"not-json") == b'{"ok":false}' and s.rejected == 1


def test_ingest_verifier_accepts_good_drops_forgery_replay_skew():
    kr, seqwm = _kr(), SeqWatermark()
    v = IngestVerifier(kr, seqwm, clock=_clock([100.0, 100.0, 100.0, 100.0, 100.0]))
    good = _signed_env(seq=1, ts=100.0)
    ok, reason, ev = v.verify(good)
    assert ok and ev.verified and not ev.tamper

    forged = _signed_env(seq=2, ts=100.0)
    forged.hmac = "deadbeef"
    ok2, reason2, ev2 = v.verify(forged)
    assert not ok2 and ev2.tamper and "hmac" in reason2

    replay = _signed_env(seq=1, ts=100.0)              # seq already accepted
    ok3, reason3, _ = v.verify(replay)
    assert not ok3 and "replay" in reason3

    skew = _signed_env(seq=3, ts=100.0)
    vskew = IngestVerifier(kr, SeqWatermark(), clock=_clock([1000.0]))  # 900s off, > ±5s
    ok4, reason4, ev4 = vskew.verify(skew)
    assert not ok4 and ev4.tamper and "skew" in reason4


def test_ingest_verifier_drops_unknown_kid_and_empty_hmac():
    # 미인증 paths distinct from HMAC-mismatch: (1) kid absent from keyring and
    # (2) empty/absent HMAC. Both must fail-closed with tamper set so the downstream
    # provenance gate excludes them. Clock is never consulted (HMAC rejects first).
    kr, seqwm = _kr(), SeqWatermark()
    v = IngestVerifier(kr, seqwm, clock=_clock([100.0, 100.0]))

    # (1) kid not in keyring -> keyring.get(kid) is None -> 'unknown kid', tamper=True
    unk = _signed_env(seq=10, ts=100.0)
    unk.kid = "kid-does-not-exist"
    ok, reason, ev = v.verify(unk)
    assert not ok and ev.tamper and not ev.verified and "unknown kid" in reason

    # (2) empty HMAC -> compare_digest(expected, '') False -> 'hmac mismatch', tamper=True
    noh = _signed_env(seq=11, ts=100.0)
    noh.hmac = ""
    ok2, reason2, ev2 = v.verify(noh)
    assert not ok2 and ev2.tamper and not ev2.verified and "hmac" in reason2


# --------------------------------------------------------------------------- #
# watchdog + ledger boot recovery
# --------------------------------------------------------------------------- #
class _FakeCollector:
    def __init__(self, name, hb):
        self.name = name
        self.source_id = name
        self._hb = hb
        self.started = False

    def heartbeat(self):
        return self._hb

    def start(self):
        self.started = True


def test_watchdog_flags_silence_and_emits_sensor_loss():
    q = queue.Queue()
    alive = _FakeCollector("live", hb=95.0)
    dead = _FakeCollector("dead", hb=10.0)             # 90s silent at now=100
    w = Watchdog([alive, dead], clock=_clock([100.0, 100.0]), inbox=q,
                 keyring=_kr(), kid=_KID, max_silence_s=10.0)
    status = w.check_once()
    assert status["live"] is True and status["dead"] is False
    envs = _drain(q)
    assert len(envs) == 1 and envs[0].payload["metric"] == "sensor_loss"
    assert envs[0].payload["value"] == "dead"


def test_watchdog_restart_factory():
    replaced = {}

    def factory(old):
        fresh = _FakeCollector(old.name, hb=200.0)
        replaced["x"] = fresh
        return fresh

    dead = _FakeCollector("d", hb=1.0)
    w = Watchdog([dead], clock=_clock([100.0]), max_silence_s=5.0,
                 restart=True, restart_factory=factory)
    w.check_once()
    assert replaced["x"].started is True


def test_collector_heartbeat_withheld_on_error():
    """A cycle whose collect() RAISES must NOT refresh the heartbeat (fix: an erroring
    collector must be distinguishable from a healthy quiet one); a quiet tick still beats."""
    state = {"n": 0}

    class _Flaky(BaseCollector):
        source_id = "flaky"

        def collect(self):
            state["n"] += 1
            if state["n"] == 1:
                return []                                  # healthy quiet tick
            raise RuntimeError("sensor down")

    c = _Flaky(queue.Queue(), _kr(), _KID, clock=_clock([100.0, 100.0]))
    assert c.tick_once() == 0 and c.heartbeat() == 100.0   # quiet success beats
    raised = False
    try:
        c.tick_once()                                      # raises; heartbeat must be withheld
    except RuntimeError:
        raised = True
    assert raised and c.heartbeat() == 100.0               # still 100 — NOT advanced on error


def test_quiet_collector_keeps_beating():
    """Regression: the fix must NOT starve a healthy-but-silent collector — every
    non-raising tick (including an empty one) refreshes the heartbeat."""

    class _Quiet(BaseCollector):
        source_id = "quiet"

        def collect(self):
            return []

    c = _Quiet(queue.Queue(), _kr(), _KID, clock=_clock([100.0, 200.0]))
    c.tick_once()
    assert c.heartbeat() == 100.0
    c.tick_once()
    assert c.heartbeat() == 200.0                          # empty tick still beats


def test_watchdog_marks_erroring_collector_dead():
    """End-to-end: a collector that errors after a healthy start goes stale, so the
    watchdog flags it dead and emits a signed sensor_loss (the fix's intent)."""
    state = {"n": 0}

    class _DiesAfterOne(BaseCollector):
        source_id = "flaky"

        def collect(self):
            state["n"] += 1
            if state["n"] == 1:
                return []
            raise RuntimeError("down")

    c = _DiesAfterOne(queue.Queue(), _kr(), _KID, clock=_clock([100.0, 100.0]), name="flaky")
    c.tick_once()                                          # hb = 100 (healthy)
    try:
        c.tick_once()                                      # error -> hb withheld
    except RuntimeError:
        pass
    assert c.heartbeat() == 100.0

    q = queue.Queue()
    w = Watchdog([c], clock=_clock([200.0, 200.0]), inbox=q, keyring=_kr(), kid=_KID,
                 max_silence_s=10.0)
    status = w.check_once()                                # now=200, hb=100 -> 100s > 10 -> dead
    assert status["flaky"] is False
    envs = _drain(q)
    assert len(envs) == 1 and envs[0].payload["metric"] == "sensor_loss"
    assert envs[0].payload["value"] == "flaky"


def test_ledger_boot_recover_order(tmp_path=None):
    import tempfile
    d = tempfile.mkdtemp()
    lpath = os.path.join(d, "intents.jsonl")
    spath = os.path.join(d, "seq.json")
    from mdg.core.state import Intent
    led = IntentLedger(lpath)
    led.record_intent(Intent(rule="pfcp_firewall", revert_cmd="undo", ts=1.0))
    seqwm = SeqWatermark(path=spath)
    seqwm.accept("net_metric", 7)                      # persists HWM=7
    # simulate crash+reboot: fresh objects reload state
    led2 = IntentLedger(lpath)
    seqwm2 = SeqWatermark(path=spath)
    be = Backend(mode="mock")                          # teardown -> [] in mock
    summary = boot_recover(led2, seqwm2, backend=be)
    assert seqwm2.hwm.get("net_metric") == 7           # HWM reloaded BEFORE drain
    assert seqwm2.accept("net_metric", 7) is False     # replay stays closed post-boot
    assert "pfcp_firewall" in summary["reverted"]


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
            import traceback
            print(f"[ERROR] {fn.__name__}: {e!r}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
