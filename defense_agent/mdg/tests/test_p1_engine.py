"""test_p1_engine — P1 실행/관측 엔진 self-verify (독립 실행 가능).

포함: safe-exec R1/R2/R5 + reap 계약, 6개 collector 의 parse/emit + HMAC
서명, ingest 소비 게이트 (PS-2 HMAC/seq/ts drop), gRPC envelope 코덱 +
enqueue servicer, watchdog liveness + sensor_loss, ledger boot recovery.

실행: python mdg/tests/test_p1_engine.py (pytest / langgraph / grpcio 불필요).
"""
from __future__ import annotations

import os
import queue
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import struct  # noqa: E402
from mdg.collector.air_side import (AirCommandTap, AirTelemetryTap, _count_packets,  # noqa: E402
                                    _decode_flight_state, _x25_crc)
from mdg.collector.base import BaseCollector  # noqa: E402
from mdg.collector.ingest import Keyring, verify_envelope  # noqa: E402
from mdg.collector.mongo import MongoLogCollector, parse_mongo_line  # noqa: E402
from mdg.collector.network import (NetworkMetricCollector, counter_diff,  # noqa: E402
                                   parse_prometheus)
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
# safe-exec (R1 timeout, R2 setsid group, R5 secret-via-stdin, reap 계약)
# --------------------------------------------------------------------------- #
def _live_backend():
    return Backend(mode="local", allow_live=True)


def test_backend_runs_and_reads_stdin_secret():
    # R5: secret 은 argv 가 아니라 stdin 으로 도착. 전달 증명을 위해 그대로 echo.
    code = "import sys;sys.stdout.write('GOT:'+sys.stdin.read())"
    r = _live_backend().run(ExecRequest(argv=[sys.executable, "-c", code],
                                        stdin_secret="s3cr3t", timeout_s=15))
    assert r.code == 0 and "GOT:s3cr3t" in r.stdout


def test_backend_labels_child_env():
    # R3: 자식 프로세스는 scoped reap 탐색을 위해 DAH_DEF_LABEL=dah_def 를 상속한다.
    code = f"import os;print(os.environ.get('{safeexec.LABEL_ENV}'))"
    r = _live_backend().run(ExecRequest(argv=[sys.executable, "-c", code], timeout_s=15))
    assert r.stdout.strip() == safeexec.LABEL


def test_backend_timeout_is_hard():
    # R1: 데드라인을 넘긴 프로세스는 kill 되고 timeout 으로 보고된다.
    r = _live_backend().run(ExecRequest(argv=[sys.executable, "-c", "import time;time.sleep(30)"],
                                        timeout_s=1))
    assert r.code == 124 and r.note == "timeout"


def test_reap_labelled_is_safe_noop_when_none():
    # 멱등 (R6): labelled 대상이 없으면 reap 은 [] 를 반환하고 예외를 던지지 않는다.
    assert isinstance(safeexec.reap_labelled("no-such-label"), list)


def test_backend_dry_run_is_operator_go_reserved():
    # operator-go 유보: allow_live 없는 local backend 는 절대 actuate 하지 않는다.
    be = Backend(allow_live=False, mode="local")
    r = be.run(ExecRequest(argv=["tcpdump", "-i", "eth0"]))
    assert r.dry_run and r.ok and "operator-go" in r.note


def test_backend_mock_table():
    be = Backend(mode="mock", mock_table={"tcpdump": "line1 IP a > b\nline2 IP c > d"})
    r = be.run(ExecRequest(argv=["ip", "netns", "exec", "x", "tcpdump", "-i", "eth0"]))
    assert not r.dry_run and _count_packets(r.stdout) == 2


# --------------------------------------------------------------------------- #
# collector — parse 헬퍼
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
    assert counter_diff(None, 5) is None          # 베이스라인
    assert counter_diff(5, 8) == 3                 # 양의 신호
    assert counter_diff(8, 2) is None              # reset -> reseed, 신호 아님


def test_parse_mongo_line_ran_only():
    accepted_ran = '{"c":"NETWORK","id":22943,"msg":"Connection accepted","attr":{"remote":"10.44.0.31:59948","connectionCount":3}}'
    accepted_sgi = '{"id":22943,"attr":{"remote":"172.30.0.5:40001"}}'
    ended = '{"id":22944,"attr":{"remote":"10.44.0.31:59948"}}'
    assert parse_mongo_line(accepted_ran)["metric"] == "DB_Access"
    assert parse_mongo_line(accepted_sgi) is None      # sgi 측은 플래그되지 않음
    assert parse_mongo_line(ended) is None


# --------------------------------------------------------------------------- #
# collector — 소비 게이트를 통과하는 signed envelope 방출
# --------------------------------------------------------------------------- #
def _drain(q):
    out = []
    while True:
        try:
            out.append(q.get_nowait())
        except queue.Empty:
            break
    return out


_NSPREFIX = ["nsenter", "--target", "4242", "--net", "--"]   # recon 이 주입한 netns prefix


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
    # HMAC 존재 + 공유 keyring 으로 검증됨 (PS-2 producer 측).
    ok, reason = verify_envelope(env, _kr(), SeqWatermark())
    assert ok, reason


# --------------------------------------------------------------------------- #
# Phase 5 — 14560 tap 에서 MAVLink flight-state 디코드 (rel_alt / flight_mode)
# --------------------------------------------------------------------------- #
def _mav_v2_frame(msgid: int, payload: bytes, crc_extra: int, seq: int = 0) -> bytes:
    """CRC 정합 MAVLink v2 프레임을 조립 (magic 0xFD)."""
    hdr = bytes([0xFD, len(payload), 0, 0, seq, 1, 1,
                 msgid & 0xFF, (msgid >> 8) & 0xFF, (msgid >> 16) & 0xFF])
    crc = _x25_crc(hdr[1:] + payload, crc_extra)
    return hdr + payload + struct.pack("<H", crc)


def _tcpdump_hex(frames: bytes, leading_junk: bytes = b"") -> str:
    """바이트를 tcpdump -x 캡처로 렌더 (요약 줄 + hex-dump 줄). leading_junk 은
    스캐너가 sync 를 넘겨야 하는 IP/UDP 헤더를 대신한다."""
    raw = leading_junk + frames
    out = ["12:00:00.1 IP 10.45.0.4.14550 > 10.45.0.2.14560: UDP, length %d" % len(frames)]
    for off in range(0, len(raw), 16):
        chunk = raw[off:off + 16]
        words = " ".join(chunk[i:i + 2].hex() for i in range(0, len(chunk), 2))
        out.append("\t0x%04x:  %s" % (off, words))
    return "\n".join(out)


def _hb(custom_mode: int, mav_type: int = 2) -> bytes:                 # QUADROTOR
    return _mav_v2_frame(0, struct.pack("<IBBBBB", custom_mode, mav_type, 3, 0x81, 4, 3), 50)


def _gpi(rel_alt_mm: int) -> bytes:
    return _mav_v2_frame(33, struct.pack("<IiiiihhhH", 123, 100, 200, 40000, rel_alt_mm, 1, 2, 3, 45), 104)


def test_crc_matches_mavlink_reference():
    # "123456789" 에 대한 MAVLink CRC-16/MCRF4XX 체크값은 0x6F91 (extra byte = 마지막 문자).
    assert _x25_crc(b"12345678", ord("9")) == 0x6F91


def test_decode_flight_state_rel_alt_and_mode():
    # GUIDED @ 30 m, junk IP/UDP 헤더 뒤 — 디코더는 magic byte 에서 sync 해야 한다.
    st = _decode_flight_state(_tcpdump_hex(_hb(4) + _gpi(30000), leading_junk=b"\x45\x00" + b"\x00" * 26))
    assert st["rel_alt"] == 30.0 and st["flight_mode"] == "GUIDED"
    # LAND 는 그대로 디코드됨 (effect observer 가 S2 non-recovery 를 이에 기반해 판정).
    assert _decode_flight_state(_tcpdump_hex(_hb(9)))["flight_mode"] == "LAND"
    # hex 없음 / 유효 프레임 없음 -> {} (best-effort; link-health 경로는 그대로 유지).
    assert _decode_flight_state("") == {}
    assert _decode_flight_state("random noise no hex") == {}


def test_decode_rejects_non_mavlink_magic_bytes():
    # CRC 유효 프레임이 아닌 떠도는 0xFD 는 거부되어야 한다 (오디코드 금지).
    assert _decode_flight_state(_tcpdump_hex(b"\xFD\x09\x00\x00" + b"\x11" * 20)) == {}


def test_telemetry_tap_emits_rel_alt_and_flight_mode():
    q = queue.Queue()
    stdout = _tcpdump_hex(_hb(4) + _gpi(30000))
    be = Backend(mode="mock", mock_table={"tcpdump": stdout})
    c = AirTelemetryTap(q, _kr(), _KID, backend=be, clock=_clock([100.0] * 6),
                        netns_prefix=_NSPREFIX)
    c.tick_once()
    payloads = [e.payload for e in _drain(q)]
    metrics = {p["metric"]: p for p in payloads}
    # Link_Heartbeat (기존, band normal)는 새 flight-state 행들과 공존한다.
    assert "Link_Heartbeat" in metrics
    assert metrics["rel_alt"]["value"] == 30.0 and metrics["rel_alt"]["band"] == "normal"
    assert metrics["flight_mode"]["value"] == "GUIDED" and metrics["flight_mode"]["band"] == "normal"
    # 모두 communication / plaintext_mavlink_tap channel 을 타므로 _telemetry_rows 가 이들을 실어 나른다.
    for m in ("rel_alt", "flight_mode"):
        assert metrics[m]["domain"] == "communication"
        assert metrics[m]["channel"] == "plaintext_mavlink_tap"


def test_telemetry_rows_carries_flight_state():
    # viewer._telemetry_rows 는 channel/domain 에 대해 generic — rel_alt/flight_mode 가 노출됨을 확인.
    from mdg.viewer.app import _telemetry_rows

    class _Tick:
        evidence = [
            {"metric": "rel_alt", "value": 30.0, "band": "normal",
             "domain": "communication", "channel": "plaintext_mavlink_tap", "source_id": "air_telemetry_tap"},
            {"metric": "flight_mode", "value": "GUIDED", "band": "normal",
             "domain": "communication", "channel": "plaintext_mavlink_tap", "source_id": "air_telemetry_tap"},
            {"metric": "Unauthorized_Command", "value": 1, "band": "warning",
             "domain": "command", "channel": "plaintext_mavlink_tap", "source_id": "air_command_tap"},
        ]

    rows = _telemetry_rows(_Tick())
    got = {r["metric"]: r["value"] for r in rows}
    assert got.get("rel_alt") == 30.0 and got.get("flight_mode") == "GUIDED"
    assert "Unauthorized_Command" not in got               # command domain 은 필터링됨


def _hb_from(custom_mode: int, mav_type: int, sysid: int, compid: int) -> bytes:
    """명시적 sysid/compid 를 가진 HEARTBEAT v2 (공존 GCS heartbeat 모델링용)."""
    hdr = bytes([0xFD, 6, 0, 0, 0, sysid, compid, 0, 0, 0])   # msgid 0 = HEARTBEAT
    pl = struct.pack("<IBBBBB", custom_mode, mav_type, 3, 0x81, 4, 3)[:6]
    crc = _x25_crc(hdr[1:] + pl, 50)
    return hdr + pl + struct.pack("<H", crc)


def test_decode_ignores_gcs_heartbeat_and_keeps_vehicle_mode():
    # 테스트베드 GCS 는 HEARTBEAT sysid=255/compid=190/MAV_TYPE_GCS(6)를 방출. 윈도우 맨 뒤에
    # 놓이면 vehicle 의 LAND (autopilot sysid=1/compid=1)를 덮어써서는 안 된다. latest-wins 였다면
    # "MODE_0" 를 보고하여 S2 LAND 탐지를 무력화할 것이다.
    vehicle_land = _hb(9)                                    # sysid=1/compid=1 (autopilot), LAND
    gcs = _hb_from(0, 6, sysid=255, compid=190)             # MAV_TYPE_GCS, 윈도우 내 마지막
    st = _decode_flight_state(_tcpdump_hex(vehicle_land + gcs))
    assert st["flight_mode"] == "LAND"                       # GCS heartbeat 무시됨, vehicle 우선
    # GCS heartbeat 단독으로는 flight_mode 를 산출하지 않음 (non-autopilot 소스에서 디코드할 것 없음).
    assert "flight_mode" not in _decode_flight_state(_tcpdump_hex(gcs))
    # expect_sys 는 vehicle sysid 를 고정: sysid 불일치는 (compid=1 이라도) 거부된다.
    assert _decode_flight_state(_tcpdump_hex(_hb(4)), expect_sys=7) == {}


def test_telemetry_tap_snapshot_feeds_effect_observer():
    # Phase 5 배선: AirTelemetryTap.snapshot() 이 effect observer 의 signed_* 경로를 공급한다.
    from mdg.safe_exec.observer import make_effect_observer

    stdout = _tcpdump_hex(_hb(4) + _gpi(30000))              # GUIDED @ 30 m (복구됨)
    be = Backend(mode="mock", mock_table={"tcpdump": stdout})
    c = AirTelemetryTap(queue.Queue(), _kr(), _KID, backend=be, clock=_clock([100.0] * 6),
                        netns_prefix=_NSPREFIX)
    assert c.snapshot() == {}                                # 첫 디코드 전까지 비어 있음 (안전)
    c.tick_once()
    snap = c.snapshot()
    assert snap["rel_alt"] == 30.0 and snap["flight_mode"] == "GUIDED"
    # 이 라이브 snapshot 을 공급하면 signed_guided 가 CONFIRM 됨 (배선 전에는 영구 UNCONFIRMED 였음).
    obs = make_effect_observer(telemetry=c.snapshot)
    assert obs("signed_guided") is True


def test_network_collector_first_poll_baseline_then_signal():
    c = NetworkMetricCollector(queue.Queue(), _kr(), _KID, clock=_clock([1.0] * 10))
    # 결정론 텍스트 주입 (httpx 우회): _process_text 를 직접 구동
    t1 = c._process_text("smf", ["s5c_rx_deletesession"], "s5c_rx_deletesession 5\n")
    t2 = c._process_text("smf", ["s5c_rx_deletesession"], "s5c_rx_deletesession 9\n")
    assert t1 == []                                    # 베이스라인, 신호 없음
    assert t2 and t2[0]["value"] == 4 and t2[0]["band"] == "danger"


class _CountingBackend:
    """run() 이 호출된 적 있는지 기록 (collector inert = exec 없음 을 단언하기 위함)."""
    def __init__(self):
        self.calls = 0

    def run(self, req):
        self.calls += 1
        from mdg.safe_exec.backend import ExecResult
        return ExecResult(ok=True, code=0, stdout="1 IP a > b", dry_run=False)


def test_netns_prefix_builder_and_inert_collectors():
    from mdg.safe_exec.nsenter_helper import (build_netns_prefix_map, netns_prefix_for,
                                              resolve_netns_targets)
    # 순수 prefix 빌더: canonical nsenter --net --, 미해석 시 None
    assert netns_prefix_for(4242) == ["nsenter", "--target", "4242", "--net", "--"]
    assert netns_prefix_for(None) is None and netns_prefix_for(0) is None

    class _Docker:
        def inspect_pid(self, c):
            return {"gcs_proxy": 111, "uav_ue": 0}.get(c)   # uav_ue 미해석
    pidmap = resolve_netns_targets(_Docker(), ["gcs_proxy", "uav_ue", "web_backend"])
    assert pidmap == {"gcs_proxy": 111}                      # 0/누락은 생략됨 (fail-closed)
    assert resolve_netns_targets(None, ["x"]) == {}          # docker 없음 -> 빈 결과 (inert)
    prefmap = build_netns_prefix_map({"gcs_proxy": 111, "uav_ue": 0})
    assert prefmap == {"gcs_proxy": ["nsenter", "--target", "111", "--net", "--"]}

    # inert 가드: netns_prefix None => collect() 는 [] 반환하고 backend 를 절대 건드리지 않음
    for Coll, kwextra in ((AirCommandTap, {}), (AirTelemetryTap, {})):
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
    assert len(_drain(q)) == 1                          # 윈도우 내 중복 제거됨


def test_sign_log_parse_and_dedupe():
    from mdg.collector.sign_log import SignLogCollector, parse_signing_line
    # ANSI + emoji drop 줄 -> 파생 secret-free Signing_Drop payload (누적 투영)
    drop = "\x1b[31m[proxy] ⛔ 서명검증 실패 → SITL 차단 (누적 7)\x1b[0m"
    p = parse_signing_line(drop)
    assert p is not None and p["metric"] == "Signing_Drop" and p["value"] == 7
    assert p["band"] == "normal" and p["channel"] == "uav_proxy_signlog"  # band=normal -> distrust 0
    # secret-free (PS-3): payload 는 파생된 닫힌 key-set 뿐; raw 줄 / peer tuple 없음
    assert set(p) == {"metric", "value", "band", "domain", "channel", "confidence", "source"}
    assert "누적" not in " ".join(str(v) for v in p.values())   # raw 로그 텍스트가 투영되지 않음
    # positive-only: banner / 무관 / null -> None (silence≠OFF, 절대 승격 안 함)
    assert parse_signing_line("[proxy] 🔒 MAVLink2 서명 강제 ON") is None
    assert parse_signing_line("[proxy] some unrelated line") is None
    assert parse_signing_line(None) is None and parse_signing_line("") is None
    # collector: dedupe 윈도우 내 누적당 한 번 방출
    q = queue.Queue()
    be = Backend(mode="mock", mock_table={"docker": drop + "\n" + drop})
    c = SignLogCollector(q, _kr(), _KID, backend=be, clock=_clock([1.0] * 4))
    c.tick_once()
    envs = _drain(q)
    assert len(envs) == 1 and envs[0].payload["value"] == 7


def test_sign_log_inert_without_backend():
    from mdg.collector.sign_log import SignLogCollector
    # backend 미배선 -> _observe 가 None 반환 -> 방출 없음 (fail-safe: signing 은 UNKNOWN 유지)
    c = SignLogCollector(queue.Queue(), _kr(), _KID, backend=None, clock=_clock([1.0] * 3))
    assert c.collect() == []


def test_mission_collector_edge_triggered():
    q = queue.Queue()
    prof = {"mission_type": "Recon", "mission_phase": "En-route", "mission_priority": "High",
            "config_version": "v"}
    c = MissionConfigCollector(q, _kr(), _KID, clock=_clock([1.0] * 5), profile=prof, refresh_every=100)
    c.tick_once(); first = _drain(q)
    c.tick_once(); second = _drain(q)
    assert len(first) == 1 and len(second) == 0        # 변경 시 방출, 이후 침묵


# --------------------------------------------------------------------------- #
# ingest — codec, servicer, PS-2 소비 게이트
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

    replay = _signed_env(seq=1, ts=100.0)              # seq 이미 수용됨
    ok3, reason3, _ = v.verify(replay)
    assert not ok3 and "replay" in reason3

    skew = _signed_env(seq=3, ts=100.0)
    vskew = IngestVerifier(kr, SeqWatermark(), clock=_clock([1000.0]))  # 900s 차이, > ±5s
    ok4, reason4, ev4 = vskew.verify(skew)
    assert not ok4 and ev4.tamper and "skew" in reason4


def test_ingest_verifier_drops_unknown_kid_and_empty_hmac():
    # 미인증 경로는 HMAC-mismatch 와 구별됨: (1) keyring 에 kid 부재,
    # (2) 빈/부재 HMAC. 둘 다 tamper 를 세운 채 fail-closed 되어 하류
    # provenance 게이트가 이들을 배제한다. clock 은 조회되지 않음 (HMAC 가 먼저 거부).
    kr, seqwm = _kr(), SeqWatermark()
    v = IngestVerifier(kr, seqwm, clock=_clock([100.0, 100.0]))

    # (1) keyring 에 없는 kid -> keyring.get(kid) 가 None -> 'unknown kid', tamper=True
    unk = _signed_env(seq=10, ts=100.0)
    unk.kid = "kid-does-not-exist"
    ok, reason, ev = v.verify(unk)
    assert not ok and ev.tamper and not ev.verified and "unknown kid" in reason

    # (2) 빈 HMAC -> compare_digest(expected, '') False -> 'hmac mismatch', tamper=True
    noh = _signed_env(seq=11, ts=100.0)
    noh.hmac = ""
    ok2, reason2, ev2 = v.verify(noh)
    assert not ok2 and ev2.tamper and not ev2.verified and "hmac" in reason2


# --------------------------------------------------------------------------- #
# watchdog + ledger 부팅 복구
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
    dead = _FakeCollector("dead", hb=10.0)             # now=100 에서 90s 침묵
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
    """collect() 가 예외를 던지는 사이클은 heartbeat 를 갱신해서는 안 된다 (수정: 오류를 내는
    collector 는 건강하고 조용한 collector 와 구별 가능해야 함); 조용한 tick 은 여전히 beat 한다."""
    state = {"n": 0}

    class _Flaky(BaseCollector):
        source_id = "flaky"

        def collect(self):
            state["n"] += 1
            if state["n"] == 1:
                return []                                  # 건강한 조용한 tick
            raise RuntimeError("sensor down")

    c = _Flaky(queue.Queue(), _kr(), _KID, clock=_clock([100.0, 100.0]))
    assert c.tick_once() == 0 and c.heartbeat() == 100.0   # 조용한 성공은 beat
    raised = False
    try:
        c.tick_once()                                      # 예외 발생; heartbeat 는 보류되어야 함
    except RuntimeError:
        raised = True
    assert raised and c.heartbeat() == 100.0               # 여전히 100 — 오류 시 전진하지 않음


def test_quiet_collector_keeps_beating():
    """회귀: 이 수정은 건강하지만 조용한 collector 를 굶겨서는 안 된다 — 예외를 던지지 않는
    모든 tick(빈 것 포함)은 heartbeat 를 갱신한다."""

    class _Quiet(BaseCollector):
        source_id = "quiet"

        def collect(self):
            return []

    c = _Quiet(queue.Queue(), _kr(), _KID, clock=_clock([100.0, 200.0]))
    c.tick_once()
    assert c.heartbeat() == 100.0
    c.tick_once()
    assert c.heartbeat() == 200.0                          # 빈 tick 도 여전히 beat


def test_watchdog_marks_erroring_collector_dead():
    """엔드투엔드: 건강하게 시작한 뒤 오류를 내는 collector 는 stale 되어, watchdog 가
    이를 dead 로 표시하고 signed sensor_loss 를 방출한다 (수정의 의도)."""
    state = {"n": 0}

    class _DiesAfterOne(BaseCollector):
        source_id = "flaky"

        def collect(self):
            state["n"] += 1
            if state["n"] == 1:
                return []
            raise RuntimeError("down")

    c = _DiesAfterOne(queue.Queue(), _kr(), _KID, clock=_clock([100.0, 100.0]), name="flaky")
    c.tick_once()                                          # hb = 100 (건강)
    try:
        c.tick_once()                                      # 오류 -> hb 보류
    except RuntimeError:
        pass
    assert c.heartbeat() == 100.0

    q = queue.Queue()
    w = Watchdog([c], clock=_clock([200.0, 200.0]), inbox=q, keyring=_kr(), kid=_KID,
                 max_silence_s=10.0)
    status = w.check_once()                                # now=200, hb=100 -> 100s > 10 -> dead 판정
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
    seqwm.accept("net_metric", 7)                      # HWM=7 영속
    # crash+reboot 시뮬레이션: 새 객체가 상태를 재로드
    led2 = IntentLedger(lpath)
    seqwm2 = SeqWatermark(path=spath)
    be = Backend(mode="mock")                          # mock 에서 teardown -> []
    summary = boot_recover(led2, seqwm2, backend=be)
    assert seqwm2.hwm.get("net_metric") == 7           # drain 전에 HWM 재로드됨
    assert seqwm2.accept("net_metric", 7) is False     # boot 후에도 replay 는 닫힌 상태 유지
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
