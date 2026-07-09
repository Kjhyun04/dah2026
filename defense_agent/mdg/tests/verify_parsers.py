"""verify_parsers — EPC/메트릭/관측 파서 세트를 위한 GATE2 verify 스크립트
(DESIGN_DECISIONS appendix A ``verify_parsers``; P4-1/P4-2/P4-5).

모든 parse 함수를 ANSI 색상 픽스처(라이브 EPC 로그는 색상 이스케이프됨 — strip 을
건너뛰는 파서는 조용히 아무것도 매치 못함) 및 null-safe 케이스(None/"" 는 예외 금지) 에
대해 행사한다. 의존성 0 으로 단독 실행 가능:

    python mdg/tests/verify_parsers.py      # -> 파서별 [PASS]/[FAIL], 실패 시 exit 1

커버되는 파서 세트 — 12개의 순수(PURE, 픽스처 테스트 가능, 라이브 백엔드 불요) 디코드 함수
(finding P2-2 / P2-4):
  log_common.ansi_strip / parse_epc_ts        (공통 EPC strip + ts, null-safe)     [2]
  smf_session.parse_smf_line                  (P4-1 SMF create/remove, ANSI, CIDR 스코프, null-safe) [1]
  mme_log.parse_mme_line                      (P4-5 MME attach/IMSI, ANSI, null-safe) [1]
  mongo.parse_mongo_line                      (A-2 id==22943 JSON, RAN-CIDR 스코프, null-safe) [1]
  network.parse_prometheus / counter_diff     (P4-2/P4-3 exposition 합산, 양의 diff 만) [2]
  web.parse_ss_established                     (5762 ESTAB 카운트)                     [1]
  air_side._count_packets                     (B-3/B-4 tcpdump HEARTBEAT/패킷 카운트 디코드, null-safe) [1]
  resolve.parse_ip_addr_show                  (2단계 tun IPv4)                      [1]
  ingest.encode_envelope / decode_envelope    (엔벨로프 코덱 왕복, 크기 가드) [2]
                                              -----------------------------------------
                                              = 순수 디코드 함수 12개, 모두 여기서 행사.

'19 파서' 목표 조정(finding P2-4 — 미조정 상태였음): 설계의 19 는 이 12개 순수 디코드 함수에
``*.collect()`` 메서드에 내장된 7개의 라이브 collector band 분류기(air_command / air_telemetry
/ network / web / mongo / mme / smf collector) 를 더한 것 — 이들은 subprocess/backend 구동
(nsenter+tcpdump / ss / docker-logs / :9090 scrape) 이며 통합 스위트(test_p4_*, verify_d11_*) 가
커버하고 여기서는 커버하지 않는다. 라이브/mock Backend 없이 실행 불가하기 때문이다. 이 파일의
계약은 12개 순수 함수; 12(순수, 여기) + 7(라이브, 통합) = 19. 파서가 추가/제거되면 이 분리를
DESIGN_DECISIONS appendix A 와 동기화하라.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.collector.air_side import _count_packets  # noqa: E402
from mdg.collector.ingest import SensorEnvelope  # noqa: E402
from mdg.collector.log_common import ansi_strip, parse_epc_ts  # noqa: E402
from mdg.collector.mme_log import parse_mme_line  # noqa: E402
from mdg.collector.mongo import parse_mongo_line  # noqa: E402
from mdg.collector.network import counter_diff, parse_prometheus  # noqa: E402
from mdg.collector.smf_session import parse_smf_line  # noqa: E402
from mdg.collector.web import parse_ss_established  # noqa: E402
from mdg.ingest.server import decode_envelope, encode_envelope  # noqa: E402
from mdg.targets.resolve import parse_ip_addr_show  # noqa: E402

# --------------------------------------------------------------------------- #
# ANSI 색상 픽스처(페이로드 토큰 주위의 Open5GS SGR 이스케이프)
# --------------------------------------------------------------------------- #
_ANSI = "\x1b[1;32m"
_RST = "\x1b[0m"
_SMF_CREATE = f"{_ANSI}07/07 03:39:36.461: [smf] INFO: UE IMSI[001010000000001] IPv4[10.45.0.2]{_RST}"
_SMF_REMOVE = f"{_ANSI}07/07 03:41:10.002: [smf] INFO: Removed Session: UE IMSI:[imsi-001010000000001] APN[internet] IPv4:[10.45.0.2]{_RST}"
_MME_ATTACH = f"{_ANSI}07/07 03:39:30.101: [mme] INFO: Attach request from UE IMSI[001010000000002]{_RST}"
_MME_ATTACH_NAI = f"{_ANSI}07/07 03:39:31.500: [emm] INFO: Attach complete IMSI[imsi-001010000000001]{_RST}"


# --------------------------------------------------------------------------- #
# log_common: ansi_strip + parse_epc_ts (null-safe)
# --------------------------------------------------------------------------- #
def test_ansi_strip():
    assert "\x1b[" in _SMF_CREATE and "\x1b[" not in ansi_strip(_SMF_CREATE)
    assert ansi_strip("") == "" and ansi_strip(None) is None      # null-safe 통과


def test_parse_epc_ts_and_null_safe():
    assert parse_epc_ts(ansi_strip(_SMF_CREATE)) == "07/07 03:39:36.461"
    assert parse_epc_ts("no timestamp here") == ""
    assert parse_epc_ts("") == "" and parse_epc_ts(None) == ""     # null-safe: re.search(None) 없음


# --------------------------------------------------------------------------- #
# smf_session.parse_smf_line (P4-1) — ANSI, create/remove, CIDR 스코프, null-safe
# --------------------------------------------------------------------------- #
def test_parse_smf_line_ansi_create_remove():
    ev = parse_smf_line(_SMF_CREATE)
    assert ev and ev.op == "add" and ev.imsi == "001010000000001" and ev.ip == "10.45.0.2"
    assert ev.ts == "07/07 03:39:36.461"
    rem = parse_smf_line(_SMF_REMOVE)
    assert rem and rem.op == "remove" and rem.imsi == "001010000000001" and rem.ip == "10.45.0.2"


def test_parse_smf_line_cidr_scoped_and_null_safe():
    # 이식성 (P2-3): pool 밖 IP 는 기본 pool 하에서 무시되고, 일치하는 config
    # pool_cidr 하에서 매치됨 — 파서는 하드코딩 리터럴이 아닌 config 를 따름.
    other = _SMF_CREATE.replace("10.45.0.2", "10.99.0.7")
    assert parse_smf_line(other) is None
    assert parse_smf_line(other, pool_cidr="10.99.0.0/16").ip == "10.99.0.7"
    # null-safe + 노이즈
    assert parse_smf_line(None) is None and parse_smf_line("") is None
    assert parse_smf_line("07/07 03:39:36.461: [smf] unrelated") is None


# --------------------------------------------------------------------------- #
# mme_log.parse_mme_line (P4-5) — ANSI attach/IMSI, null-safe
# --------------------------------------------------------------------------- #
def test_parse_mme_line_ansi_attach_and_null_safe():
    ev = parse_mme_line(_MME_ATTACH)
    assert ev and ev.imsi == "001010000000002" and ev.kind == "attach"
    assert ev.ts == "07/07 03:39:30.101"
    nai = parse_mme_line(_MME_ATTACH_NAI)
    assert nai and nai.imsi == "001010000000001" and nai.kind == "attach"
    assert parse_mme_line(None) is None and parse_mme_line("") is None
    assert parse_mme_line("07/07 03:39:30.101: [mme] INFO: eNB connected") is None  # IMSI 없음


# --------------------------------------------------------------------------- #
# mongo.parse_mongo_line (A-2) — id==22943 JSON, RAN-CIDR 스코프, null-safe
# --------------------------------------------------------------------------- #
def test_parse_mongo_line_ran_scope_and_null_safe():
    ran = '{"t":{"$date":"x"},"id":22943,"msg":"Connection accepted","attr":{"remote":"10.44.0.31:44512"}}'
    p = parse_mongo_line(ran)
    assert p and p["metric"] == "DB_Access" and p["remote"] == "10.44.0.31:44512"
    # sgi/정상 측(RAN 아님) -> 신호 아님
    sgi = '{"id":22943,"attr":{"remote":"10.51.0.9:5000"}}'
    assert parse_mongo_line(sgi) is None
    # id 22944 (연결 종료) 무시; 22943 포함 비-JSON 무시
    assert parse_mongo_line('{"id":22944,"attr":{"remote":"10.44.0.31:1"}}') is None
    assert parse_mongo_line("garbage 22943 not json") is None
    assert parse_mongo_line(None) is None and parse_mongo_line("") is None
    # 이식성 (P2-3): 다른 RAN CIDR 는 config 를 따름
    assert parse_mongo_line(sgi, ran_cidr="10.51.0.0/16") is not None


# --------------------------------------------------------------------------- #
# network.parse_prometheus + counter_diff (P4-2/P4-3)
# --------------------------------------------------------------------------- #
def test_parse_prometheus_sums_labelsets():
    text = (
        "# HELP s5c_rx_deletesession delete count\n"
        "# TYPE s5c_rx_deletesession counter\n"
        's5c_rx_deletesession{addr="10.50.0.3"} 8\n'
        's5c_rx_deletesession{addr="10.50.0.5"} 1\n'
        "pfcp_sessions_active -9\n"                 # 버그성 음수 게이지(트립 소스 절대 아님)
    )
    out = parse_prometheus(text)
    assert out["s5c_rx_deletesession"] == 9.0       # 피어별 시리즈를 패밀리 합계로 합산
    assert out["pfcp_sessions_active"] == -9.0
    assert parse_prometheus("") == {}               # null-safe (빈 exposition)


def test_counter_diff_positive_only():
    assert counter_diff(None, 5.0) is None          # 첫 관측 -> 기준선, 신호 없음
    assert counter_diff(5.0, 8.0) == 3.0            # 양의 diff -> 신호
    assert counter_diff(8.0, 5.0) is None           # 리셋/재시작 -> 재시드, 신호 아님


# --------------------------------------------------------------------------- #
# web.parse_ss_established (5762 backdoor 상태)
# --------------------------------------------------------------------------- #
def test_parse_ss_established():
    estab = "0      0      10.44.0.31:44512      10.45.0.2:5762\n"
    assert parse_ss_established(estab, 5762) == 1
    assert parse_ss_established("", 5762) == 0                      # LISTEN_NO_ESTAB / 빈 입력
    assert parse_ss_established("0 0 1.2.3.4:80 5.6.7.8:80\n", 5762) == 0


# --------------------------------------------------------------------------- #
# resolve.parse_ip_addr_show (2단계 tun IPv4)
# --------------------------------------------------------------------------- #
def test_parse_ip_addr_show():
    txt = ("5: tun_srsue: <POINTOPOINT,UP,LOWER_UP> mtu 1500 qdisc fq\n"
           "    inet 10.45.0.2/32 scope global tun_srsue\n")
    assert parse_ip_addr_show(txt) == "10.45.0.2"
    assert parse_ip_addr_show("") is None and parse_ip_addr_show("no inet") is None


# --------------------------------------------------------------------------- #
# air_side._count_packets (B-3/B-4 tcpdump 패킷 카운트 디코드, null-safe)
# --------------------------------------------------------------------------- #
def test_air_side_count_packets():
    # tcpdump -q 라인: 캡처된 각 패킷은 ' IP ' 와 ' > ' 를 지님 -> 카운트
    cap = ("03:39:36.461 IP 10.44.0.31.44512 > 10.45.0.2.14556: UDP, length 20\n"
           "03:39:36.501 IP 10.44.0.31.44512 > 10.45.0.2.14556: UDP, length 20\n")
    assert _count_packets(cap) == 2
    # tcpdump 트레일러/요약 라인은 두 토큰 모두 없음 -> 카운트 안 됨(거짓 HEARTBEAT 신호 없음)
    assert _count_packets("2 packets captured\n2 packets received by filter\n0 dropped\n") == 0
    # null-safe: None / '' -> 0, 예외 없음(유휴 기준선 B-3 = 0 = normal)
    assert _count_packets(None) == 0 and _count_packets("") == 0


# --------------------------------------------------------------------------- #
# ingest 엔벨로프 코덱(encode/decode 왕복 + 크기 가드)
# --------------------------------------------------------------------------- #
def test_envelope_codec_roundtrip():
    env = SensorEnvelope(payload={"metric": "DB_Access", "value": 1}, source_id="mongo_log",
                         kid="k1", seq=7, ts=123.5, nonce="ab", hmac="deadbeef")
    back = decode_envelope(encode_envelope(env))
    assert back.payload == env.payload and back.source_id == "mongo_log"
    assert back.seq == 7 and back.nonce == "ab" and back.hmac == "deadbeef"
    # 초과 크기 가드는 조용한 절단 대신 예외 발생
    raised = False
    try:
        decode_envelope(b"x" * (2 * 1024 * 1024 + 1))
    except Exception:
        raised = True
    assert raised


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
