"""verify_parsers — GATE2 verify-script for the EPC/metric/observation parser set
(DESIGN_DECISIONS appendix A ``verify_parsers``; P4-1/P4-2/P4-5).

Exercises EVERY parse function against an ANSI-coloured fixture (the live EPC logs are
colour-escaped — a parser that skips the strip silently matches nothing) AND a null-safe
case (None/"" must not raise). Runnable standalone with zero deps:

    python mdg/tests/verify_parsers.py      # -> [PASS]/[FAIL] per parser, exit 1 on any fail

Parser set covered — the 12 PURE (fixture-testable, no live backend) decode functions
(finding P2-2 / P2-4):
  log_common.ansi_strip / parse_epc_ts        (shared EPC strip + ts, null-safe)     [2]
  smf_session.parse_smf_line                  (P4-1 SMF create/remove, ANSI, CIDR-scoped, null-safe) [1]
  mme_log.parse_mme_line                      (P4-5 MME attach/IMSI, ANSI, null-safe) [1]
  mongo.parse_mongo_line                      (A-2 id==22943 JSON, RAN-CIDR scoped, null-safe) [1]
  network.parse_prometheus / counter_diff     (P4-2/P4-3 exposition sum, positive-diff-only) [2]
  web.parse_ss_established                     (5762 ESTAB count)                     [1]
  air_side._count_packets                     (B-3/B-4 tcpdump HEARTBEAT/packet-count decode, null-safe) [1]
  resolve.parse_ip_addr_show                  (stage-2 tun IPv4)                      [1]
  ingest.encode_envelope / decode_envelope    (envelope codec roundtrip, size guard) [2]
                                              -----------------------------------------
                                              = 12 pure decode fns, ALL exercised here.

'19 파서' target reconciliation (finding P2-4 — was unreconciled): the design's 19 counts
these 12 PURE decode fns PLUS the 7 LIVE collector band-classifiers embedded in the
``*.collect()`` methods (air_command / air_telemetry / network / web / mongo / mme /
smf collectors) — those are subprocess/backend-driven (nsenter+tcpdump / ss / docker-logs
/ :9090 scrape) and are covered by the integration suite (test_p4_*, verify_d11_*), NOT
here, because they cannot run without a live/mock Backend. This file's contract is the
12 PURE fns; 12 (pure, here) + 7 (live, integration) = 19. Keep this split in sync with
DESIGN_DECISIONS appendix A if a parser is added/removed.
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
# ANSI-coloured fixtures (Open5GS SGR escapes around the payload tokens)
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
    assert ansi_strip("") == "" and ansi_strip(None) is None      # null-safe passthrough


def test_parse_epc_ts_and_null_safe():
    assert parse_epc_ts(ansi_strip(_SMF_CREATE)) == "07/07 03:39:36.461"
    assert parse_epc_ts("no timestamp here") == ""
    assert parse_epc_ts("") == "" and parse_epc_ts(None) == ""     # null-safe: no re.search(None)


# --------------------------------------------------------------------------- #
# smf_session.parse_smf_line (P4-1) — ANSI, create/remove, CIDR-scope, null-safe
# --------------------------------------------------------------------------- #
def test_parse_smf_line_ansi_create_remove():
    ev = parse_smf_line(_SMF_CREATE)
    assert ev and ev.op == "add" and ev.imsi == "001010000000001" and ev.ip == "10.45.0.2"
    assert ev.ts == "07/07 03:39:36.461"
    rem = parse_smf_line(_SMF_REMOVE)
    assert rem and rem.op == "remove" and rem.imsi == "001010000000001" and rem.ip == "10.45.0.2"


def test_parse_smf_line_cidr_scoped_and_null_safe():
    # portability (P2-3): an out-of-pool IP is ignored under the default pool, matched under
    # a matching config pool_cidr — parser follows config, not a hardcoded literal.
    other = _SMF_CREATE.replace("10.45.0.2", "10.99.0.7")
    assert parse_smf_line(other) is None
    assert parse_smf_line(other, pool_cidr="10.99.0.0/16").ip == "10.99.0.7"
    # null-safe + noise
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
    assert parse_mme_line("07/07 03:39:30.101: [mme] INFO: eNB connected") is None  # no IMSI


# --------------------------------------------------------------------------- #
# mongo.parse_mongo_line (A-2) — id==22943 JSON, RAN-CIDR scope, null-safe
# --------------------------------------------------------------------------- #
def test_parse_mongo_line_ran_scope_and_null_safe():
    ran = '{"t":{"$date":"x"},"id":22943,"msg":"Connection accepted","attr":{"remote":"10.44.0.31:44512"}}'
    p = parse_mongo_line(ran)
    assert p and p["metric"] == "DB_Access" and p["remote"] == "10.44.0.31:44512"
    # sgi/normal side (not RAN) -> not a signal
    sgi = '{"id":22943,"attr":{"remote":"10.51.0.9:5000"}}'
    assert parse_mongo_line(sgi) is None
    # id 22944 (connection ended) ignored; non-JSON containing 22943 ignored
    assert parse_mongo_line('{"id":22944,"attr":{"remote":"10.44.0.31:1"}}') is None
    assert parse_mongo_line("garbage 22943 not json") is None
    assert parse_mongo_line(None) is None and parse_mongo_line("") is None
    # portability (P2-3): a different RAN CIDR follows config
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
        "pfcp_sessions_active -9\n"                 # buggy negative gauge (never a trip source)
    )
    out = parse_prometheus(text)
    assert out["s5c_rx_deletesession"] == 9.0       # per-peer series summed to family total
    assert out["pfcp_sessions_active"] == -9.0
    assert parse_prometheus("") == {}               # null-safe (empty exposition)


def test_counter_diff_positive_only():
    assert counter_diff(None, 5.0) is None          # first obs -> baseline, no signal
    assert counter_diff(5.0, 8.0) == 3.0            # positive diff -> signal
    assert counter_diff(8.0, 5.0) is None           # reset/restart -> reseed, not a signal


# --------------------------------------------------------------------------- #
# web.parse_ss_established (5762 backdoor state)
# --------------------------------------------------------------------------- #
def test_parse_ss_established():
    estab = "0      0      10.44.0.31:44512      10.45.0.2:5762\n"
    assert parse_ss_established(estab, 5762) == 1
    assert parse_ss_established("", 5762) == 0                      # LISTEN_NO_ESTAB / empty
    assert parse_ss_established("0 0 1.2.3.4:80 5.6.7.8:80\n", 5762) == 0


# --------------------------------------------------------------------------- #
# resolve.parse_ip_addr_show (stage-2 tun IPv4)
# --------------------------------------------------------------------------- #
def test_parse_ip_addr_show():
    txt = ("5: tun_srsue: <POINTOPOINT,UP,LOWER_UP> mtu 1500 qdisc fq\n"
           "    inet 10.45.0.2/32 scope global tun_srsue\n")
    assert parse_ip_addr_show(txt) == "10.45.0.2"
    assert parse_ip_addr_show("") is None and parse_ip_addr_show("no inet") is None


# --------------------------------------------------------------------------- #
# air_side._count_packets (B-3/B-4 tcpdump packet-count decode, null-safe)
# --------------------------------------------------------------------------- #
def test_air_side_count_packets():
    # tcpdump -q lines: each captured packet carries ' IP ' and ' > ' -> counted
    cap = ("03:39:36.461 IP 10.44.0.31.44512 > 10.45.0.2.14556: UDP, length 20\n"
           "03:39:36.501 IP 10.44.0.31.44512 > 10.45.0.2.14556: UDP, length 20\n")
    assert _count_packets(cap) == 2
    # tcpdump trailer/summary lines carry neither token -> not counted (no false HEARTBEAT signal)
    assert _count_packets("2 packets captured\n2 packets received by filter\n0 dropped\n") == 0
    # null-safe: None / '' -> 0, never raises (idle baseline B-3 = 0 = normal)
    assert _count_packets(None) == 0 and _count_packets("") == 0


# --------------------------------------------------------------------------- #
# ingest envelope codec (encode/decode roundtrip + size guard)
# --------------------------------------------------------------------------- #
def test_envelope_codec_roundtrip():
    env = SensorEnvelope(payload={"metric": "DB_Access", "value": 1}, source_id="mongo_log",
                         kid="k1", seq=7, ts=123.5, nonce="ab", hmac="deadbeef")
    back = decode_envelope(encode_envelope(env))
    assert back.payload == env.payload and back.source_id == "mongo_log"
    assert back.seq == 7 and back.nonce == "ab" and back.hmac == "deadbeef"
    # oversize guard raises rather than silently truncating
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
