"""Air-side collectors (2) — netns-sidecar MAVLink taps (B-3/B-4, D-1).

Both join a target container's network namespace (via the recon-injected
``nsenter --target <pid> --net --`` prefix; None => inert) and run ``tcpdump`` through
the safe-exec Backend (불변식②). They observe the plaintext MAVLink planes the testbed
exposes:

  AirCommandTap   — uplink command entry on gcs_proxy eth0 UDP:14556 (B-3). Idle
                    baseline is 0 (traffic only under attack), so ANY packet is an
                    Unauthorized_Command signal; count -> band.
  AirTelemetryTap — downlink telemetry (14560) + uav_ue lo:14550 cross-tap (B-4/D-1).
                    Emits a link-health / HEARTBEAT-presence signal; pymavlink is used
                    to decode sys id when available (optional import).

Live tool constraint (B-2): the air image has tcpdump but no curl/nc, so these use
tcpdump only. A dry/mock Backend yields no threat signal (heartbeat still refreshes).
"""
from __future__ import annotations

import struct
from typing import Optional

from .base import BaseCollector


def _tcpdump_argv(netns_prefix: list[str], iface: str, port: int, count: int,
                  hexdump: bool = False) -> list[str]:
    # -l line-buffered, -n no-resolve, -c bounded count (so tcpdump self-terminates),
    # -q quiet. UDP filter pinned to the command/telemetry port. ``hexdump`` adds -x so the
    # MAVLink payload is dumped in hex (telemetry tap only) for flight-state decode (Phase 5);
    # the one-line packet summary is still printed, so ``_count_packets`` is unaffected.
    flags = ["tcpdump", "-l", "-n", "-q", "-c", str(count), "-i", iface]
    if hexdump:
        flags.append("-x")
    return list(netns_prefix) + flags + ["udp", "port", str(port)]


def _count_packets(stdout: str) -> int:
    """Count tcpdump packet lines (each captured packet is one line with ' IP ')."""
    if not stdout:
        return 0
    return sum(1 for ln in stdout.splitlines() if " IP " in ln or " > " in ln)


# --------------------------------------------------------------------------- #
# MAVLink flight-state decode (Phase 5) — GLOBAL_POSITION_INT.relative_alt +
# HEARTBEAT.custom_mode -> rel_alt / flight_mode SensorEv metrics.
#
# Self-contained (no pymavlink runtime dep): we sync on the MAVLink magic byte and
# CRC-validate frames for the two message ids we care about, so IP/UDP header bytes in
# the tcpdump hex can never masquerade as a valid frame (a stray 0xFD/0xFE that is not a
# real, CRC-correct HEARTBEAT/GLOBAL_POSITION_INT is rejected). READ-ONLY decode of an
# already-captured buffer — no new subprocess (불변식②) and no routing effect (불변식①:
# both metrics are emitted band="normal", which correlate() never turns into an incident).
# --------------------------------------------------------------------------- #
_MSGID_HEARTBEAT = 0
_MSGID_GLOBAL_POSITION_INT = 33
# CRC_EXTRA seed byte per message (from the MAVLink XML message crc), used in the X.25 CRC.
_CRC_EXTRA = {_MSGID_HEARTBEAT: 50, _MSGID_GLOBAL_POSITION_INT: 104}

# ArduCopter custom_mode -> mode string (the SITL vehicle is a copter). Other vehicle types
# fall back to "MODE_<n>". LAND(9)/GUIDED(4) are the S2 recovery-visible modes.
_COPTER_MODES = {
    0: "STABILIZE", 1: "ACRO", 2: "ALT_HOLD", 3: "AUTO", 4: "GUIDED", 5: "LOITER",
    6: "RTL", 7: "CIRCLE", 9: "LAND", 11: "DRIFT", 13: "SPORT", 14: "FLIP",
    15: "AUTOTUNE", 16: "POSHOLD", 17: "BRAKE", 18: "THROW", 19: "AVOID_ADSB",
    20: "GUIDED_NOGPS", 21: "SMART_RTL", 22: "FLOWHOLD", 23: "FOLLOW", 24: "ZIGZAG",
    25: "SYSTEMID", 26: "AUTOROTATE", 27: "AUTO_RTL",
}
_COPTER_TYPES = {2, 13, 14, 15}  # QUADROTOR / HEXAROTOR / OCTOROTOR / TRICOPTER


def _mode_string(mav_type: int, custom_mode: int) -> str:
    """custom_mode -> human mode string (copter table); "MODE_<n>" for non-copter/unknown."""
    if mav_type in _COPTER_TYPES:
        name = _COPTER_MODES.get(custom_mode)
        if name:
            return name
    return f"MODE_{custom_mode}"


def _x25_crc(data: bytes, crc_extra: int) -> int:
    """MAVLink CRC-16/MCRF4XX over ``data`` then the message ``crc_extra`` seed byte."""
    crc = 0xFFFF
    for b in bytes(data) + bytes([crc_extra & 0xFF]):
        tmp = (b ^ crc) & 0xFF
        tmp = (tmp ^ ((tmp << 4) & 0xFF)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


def _hex_bytes(stdout: str) -> bytes:
    """Reconstruct raw packet bytes from ``tcpdump -x`` hex-dump lines.

    A hex line looks like ``\t0x0010:  4500 0043 8a3c ...``; the one-line packet summary and
    any other text are skipped. All hex words are concatenated into one buffer for the frame
    scanner to sync on — CRC validation makes cross-packet false frames a non-issue."""
    out = bytearray()
    for ln in (stdout or "").splitlines():
        s = ln.strip()
        if not s.startswith("0x") or ":" not in s:
            continue
        body = s.split(":", 1)[1]
        for word in body.split():
            if len(word) % 2 != 0:
                continue
            try:
                out.extend(bytes.fromhex(word))
            except ValueError:
                continue
    return bytes(out)


def _iter_mav_frames(data: bytes):
    """Yield ``(msgid, sysid, compid, payload)`` for CRC-valid MAVLink v1/v2 HEARTBEAT/
    GLOBAL_POSITION_INT frames found by magic-byte sync. sysid/compid are surfaced so the
    decoder can filter to the vehicle autopilot (a co-resident GCS heartbeat must not clobber
    flight_mode). Only the two known message ids are validated/yielded; everything else advances
    one byte (so header bytes never desync the scan)."""
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b == 0xFD and i + 12 <= n:                 # MAVLink v2: magic,len,incompat,compat,seq,sys,comp,msgid(3)
            plen = data[i + 1]
            incompat = data[i + 2]
            sysid, compid = data[i + 5], data[i + 6]
            msgid = data[i + 7] | (data[i + 8] << 8) | (data[i + 9] << 16)
            end = i + 10 + plen                        # first CRC byte
            extra = _CRC_EXTRA.get(msgid)
            if extra is not None and end + 2 <= n:
                got = data[end] | (data[end + 1] << 8)
                if _x25_crc(data[i + 1:end], extra) == got:
                    yield msgid, sysid, compid, data[i + 10:end]
                    i = end + 2 + (13 if (incompat & 0x01) else 0)   # skip trailing signature
                    continue
            i += 1
        elif b == 0xFE and i + 8 <= n:                 # MAVLink v1: magic,len,seq,sys,comp,msgid(1)
            plen = data[i + 1]
            sysid, compid = data[i + 3], data[i + 4]
            msgid = data[i + 5]
            end = i + 6 + plen
            extra = _CRC_EXTRA.get(msgid)
            if extra is not None and end + 2 <= n:
                got = data[end] | (data[end + 1] << 8)
                if _x25_crc(data[i + 1:end], extra) == got:
                    yield msgid, sysid, compid, data[i + 6:end]
                    i = end + 2
                    continue
            i += 1
        else:
            i += 1


# Vehicle autopilot component id (MAV_COMP_ID_AUTOPILOT1). The testbed GCS (testbed-v2/gcs/gcs.py)
# emits its own HEARTBEAT with sysid=255/compid=190/MAV_TYPE_GCS onto the very 14550/14560 planes
# this tap captures, so an unfiltered decoder lets a GCS heartbeat clobber flight_mode with
# "MODE_0" and defeat S2 LAND detection. Only the autopilot's own frames are trusted.
_COMP_AUTOPILOT = 1


def _decode_flight_state(stdout: str, expect_sys: int = 1) -> dict:
    """Best-effort {rel_alt(m), flight_mode(str)} from a ``tcpdump -x`` telemetry capture.

    Only frames from the vehicle AUTOPILOT are trusted: compid == MAV_COMP_ID_AUTOPILOT1 and,
    when ``expect_sys`` is truthy, sysid == expect_sys (``expect_sys=0`` => accept any sysid).
    This rejects the co-resident GCS HEARTBEAT (sysid=255/compid=190/MAV_TYPE_GCS) that would
    otherwise flicker flight_mode to "MODE_0" latest-wins.

    Latest wins (parse order == wire order). Truncated v2 payloads are zero-padded (MAVLink
    trailing-zero truncation). Returns {} when nothing decodable — never raises, so the
    existing Link_Heartbeat/Packet_Loss signal path is unaffected on any decode failure."""
    data = _hex_bytes(stdout)
    if not data:
        return {}
    out: dict = {}
    for msgid, sysid, compid, payload in _iter_mav_frames(data):
        if compid != _COMP_AUTOPILOT or (expect_sys and sysid != expect_sys):
            continue                                   # not the vehicle autopilot -> ignore (GCS et al.)
        if msgid == _MSGID_GLOBAL_POSITION_INT:
            pl = payload.ljust(20, b"\x00")            # relative_alt is int32 @ payload offset 16 (mm)
            rel_mm = struct.unpack_from("<i", pl, 16)[0]
            out["rel_alt"] = round(rel_mm / 1000.0, 3)
        elif msgid == _MSGID_HEARTBEAT:
            pl = payload.ljust(6, b"\x00")             # custom_mode uint32 @0, type uint8 @4
            custom_mode = struct.unpack_from("<I", pl, 0)[0]
            out["flight_mode"] = _mode_string(pl[4], custom_mode)
    return out


class AirCommandTap(BaseCollector):
    """gcs_proxy eth0 UDP:14556 command tap -> Unauthorized_Command (command domain)."""
    source_id = "air_command_tap"
    domain = "command"

    def __init__(self, *args, container: str = "gcs_proxy", iface: str = "eth0",
                 port: int = 14556, count: int = 20,
                 netns_prefix: Optional[list[str]] = None, **kw):
        super().__init__(*args, **kw)
        self.iface = iface
        self.port = port
        self.count = count
        # netns entry prefix = canonical ["nsenter","--target","<pid>","--net","--"],
        # built by nsenter_helper from the recon-resolved host PID and injected via
        # build_collectors. None = unresolved target => this tap runs inert (no fallback;
        # ip-netns-exec is NOT invented — it would silently fail/mis-target on docker).
        self.netns_prefix = netns_prefix

    def collect(self) -> list[dict]:
        if self.netns_prefix is None:
            return []                                   # inert: unresolved netns target
        # 짧은 deadline: idle 인터페이스에서 tcpdump가 count 패킷을 기다리며 무한 블로킹하지
        # 않도록 ~2.0s 마감을 준다. -c count는 유지하되(공격 시 즉시 count까지 캡처) idle이면
        # 타임아웃이 먼저 끊어 빈 stdout(=n<=0)으로 즉시 반환 → 관측은 세마포어 미획득이라
        # 집행 경로를 막지 않지만, 짧은 마감으로 관측 스레드 자체의 정체도 방지한다.
        res = self._observe(
            _tcpdump_argv(self.netns_prefix, self.iface, self.port, self.count),
            timeout_s=2.0,
        )
        if res is None or res.dry_run:
            return []                                   # no live capture -> no signal
        n = _count_packets(res.stdout)
        if n <= 0:
            return []                                   # idle baseline (B-3): 0 = normal
        band = "warning" if n == 1 else "critical"      # Unauthorized_Command bands
        return [{
            "metric": "Unauthorized_Command", "value": n, "band": band,
            "domain": "command", "channel": "plaintext_mavlink_tap",
            "confidence": 0.95,
        }]


class AirTelemetryTap(BaseCollector):
    """Downlink telemetry (14560) + uav_ue lo:14550 cross-tap (D-1). Emits link-health
    / HEARTBEAT-presence on the communication domain.

    P5-Q2 note: this runs a SINGLE tcpdump on one iface/port and emits ONE dict (fixed
    source_id/channel), so 14560 and lo:14550 are NOT separable in the recorded evidence —
    they collapse into one telemetry root. The verifier's anti-spoof '∧' is therefore
    realized CROSS-PLANE (comm heartbeat ∧ command-plane gcs_proxy), not within this tap.
    Only a future collector SPLIT (distinct source_ids for 14560 vs lo:14550) would make a
    within-telemetry 14560∧14550 conjunction meaningful."""
    source_id = "air_telemetry_tap"
    domain = "communication"

    def __init__(self, *args, container: str = "uav_ue", iface: str = "lo",
                 port: int = 14550, count: int = 6, expect_sys: int = 1,
                 netns_prefix: Optional[list[str]] = None, **kw):
        super().__init__(*args, **kw)
        self.iface = iface
        self.port = port
        self.count = count
        self.expect_sys = expect_sys
        self.netns_prefix = netns_prefix          # None => inert (no ip-netns-exec fallback)
        # Phase 5: latest decoded flight snapshot {rel_alt, flight_mode}, accumulated across
        # cycles (each field carries its most-recent reading). Read by the effect observer's
        # signed_* path via ``snapshot()`` from the graph thread; written here from the collector
        # thread. Whole-dict reference swap only, so reads/writes are atomic under the GIL — no lock.
        self._latest: dict = {}

    def snapshot(self) -> dict:
        """Thread-safe copy of the latest {rel_alt, flight_mode} flight snapshot (Phase 5).

        Injected into ``make_effect_observer(telemetry=...)`` so signed_guided (S2 30m 복귀)
        can CONFIRM. Empty {} until the first HEARTBEAT/GLOBAL_POSITION_INT is decoded — the
        observer reads that as UNCONFIRMED (safe)."""
        return dict(self._latest)

    def collect(self) -> list[dict]:
        if self.netns_prefix is None:
            return []                                   # inert: unresolved netns target
        # deadline ~3.0s: ~1Hz HEARTBEAT에서 2s 창은 약 2패킷만 보여 HB jitter>2s이거나
        # 샘플링 공백이 짧은 실공백과 정렬되면 n==0→Packet_Loss(warning) 오탐이 났다. 창을
        # 3.0s로 소폭 확대해 최소 한 번의 HB를 안정적으로 포착, 오탐을 완화한다(손실-온셋
        # 지연은 interval_s≈0.1 back-to-back 재무장으로 별도 완화). count는 유지하되
        # 타임아웃이 먼저 끊는다 — 실제 손실이면 빈 반환(n==0)이 Packet_Loss로 정상 처리된다.
        res = self._observe(
            _tcpdump_argv(self.netns_prefix, self.iface, self.port, self.count, hexdump=True),
            timeout_s=3.0,
        )
        if res is None or res.dry_run:
            return []
        n = _count_packets(res.stdout)
        # link present if we saw downlink packets; loss signal if the cross-tap is silent
        if n > 0:
            band = "normal"
            metric, value = "Link_Heartbeat", n
        else:
            band = "warning"
            metric, value = "Packet_Loss", 100          # silent cross-tap = suspected loss
        rows = [{
            "metric": metric, "value": value, "band": band,
            "domain": "communication", "channel": "plaintext_mavlink_tap",
            "confidence": 0.95,
        }]
        # Phase 5 — flight-state observation for the S2 30m-recovery demo. Decode the MAVLink
        # payload (best-effort) and emit rel_alt / flight_mode as informational telemetry rows
        # (band="normal" => never an incident; the viewer's comm panel and the effect observer
        # read them). A decode miss simply omits these rows — link-health above is unaffected.
        flight = _decode_flight_state(res.stdout, expect_sys=self.expect_sys)
        if flight:
            # Accumulate latest-known fields (each cycle may decode only one of the two) so the
            # effect observer's signed_* path sees both rel_alt AND flight_mode. Reference swap =
            # atomic under the GIL; ``snapshot()`` reads the whole dict.
            merged = dict(self._latest)
            merged.update(flight)
            self._latest = merged
        if "rel_alt" in flight:
            rows.append({
                "metric": "rel_alt", "value": flight["rel_alt"], "band": "normal",
                "domain": "communication", "channel": "plaintext_mavlink_tap",
                "confidence": 0.95,
            })
        if "flight_mode" in flight:
            rows.append({
                "metric": "flight_mode", "value": flight["flight_mode"], "band": "normal",
                "domain": "communication", "channel": "plaintext_mavlink_tap",
                "confidence": 0.95,
            })
        return rows
