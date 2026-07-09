"""Air 측 collector 2종 — netns-사이드카 MAVLink 탭 (B-3/B-4, D-1).

둘 다 타깃 컨테이너의 네트워크 네임스페이스에 합류하고(recon 주입
``nsenter --target <pid> --net --`` prefix 경유; None => inert) safe-exec Backend를 통해
``tcpdump``를 실행한다(불변식2.). testbed가 노출하는 평문 MAVLink 평면을 관측한다:

  AirCommandTap   — gcs_proxy eth0 UDP:14556의 업링크 명령 진입 (B-3). idle
                    baseline은 0이므로(공격 시에만 트래픽), 어떤 패킷이든
                    Unauthorized_Command 신호다; count -> band.
  AirTelemetryTap — 다운링크 telemetry (14560) + uav_ue lo:14550 cross-tap (B-4/D-1).
                    link-health / HEARTBEAT-presence 신호를 방출한다; 가능하면 pymavlink로
                    sys id를 디코드한다(선택적 import).

라이브 도구 제약 (B-2): air 이미지에는 tcpdump는 있으나 curl/nc는 없어 이들은 tcpdump만
쓴다. dry/mock Backend는 위협 신호를 내지 않는다(heartbeat는 여전히 갱신).
"""
from __future__ import annotations

import struct
from typing import Optional

from ..config import defaults as D          # P4 단일 설정원: 포트는 INPUT_SPEC["ports"] 에서만 정의
from .base import BaseCollector


def _tcpdump_argv(netns_prefix: list[str], iface: str, port: int, count: int,
                  hexdump: bool = False) -> list[str]:
    # -l line-buffered, -n no-resolve, -c bounded count (tcpdump 자기종료용),
    # -q quiet. UDP 필터는 command/telemetry 포트에 고정. ``hexdump``는 -x를 추가해
    # MAVLink payload를 hex로 덤프한다(telemetry 탭 전용) flight-state 디코드용(Phase 5);
    # 한 줄 패킷 요약은 여전히 출력되므로 ``_count_packets``는 영향받지 않는다.
    flags = ["tcpdump", "-l", "-n", "-q", "-c", str(count), "-i", iface]
    if hexdump:
        flags.append("-x")
    return list(netns_prefix) + flags + ["udp", "port", str(port)]


def _count_packets(stdout: str) -> int:
    """tcpdump 패킷 라인을 센다(캡처된 각 패킷은 ' IP '가 있는 한 줄)."""
    if not stdout:
        return 0
    return sum(1 for ln in stdout.splitlines() if " IP " in ln or " > " in ln)


# --------------------------------------------------------------------------- #
# MAVLink flight-state 디코드 (Phase 5) — GLOBAL_POSITION_INT.relative_alt +
# HEARTBEAT.custom_mode -> rel_alt / flight_mode SensorEv 메트릭.
#
# 자기완결형(pymavlink 런타임 의존 없음): MAVLink 매직 바이트에 동기화하고 관심 있는 두
# message id에 대해 프레임을 CRC 검증하므로, tcpdump hex 안의 IP/UDP 헤더 바이트가 유효
# 프레임으로 위장할 수 없다(실제 CRC-정합 HEARTBEAT/GLOBAL_POSITION_INT가 아닌 떠도는
# 0xFD/0xFE는 거부됨). 이미 캡처된 버퍼의 READ-ONLY 디코드 — 새 subprocess 없음(불변식2.),
# 라우팅 효과 없음(불변식1.: 두 메트릭 모두 band="normal"로 방출되어 correlate()가 결코
# incident로 만들지 않음).
# --------------------------------------------------------------------------- #
_MSGID_HEARTBEAT = 0
_MSGID_GLOBAL_POSITION_INT = 33
# 메시지별 CRC_EXTRA 시드 바이트 (MAVLink XML message crc 유래), X.25 CRC에 사용.
_CRC_EXTRA = {_MSGID_HEARTBEAT: 50, _MSGID_GLOBAL_POSITION_INT: 104}

# ArduCopter custom_mode -> 모드 문자열 (SITL 기체는 copter). 다른 기체 타입은
# "MODE_<n>"로 폴백. LAND(9)/GUIDED(4)가 S2 recovery-가시 모드다.
_COPTER_MODES = {
    0: "STABILIZE", 1: "ACRO", 2: "ALT_HOLD", 3: "AUTO", 4: "GUIDED", 5: "LOITER",
    6: "RTL", 7: "CIRCLE", 9: "LAND", 11: "DRIFT", 13: "SPORT", 14: "FLIP",
    15: "AUTOTUNE", 16: "POSHOLD", 17: "BRAKE", 18: "THROW", 19: "AVOID_ADSB",
    20: "GUIDED_NOGPS", 21: "SMART_RTL", 22: "FLOWHOLD", 23: "FOLLOW", 24: "ZIGZAG",
    25: "SYSTEMID", 26: "AUTOROTATE", 27: "AUTO_RTL",
}
_COPTER_TYPES = {2, 13, 14, 15}  # QUADROTOR / HEXAROTOR / OCTOROTOR / TRICOPTER


def _mode_string(mav_type: int, custom_mode: int) -> str:
    """custom_mode -> 사람용 모드 문자열(copter 테이블); non-copter/unknown은 "MODE_<n>"."""
    if mav_type in _COPTER_TYPES:
        name = _COPTER_MODES.get(custom_mode)
        if name:
            return name
    return f"MODE_{custom_mode}"


def _x25_crc(data: bytes, crc_extra: int) -> int:
    """``data`` 위에 MAVLink CRC-16/MCRF4XX 계산 후 메시지 ``crc_extra`` 시드 바이트."""
    crc = 0xFFFF
    for b in bytes(data) + bytes([crc_extra & 0xFF]):
        tmp = (b ^ crc) & 0xFF
        tmp = (tmp ^ ((tmp << 4) & 0xFF)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


def _hex_bytes(stdout: str) -> bytes:
    """``tcpdump -x`` hex-dump 라인에서 원시 패킷 바이트를 재구성한다.

    hex 라인은 ``\t0x0010:  4500 0043 8a3c ...`` 형태다; 한 줄 패킷 요약과 기타 텍스트는
    건너뛴다. 모든 hex word를 하나의 버퍼로 이어붙여 프레임 스캐너가 동기화하게 한다 —
    CRC 검증으로 패킷 간 거짓 프레임은 문제되지 않는다."""
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
    """매직 바이트 동기화로 찾은 CRC-유효 MAVLink v1/v2 HEARTBEAT/GLOBAL_POSITION_INT
    프레임에 대해 ``(msgid, sysid, compid, payload)``를 yield한다. sysid/compid를 노출해
    디코더가 기체 autopilot으로 필터할 수 있게 한다(공존 GCS heartbeat가 flight_mode를
    덮어써선 안 됨). 알려진 두 message id만 검증/yield하고; 나머지는 모두 한 바이트씩
    전진한다(헤더 바이트가 스캔을 결코 desync하지 않도록)."""
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
                    i = end + 2 + (13 if (incompat & 0x01) else 0)   # 후행 signature 스킵
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


# 기체 autopilot 컴포넌트 id (MAV_COMP_ID_AUTOPILOT1). testbed GCS(testbed-v2/gcs/gcs.py)는
# 이 탭이 캡처하는 바로 그 14550/14560 평면에 sysid=255/compid=190/MAV_TYPE_GCS로 자체
# HEARTBEAT를 방출하므로, 필터 없는 디코더는 GCS heartbeat가 flight_mode를 "MODE_0"으로
# 덮어써 S2 LAND 탐지를 무력화하게 둔다. autopilot 자신의 프레임만 신뢰한다.
_COMP_AUTOPILOT = 1


def _decode_flight_state(stdout: str, expect_sys: int = 1) -> dict:
    """``tcpdump -x`` telemetry 캡처로부터 best-effort {rel_alt(m), flight_mode(str)}.

    기체 AUTOPILOT의 프레임만 신뢰한다: compid == MAV_COMP_ID_AUTOPILOT1이고,
    ``expect_sys``가 truthy이면 sysid == expect_sys(``expect_sys=0`` => 임의 sysid 허용).
    이는 그렇지 않으면 flight_mode를 "MODE_0"으로 latest-wins 깜빡이게 할 공존 GCS
    HEARTBEAT(sysid=255/compid=190/MAV_TYPE_GCS)를 거부한다.

    Latest wins(파싱 순서 == 와이어 순서). 잘린 v2 payload는 zero-pad된다(MAVLink 후행-0
    절단). 디코드 가능한 게 없으면 {}를 반환한다 — 결코 raise하지 않으므로 기존
    Link_Heartbeat/Packet_Loss 신호 경로는 어떤 디코드 실패에도 영향받지 않는다."""
    data = _hex_bytes(stdout)
    if not data:
        return {}
    out: dict = {}
    for msgid, sysid, compid, payload in _iter_mav_frames(data):
        if compid != _COMP_AUTOPILOT or (expect_sys and sysid != expect_sys):
            continue                                   # 기체 autopilot 아님 -> 무시 (GCS 등)
        if msgid == _MSGID_GLOBAL_POSITION_INT:
            pl = payload.ljust(20, b"\x00")            # relative_alt는 payload offset 16의 int32 (mm)
            rel_mm = struct.unpack_from("<i", pl, 16)[0]
            out["rel_alt"] = round(rel_mm / 1000.0, 3)
        elif msgid == _MSGID_HEARTBEAT:
            pl = payload.ljust(6, b"\x00")             # custom_mode uint32 @0, type uint8 @4
            custom_mode = struct.unpack_from("<I", pl, 0)[0]
            out["flight_mode"] = _mode_string(pl[4], custom_mode)
    return out


class AirCommandTap(BaseCollector):
    """gcs_proxy eth0 UDP:14556 명령 탭 -> Unauthorized_Command (command 도메인)."""
    source_id = "air_command_tap"
    domain = "command"

    def __init__(self, *args, container: str = "gcs_proxy", iface: str = "eth0",
                 port: int = D.INPUT_SPEC["ports"]["command"], count: int = 20,
                 netns_prefix: Optional[list[str]] = None, **kw):
        super().__init__(*args, **kw)
        self.iface = iface
        self.port = port
        self.count = count
        # netns 진입 prefix = 정규 ["nsenter","--target","<pid>","--net","--"],
        # recon이 해소한 호스트 PID로 nsenter_helper가 만들어 build_collectors 경유로
        # 주입한다. None = 미해소 타깃 => 이 탭은 inert로 동작한다(폴백 없음;
        # ip-netns-exec를 지어내지 않는다 — docker에서 조용히 실패/오조준할 것이므로).
        self.netns_prefix = netns_prefix

    def collect(self) -> list[dict]:
        if self.netns_prefix is None:
            return []                                   # inert: 미해소 netns 타깃
        # 짧은 deadline: idle 인터페이스에서 tcpdump가 count 패킷을 기다리며 무한 블로킹하지
        # 않도록 ~2.0s 마감을 준다. -c count는 유지하되(공격 시 즉시 count까지 캡처) idle이면
        # 타임아웃이 먼저 끊어 빈 stdout(=n<=0)으로 즉시 반환한다. 이 관측은 세마포어 미획득이라
        # 집행 경로를 막지 않지만, 짧은 마감으로 관측 스레드 자체의 정체도 방지한다.
        res = self._observe(
            _tcpdump_argv(self.netns_prefix, self.iface, self.port, self.count),
            timeout_s=2.0,
        )
        if res is None or res.dry_run:
            return []                                   # 라이브 캡처 없음 -> 신호 없음
        n = _count_packets(res.stdout)
        if n <= 0:
            return []                                   # idle baseline (B-3): 0 = normal
        band = "warning" if n == 1 else "critical"      # Unauthorized_Command 밴드
        return [{
            "metric": "Unauthorized_Command", "value": n, "band": band,
            "domain": "command", "channel": "plaintext_mavlink_tap",
            "confidence": 0.95,
        }]


class AirTelemetryTap(BaseCollector):
    """다운링크 telemetry (14560) + uav_ue lo:14550 cross-tap (D-1). communication 도메인에
    link-health / HEARTBEAT-presence를 방출한다.

    P5-Q2 주: 하나의 iface/port에서 SINGLE tcpdump를 돌리고 dict 하나(고정
    source_id/channel)를 방출하므로, 14560과 lo:14550은 기록된 근거에서 분리되지 않는다 —
    하나의 telemetry 루트로 합쳐진다. 따라서 verifier의 anti-spoof '∧'는 이 탭 내부가 아니라
    CROSS-PLANE(comm heartbeat ∧ command-plane gcs_proxy)으로 실현된다.
    미래의 collector SPLIT(14560 vs lo:14550에 서로 다른 source_id)만이 telemetry 내부
    14560∧14550 논리곱을 의미 있게 만든다."""
    source_id = "air_telemetry_tap"
    domain = "communication"

    def __init__(self, *args, container: str = "uav_ue", iface: str = "lo",
                 port: int = D.INPUT_SPEC["ports"]["uav_lo_telemetry"], count: int = 6, expect_sys: int = 1,
                 netns_prefix: Optional[list[str]] = None, **kw):
        super().__init__(*args, **kw)
        self.iface = iface
        self.port = port
        self.count = count
        self.expect_sys = expect_sys
        self.netns_prefix = netns_prefix          # None => inert (ip-netns-exec 폴백 없음)
        # Phase 5: 최신 디코드된 비행 스냅샷 {rel_alt, flight_mode}, 사이클에 걸쳐 누적됨
        # (각 필드는 가장 최근 읽은 값을 보유). 그래프 스레드에서 effect observer의 signed_*
        # 경로가 ``snapshot()`` 경유로 읽고; 여기 collector 스레드에서 쓴다. dict 전체 참조
        # 교체뿐이라 읽기/쓰기가 GIL 하에서 atomic이다 — 락 없음.
        self._latest: dict = {}

    def snapshot(self) -> dict:
        """최신 {rel_alt, flight_mode} 비행 스냅샷의 스레드-안전 복사본 (Phase 5).

        ``make_effect_observer(telemetry=...)``에 주입되어 signed_guided(S2 30m 복귀)가
        CONFIRM할 수 있게 한다. 첫 HEARTBEAT/GLOBAL_POSITION_INT가 디코드될 때까지 {} —
        observer는 이를 UNCONFIRMED(안전)로 읽는다."""
        return dict(self._latest)

    def collect(self) -> list[dict]:
        if self.netns_prefix is None:
            return []                                   # inert: 미해소 netns 타깃
        # deadline ~3.0s: ~1Hz HEARTBEAT에서 2s 창은 약 2패킷만 보여 HB jitter>2s이거나
        # 샘플링 공백이 짧은 실공백과 정렬되면 n==0이 되어 Packet_Loss(warning) 오탐이 났다. 창을
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
        # STATUS-ONLY link health (P2): 이 탭은 상시 link-health STATUS 소스이며 incident
        # 소스가 아니다. 존재(Link_Heartbeat)와 침묵(Packet_Loss) cross-tap 모두 band="normal"로
        # 방출되어, 일시적 HB jitter / 샘플링 공백이 (a) correlate의 단일신호 Packet_Loss
        # incident를 트립하거나 (b) compute_trust에서 communication trust를 저하시키는
        # (severity_factor("normal")==0) 일이 결코 없다 — 즉 관측 blip으로부터 자율(파괴적)
        # 복구를 구동할 수 없다. 진짜 지속된 telemetry-silence는 여전히 (1) band가 아니라 metric
        # NAME(Link_Heartbeat vs Packet_Loss+channel)에 키를 두는 독립 Verifier와 (2) 뷰어
        # 우측 link-health 상태 박스를 통해 DEGRADED로 드러나지만 — agent incident/자동복구로는
        # 결코 아니다. snapshot()/rel_alt/flight_mode은 영향받지 않는다.
        if n > 0:
            metric, value = "Link_Heartbeat", n
        else:
            metric, value = "Packet_Loss", 100          # 침묵 cross-tap = 손실 의심 (status-only)
        rows = [{
            "metric": metric, "value": value, "band": "normal",   # status-only: 결코 incident를 트립하지 않음
            "domain": "communication", "channel": "plaintext_mavlink_tap",
            "confidence": 0.95,
        }]
        # Phase 5 — S2 30m-복구 데모용 flight-state 관측. MAVLink payload를 디코드하고
        # (best-effort) rel_alt / flight_mode를 정보성 telemetry 행으로 방출한다
        # (band="normal" => 결코 incident 아님; 뷰어 comm 패널과 effect observer가 읽음).
        # 디코드 실패 시 이 행들을 생략할 뿐 — 위의 link-health는 영향받지 않는다.
        flight = _decode_flight_state(res.stdout, expect_sys=self.expect_sys)
        if flight:
            # 최신 알려진 필드를 누적한다(각 사이클은 둘 중 하나만 디코드할 수 있음) effect
            # observer의 signed_* 경로가 rel_alt와 flight_mode를 모두 보도록. 참조 교체 =
            # GIL 하에서 atomic; ``snapshot()``은 dict 전체를 읽는다.
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
