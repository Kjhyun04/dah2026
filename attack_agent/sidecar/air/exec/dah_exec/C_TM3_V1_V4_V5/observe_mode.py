#!/usr/bin/env python3
"""observe_mode (PROBE): 드론의 **실측 비행 mode** 를 평문 다운링크에서 읽는다(관측·RO).

성공판정을 자기보고(INJECT ACK)가 아니라 **실제 텔레메트리**에 근거시키기 위한 관측 센서.
평문 MAVLink 다운링크(프록시가 이미 복호해 전달하는 14550/14560 구간)를 AF_PACKET raw 로
**수동 캡처(bind 안 함·송신 0)** → HEARTBEAT(autopilot comp==1) 의 custom_mode 를 읽어 보고한다.

- 복호·키 불요: 프록시가 forward 하는 **이미 평문** 인 다운링크를 읽는다(감독의 14555 복호와 독립·
  별개 경로). grep0 무관(사이드카·core 아님). 완전 read-only(패킷 송신 0).
- stdout 계약: {"observed_mode": <int|null>, "modes_ever": [...], "heartbeats": N, "note": ...}
  observe_mode 파서(recon.parse_observed_mode)가 observed_mode 만 소비한다.
- raw 소켓/트래픽 미가용 시 보수적으로 observed_mode=null (미관측).
"""
from __future__ import annotations

import json
import os
import socket
import struct
import time

# 평문 다운링크 UDP 포트 (uav_proxy --plain-listen 14550 · gcs_proxy plain-peer :14560)
_PLAINTEXT_PORTS = (14550, 14560)


def _emit(mode, heartbeats, modes_ever, note=""):
    print(json.dumps({
        "observed_mode": mode,
        "modes_ever": modes_ever,
        "heartbeats": heartbeats,
        "note": note,
    }))


def main() -> None:
    duration_s = float(os.environ.get("OBSERVE_S", "6"))
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except Exception as e:  # NET_RAW 없음 등 → 미관측(보수)
        _emit(None, 0, [], f"no_raw_socket:{type(e).__name__}")
        return
    try:
        from pymavlink import mavutil
    except Exception:
        s.close()
        _emit(None, 0, [], "no_pymavlink")
        return

    mav = mavutil.mavlink.MAVLink(None)
    mav.robust_parsing = True
    s.settimeout(2.0)
    end = time.time() + duration_s
    final_mode = None
    heartbeats = 0
    modes_ever: list[int] = []
    try:
        while time.time() < end:
            try:
                raw, _ = s.recvfrom(65535)
            except socket.timeout:
                continue
            # Ethernet(14) → IPv4(0x0800) → UDP(17)
            if len(raw) < 42 or struct.unpack("!H", raw[12:14])[0] != 0x0800:
                continue
            ip = raw[14:]
            ihl = (ip[0] & 0x0F) * 4
            if len(ip) < ihl + 8 or ip[9] != 17:
                continue
            udp = ip[ihl:]
            sport, dport = struct.unpack("!HH", udp[:4])
            if not (sport in _PLAINTEXT_PORTS or dport in _PLAINTEXT_PORTS):
                continue
            try:
                msgs = mav.parse_buffer(udp[8:]) or []
            except Exception:
                continue  # 손상 프레임 1개가 전체 캡처를 못 죽인다
            for m in msgs:
                try:
                    if (m.get_type() == "HEARTBEAT"
                            and m.get_srcComponent() == 1
                            and getattr(m, "type", 0) != 6):  # comp==1 autopilot, GCS(6) 제외
                        cm = int(m.custom_mode)
                        heartbeats += 1
                        final_mode = cm
                        if cm not in modes_ever:
                            modes_ever.append(cm)
                except Exception:
                    continue
    finally:
        try:
            s.close()
        except OSError:
            pass
    _emit(final_mode, heartbeats, modes_ever,
          "observed" if final_mode is not None else "no_heartbeat")


if __name__ == "__main__":
    main()
