#!/usr/bin/env python3
# uav_gps — GPS 인젝터 (SITL 참값 미러). SIMSTATE(truth lat/lng)+VFR_HUD(alt) -> GPS_INPUT @10Hz.
#   SITL은 SIM_GPS1_ENABLE=0, GPS1_TYPE=14(MAV) 로 떠 있어야 함. UAV netns 로컬(비셀룰러 센서 표현).
#   사용: python3 gps_inject.py udpin:0.0.0.0:14540   (v2 재사용, v1 검증 로직)
#   v2.1 수정: 속도(vn/ve/vd)를 0이 아닌 참값으로 주입 — 수평은 참값 위치 미분,
#     수직은 VFR_HUD climb rate. (이전엔 vn=ve=vd=0 + ignore_flags=0 이라 상승 중
#     EKF에 "수직속도 0"을 주입해 이륙 시 고도 폭주. 정지 검증(G2)만 통과했던 버그.)
import sys, time, math
from pymavlink import mavutil

CONN = sys.argv[1] if len(sys.argv) > 1 else 'udpin:0.0.0.0:14540'
m = mavutil.mavlink_connection(CONN)
print("[GPS] %s — SITL telemetry 대기..." % CONN, flush=True)
if m.wait_heartbeat(timeout=60) is None:
    print("[GPS] ✗ SITL telemetry 없음"); sys.exit(1)
print("[GPS] ✓ SITL 연결(sys=%d) — GPS_INPUT 주입 @10Hz" % m.target_system, flush=True)
m.mav.request_data_stream_send(m.target_system, m.target_component, mavutil.mavlink.MAV_DATA_STREAM_ALL, 5, 1)

R_EARTH = 111320.0                                 # 위도 1도 ≈ 111.32km
last_truth = None; last_alt = 30.0; last_climb = 0.0
prev_lat = prev_lon = prev_t = None                # 참값 위치 미분용
last_send = 0.0; n = 0
while True:
    while True:                                    # 비블로킹 drain
        msg = m.recv_match(blocking=False)
        if not msg: break
        t = msg.get_type()
        if t == "SIMSTATE":  last_truth = (msg.lat, msg.lng)   # degE7 truth
        elif t == "VFR_HUD": last_alt = msg.alt; last_climb = msg.climb  # MSL m, climb +up m/s
    now = time.time()
    if last_truth and now - last_send >= 0.1:                  # 10Hz
        last_send = now
        lat, lon = last_truth
        # 참값 속도(NED): 수평=참값 위치 미분, 수직=climb rate(+up 이면 vd는 -). 되먹임 없음.
        if prev_lat is not None and now > prev_t:
            ddt = now - prev_t
            vn = ((lat - prev_lat) / 1e7) * R_EARTH / ddt
            ve = ((lon - prev_lon) / 1e7) * R_EARTH * math.cos(math.radians(lat / 1e7)) / ddt
        else:
            vn = ve = 0.0
        vd = -last_climb
        prev_lat, prev_lon, prev_t = lat, lon, now
        gt = now - 315964800; week = int(gt // 604800); wms = int((gt % 604800) * 1000)
        m.mav.gps_input_send(int(now * 1e6), 0, 0, wms, week, 3,
                             lat, lon, last_alt, 1.0, 1.0, vn, ve, vd, 0.5, 1.0, 1.0, 14, 0)
        n += 1
        if n % 50 == 0:
            print("[GPS] injected %d @10Hz (lat=%.5f alt=%.1f v=%.1f/%.1f/%.1f)" % (
                n, lat / 1e7, last_alt, vn, ve, vd), flush=True)
    time.sleep(0.02)
