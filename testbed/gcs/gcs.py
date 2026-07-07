#!/usr/bin/env python3
# gcs_c2 — 능동 GCS (sysid=255). UAV HEARTBEAT 수신(다운링크) + 명령/파라미터 왕복(업링크).
#   셀룰러 C2 종단 실증. 사용: python3 gcs.py udpin:0.0.0.0:14550
import sys, time, os
from pymavlink import mavutil

CONN = sys.argv[1] if len(sys.argv) > 1 else 'udpin:0.0.0.0:14550'
m = mavutil.mavlink_connection(CONN, source_system=255, source_component=190)
_kf = os.environ.get("MAV_SIGN_KEYFILE", "/sign.key")
if os.path.exists(_kf):
    m.setup_signing(bytes.fromhex(open(_kf).read().strip()), sign_outgoing=True, allow_unsigned_callback=lambda mav, i: True, link_id=0)
    print("[GCS] 🔒 MAVLink2 서명 송신 ON (link_id=0)", flush=True)
print("[GCS] %s listening (sysid=255) — UAV 대기..." % CONN, flush=True)
if m.wait_heartbeat(timeout=60) is None:
    print("[GCS] ✗ UAV HEARTBEAT 미수신 (셀룰러 C2 불통)"); sys.exit(1)
print("[GCS] ✓ DOWNLINK HEARTBEAT from UAV sys=%d (셀룰러 경유)" % m.target_system, flush=True)
m.mav.request_data_stream_send(m.target_system, m.target_component, mavutil.mavlink.MAV_DATA_STREAM_ALL, 4, 1)

ack = False; param = False; last_hb = 0.0; last_cmd = 0.0; last_par = 0.0; last_stream = 0.0
while True:
    now = time.time()
    if now - last_hb > 1:                    # GCS heartbeat (차량이 GCS 인지)
        m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0); last_hb = now
    if now - last_stream > 5:                # 데이터스트림 주기적 재요청(SITL 재기동 내성)
        m.mav.request_data_stream_send(m.target_system, m.target_component, mavutil.mavlink.MAV_DATA_STREAM_ALL, 4, 1); last_stream = now
    if not ack and now - last_cmd > 3:       # 업링크 명령
        m.mav.command_long_send(m.target_system, m.target_component,
            mavutil.mavlink.MAV_CMD_REQUEST_AUTOPILOT_CAPABILITIES, 0, 1, 0,0,0,0,0,0); last_cmd = now
    if not param and now - last_par > 3:     # 파라미터 프로토콜
        m.mav.param_request_read_send(m.target_system, m.target_component, b'SYSID_THISMAV', -1); last_par = now
    msg = m.recv_match(blocking=True, timeout=1)
    if not msg: continue
    t = msg.get_type()
    if t in ('COMMAND_ACK', 'AUTOPILOT_VERSION') and not ack:
        ack = True; print("[GCS] ✓ UPLINK ACK ok (%s) — 양방향 C2 성립" % t, flush=True)
    elif t == 'PARAM_VALUE' and not param:
        param = True; print("[GCS] ✓ PARAM roundtrip ok (%s=%.0f)" % (msg.param_id, msg.param_value), flush=True)
