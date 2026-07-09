#!/usr/bin/env python3
# gcs_cmd — 능동 GCS C2 명령기 (sysid=255). gcs.py(검증기)의 상위판.
#   gcs_proxy netns에서 udpin:0.0.0.0:14550 으로 붙으면, 내려보내는 명령은
#   프록시가 ARIA-256-GCM으로 암호화해 셀룰러로 UAV에 전달(업링크),
#   텔레메트리/ACK는 복호되어 14550으로 돌아온다(다운링크).
#   기체: ArduCopter (quad). 홈 37.5665,126.9780.
#
# 지속 연결(REPL) 모드 — 링크를 끊지 않아 빠르고, GCS 하트비트 유지로 페일세이프 방지.
#   python3 gcs_cmd.py                # 대화형: 프롬프트에 명령 타이핑
#   명령: status | mode <M> | arm | disarm | takeoff <alt> | goto <lat> <lon> <alt>
#         | rtl | land | nofs (GCS 페일세이프 완화) | watch [sec] | help | quit
#
# 단발 모드(스크립트용):  python3 gcs_cmd.py status  /  ... takeoff 20  ...
import sys, time, threading
from pymavlink import mavutil

CONN = 'udpin:0.0.0.0:14550'
mav = mavutil.mavlink_connection(CONN, source_system=255, source_component=190)

# 최신 텔레메트리 캐시. 수신 스레드가 계속 갱신한다.
STATE = {'mode': '?', 'armed': False, 'volt': 0.0, 'lat': 0.0, 'lon': 0.0,
         'alt': 0.0, 'rel': 0.0, 'hb_seen': False}
_run = True

def _rx_loop():
    """다운링크 수신 + 상태 갱신. blocking recv로 항상 링크를 소비."""
    while _run:
        msg = mav.recv_match(blocking=True, timeout=1)
        if not msg: continue
        t = msg.get_type()
        if t == 'HEARTBEAT' and msg.get_srcSystem() == mav.target_system:
            STATE['hb_seen'] = True
            STATE['mode'] = mavutil.mode_string_v10(msg)
            STATE['armed'] = bool(msg.base_mode & mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED)
        elif t == 'SYS_STATUS':
            STATE['volt'] = msg.voltage_battery / 1000.0
        elif t == 'GLOBAL_POSITION_INT':
            STATE['lat'] = msg.lat / 1e7; STATE['lon'] = msg.lon / 1e7
            STATE['alt'] = msg.alt / 1000.0; STATE['rel'] = msg.relative_alt / 1000.0

def _hb_loop():
    """GCS 하트비트 1Hz 지속 송신 — 링크 유지로 GCS 페일세이프 방지."""
    while _run:
        mav.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS,
            mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
        time.sleep(1)

def link():
    print("[GCS] %s — UAV HEARTBEAT 대기(셀룰러/ARIA)..." % CONN, flush=True)
    if mav.wait_heartbeat(timeout=30) is None:
        print("[GCS] ✗ HEARTBEAT 미수신 — C2 불통"); sys.exit(1)
    print("[GCS] ✓ 링크 성립 (UAV sys=%d)" % mav.target_system, flush=True)
    mav.mav.request_data_stream_send(mav.target_system, mav.target_component,
        mavutil.mavlink.MAV_DATA_STREAM_ALL, 4, 1)
    threading.Thread(target=_hb_loop, daemon=True).start()
    threading.Thread(target=_rx_loop, daemon=True).start()

def show_status():
    print("[STATUS] 모드=%s 시동=%s 배터리=%.1fV  lat=%.7f lon=%.7f alt=%.1fm rel=%.1fm" % (
        STATE['mode'], 'ARMED' if STATE['armed'] else 'DISARMED', STATE['volt'],
        STATE['lat'], STATE['lon'], STATE['alt'], STATE['rel']), flush=True)

def set_mode(name):
    mav.set_mode_apm(name); print("[GCS] → 모드 %s 요청" % name, flush=True)

def arm(on=True):
    if on: set_mode('GUIDED'); time.sleep(1)
    mav.mav.command_long_send(mav.target_system, mav.target_component,
        mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 0, 1 if on else 0, 0,0,0,0,0,0)
    print("[GCS] → %s 요청" % ('ARM' if on else 'DISARM'), flush=True)

def takeoff(alt):
    set_mode('GUIDED'); time.sleep(1); arm(True); time.sleep(2)
    mav.mav.command_long_send(mav.target_system, mav.target_component,
        mavutil.mavlink.MAV_CMD_NAV_TAKEOFF, 0, 0,0,0,0,0,0, float(alt))
    print("[GCS] → 이륙 %sm 요청 (rel 고도가 오르는지 watch로 확인)" % alt, flush=True)

def goto(lat, lon, alt):
    set_mode('GUIDED')
    mav.mav.set_position_target_global_int_send(
        0, mav.target_system, mav.target_component,
        mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT,
        0b0000111111111000, int(float(lat)*1e7), int(float(lon)*1e7), float(alt),
        0,0,0, 0,0,0, 0,0)
    print("[GCS] → goto %s,%s @%sm rel 전송" % (lat, lon, alt), flush=True)

def nofs():
    """GCS 페일세이프 완화(FS_GCS_ENABLE=0). 링크 순단에도 모드 안 바뀜."""
    mav.mav.param_set_send(mav.target_system, mav.target_component,
        b'FS_GCS_ENABLE', 0, mavutil.mavlink.MAV_PARAM_TYPE_INT8)
    print("[GCS] → FS_GCS_ENABLE=0 (GCS 페일세이프 완화) 요청", flush=True)

def watch(sec=15):
    end = time.time() + float(sec)
    while time.time() < end:
        show_status(); time.sleep(1)

def dispatch(parts):
    c = parts[0]; a = parts[1:]
    if   c in ('status','s'):  show_status()
    elif c == 'mode':          set_mode(a[0])
    elif c == 'arm':           arm(True)
    elif c == 'disarm':        arm(False)
    elif c == 'takeoff':       takeoff(a[0])
    elif c == 'goto':          goto(a[0], a[1], a[2])
    elif c == 'rtl':           set_mode('RTL')
    elif c == 'land':          set_mode('LAND')
    elif c == 'nofs':          nofs()
    elif c == 'watch':         watch(a[0] if a else 15)
    elif c in ('help','h','?'):print("명령: status|mode <M>|arm|disarm|takeoff <alt>|goto <lat> <lon> <alt>|rtl|land|nofs|watch [sec]|quit")
    else: print("알 수 없는 명령: %s (help)" % c)

def repl():
    print("[GCS] 대화형 세션 — 하트비트 유지중. 'help', 'quit'. ", flush=True)
    nofs()  # 시작 시 페일세이프 완화(끊겨도 알트 안 튀게)
    while True:
        try:
            line = input("c2> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line: continue
        if line in ('quit','q','exit'): break
        try: dispatch(line.split())
        except Exception as e: print("[ERR] %s" % e)
    print("[GCS] 세션 종료.")

def main():
    link()
    if len(sys.argv) < 2:
        repl()
    else:
        dispatch(sys.argv[1:]); time.sleep(1); show_status()

if __name__ == '__main__':
    try: main()
    finally:
        globals()['_run'] = False
