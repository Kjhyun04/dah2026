#!/usr/bin/env python3
"""gcs_signed_correct.py — SIGNED 복구-교정 발신기(참조용 / 대체됨).

!!! 독립 발신기로는 동작하지 않음 — 배포 금지(live-verified 2026-07-09) !!!
gcs_c2 안에서 gcs.py가 SITL signing link의 유일한 소유자다: 그것만이
udpin:127.0.0.1:14550을 bind하고 /sign.key로 setup_signing(sign_outgoing=True)를 했다. 따라서
두 번째 프로세스(독립적으로 exec된 이 발신기)는 14550에서 telemetry를 받을 수도, 그 signed link로
방출할 수도 없다 — 소켓을 이미 gcs.py가 점유하고 있어, 이 발신기의 heartbeat 대기는 timeout되고
그 명령은 SITL에 결코 도달하지 못한다. 이 파일은 오직 signed set_mode(GUIDED)+return-to-alt
시퀀스의 참조 구현으로만 유지된다(gcs.py의 trigger 핸들러가 그대로 미러링하는 정확한 관례).

실제(live-verified) 복구 경로 — gcs.py TRIGGER-FILE 폴링, 표준 형태는
assets/gcs_recovery_trigger.README 참조:
  1. MDG는 gcs_c2 안에 trigger 파일을 씀으로써 위임한다(signer_shim._delegate_argv):
        docker exec gcs_c2 sh -c 'printf "%s %s" "$1" "$2" > /tmp/mdg_correct' sh <MODE> <ALT>
  2. 배포된 gcs.py는 매 루프마다 /tmp/mdg_correct를 폴링한다; 존재하면 "<MODE> <ALT>"를 읽고
     자신의 signing link로 set_mode(GUIDED)+COMPONENT_ARM_DISARM(arm)+NAV_TAKEOFF(alt)를
     발행한 뒤 파일을 삭제한다. 서명은 gcs.py가 자신의 키로 생성한다 — MDG는 KEY-FREE로 유지된다.

키 소유권(E11 non-proliferation): MAVLink uplink-signing 키는 오직 gcs_c2 안에만 존재한다
(/sign.key, /gcs.py가 이미 쓰는 그 키). MDG는 그것을 절대 열거나, 읽거나, 이름 짓거나, 복사하지 않는다
— 서명은 키를 이미 소유한 컨테이너 안, 여기서 생성된다. 이것이
defense_agent 코드베이스가 정적으로 key-free를 유지하는 이유다(verify_signer_no_keyopen): 키를 만지는
유일한 코드는 이 컨테이너 내부 발신기다.

동작(S2 물리적 복귀): 로컬 SITL 브리지로 SIGNED MAVLink2 link를 연다
(udpout:127.0.0.1:14550 -> ARIA cipher proxy 14555 -> uav_proxy signature verify -> SITL), 그다음
  (a) DO_SET_MODE GUIDED  — guided target을 받아들이는 모드로 명령 권한을 되찾고,
  (b) 현재 위치 위로 <alt> m RELATIVE-altitude hover로 복귀
      (SET_POSITION_TARGET_GLOBAL_INT, MAV_FRAME_GLOBAL_RELATIVE_ALT_INT),
그리하여 명령 탈취(예: 무단 LAND)를 물리적으로 무효화하고 드론이 다시
~30 m home/hover 고도로 상승한다. 서명은 /gcs.py와 동일한 관례를 쓴다
(setup_signing(bytes.fromhex(<key>), sign_outgoing=True)).
"""
from __future__ import annotations

import sys
import time

from pymavlink import mavutil

SIGN_KEYFILE = "/sign.key"          # gcs_c2 로컬 signing 키(/gcs.py가 쓰는 그 키) — 절대 gcs_c2를 벗어나지 않음
LINK = "udpout:127.0.0.1:14550"     # 로컬 signed uplink -> ARIA proxy -> uav_proxy verify -> SITL
COPTER_GUIDED_CUSTOM_MODE = 4       # ArduCopter GUIDED custom_mode

# --- blocking-time budget (HISTORICAL — 이 독립 발신기는 대체됨; 헤더 참조) ------
# NOTE: 이 예산은 구형 docker exec gcs_c2 python3 <sender> … 모델에 적용됐으며, 그 모델은
# 동작하지 않는다(SITL link를 gcs.py가 소유). signed 시퀀스의 참조로만 유지된다;
# live 경로(gcs.py trigger 폴링)는 비동기이며 _DELEGATE_TIMEOUT_S로 제한되지 않는다.
# (historical) 이 발신기를 실행하던 Backend spawn은
# HARD deadline(signer_shim._DELEGATE_TIMEOUT_S)을 강제했다. 이 발신기의 최악 블로킹이 그
# deadline을 초과하면 프로세스 그룹이 시퀀스 도중에 SIGKILL된다 — 그러면 S2 물리적 복귀가 조용히
# 잘릴 수 있다(GUIDED는 설정됐으나 30 m 재배치가 발행 안 됨, 또는 한 번만 발행). 그래서 아래 모든
# 블로킹 호출은 제한되며 최악의 경우가 spawn deadline보다 충분히 낮게 유지되어야 한다:
#     HEARTBEAT_TIMEOUT_S + 2*(POS_TIMEOUT_S + SETTLE_S) = 5 + 2*(2 + 1) = 11s  (<< 30s deadline).
# 둘 중 하나라도 재조정되면 이 합과 signer_shim._DELEGATE_TIMEOUT_S를 lockstep으로 유지하라.
HEARTBEAT_TIMEOUT_S = 5.0           # heartbeat에서 target_system을 학습(이전 10s)
POS_TIMEOUT_S = 2.0                 # 재배치마다 best-effort 현재 위치 읽기(이전 5s)
SETTLE_S = 1.0                      # 전송 사이에 mode / guided target이 적용되도록 대기


def _load_signing_key() -> bytes:
    """gcs_c2 자신의 signing 키를 읽는다(hex 텍스트, /gcs.py처럼). 오직 gcs_c2 안에서만 실행된다."""
    with open(SIGN_KEYFILE, "r", encoding="utf-8") as fh:
        return bytes.fromhex(fh.read().strip())


def _connect_signed() -> "mavutil.mavfile":
    master = mavutil.mavlink_connection(LINK, dialect="ardupilotmega")
    # MAVLink2 + outgoing signing — /gcs.py의 setup_signing(sign_outgoing=True)과 동일한 관례.
    master.setup_signing(_load_signing_key(), sign_outgoing=True)
    return master


def _wait_target(master: "mavutil.mavfile", timeout: float = HEARTBEAT_TIMEOUT_S):
    """heartbeat에서 vehicle system/component id를 학습해 명령 target을 지정한다.

    HEARTBEAT msg(또는 None)를 반환한다. telemetry가 실제로 이 발신기에 도달했는지 크게
    로깅한다: heartbeat가 오지 않으면 target_system은 0(broadcast)으로 남고 교정은
    best-effort broadcast로 강등된다 — 그것은 spawn stdout에 반드시 보여야 한다(누락된
    gcs.py-to-client telemetry relay는 그렇지 않으면 조용하다). 발신기는 그래도 best-effort로 진행한다."""
    hb = master.wait_heartbeat(timeout=timeout)
    if hb is None or getattr(master, "target_system", 0) == 0:
        print(f"gcs_signed_correct: WARNING no HEARTBEAT within {timeout:.0f}s "
              "-> target_system=0 (broadcast); telemetry relay to this sender may be absent",
              flush=True)
    else:
        print(f"gcs_signed_correct: HEARTBEAT sys={master.target_system} "
              f"comp={master.target_component}", flush=True)
    return hb


def _set_mode_guided(master: "mavutil.mavfile", custom_mode: int) -> None:
    master.mav.command_long_send(
        master.target_system, master.target_component,
        mavutil.mavlink.MAV_CMD_DO_SET_MODE, 0,
        mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, custom_mode,
        0, 0, 0, 0, 0,
    )


def _current_global(master: "mavutil.mavfile", timeout: float = POS_TIMEOUT_S):
    """복귀 hover가 현재 위치를 유지하도록 best-effort 현재 lat/lon(1e7 int deg)."""
    msg = master.recv_match(type="GLOBAL_POSITION_INT", blocking=True, timeout=timeout)
    if msg is None:
        print(f"gcs_signed_correct: no GLOBAL_POSITION_INT within {timeout:.0f}s "
              "-> altitude-only takeoff-to-alt fallback", flush=True)
        return None, None
    return int(msg.lat), int(msg.lon)


def _return_to_alt(master: "mavutil.mavfile", alt_m: float) -> None:
    """현재 위치 위로 alt_m RELATIVE 고도로의 복귀를 명령한다(GUIDED hold).

    type_mask는 오직 position 필드만 활성화한다(vel/accel/yaw 비트는 ignore로 설정). Frame이
    RELATIVE_ALT이므로 alt_m은 home 위 높이(~30 m)이며, arducopter --home=...,30과 일치한다."""
    lat, lon = _current_global(master)
    # 0b0000_111_111_111_000 -> position(x,y,z) 사용, vel/accel/yaw/yaw_rate 무시.
    type_mask = 0b0000111111111000
    if lat is None or lon is None:
        # Fallback: 아직 position fix 없음 — GUIDED에서 takeoff-to-alt로 고도만 명령.
        master.mav.command_long_send(
            master.target_system, master.target_component,
            mavutil.mavlink.MAV_CMD_NAV_TAKEOFF, 0,
            0, 0, 0, 0, 0, 0, float(alt_m),
        )
        return
    master.mav.set_position_target_global_int_send(
        0, master.target_system, master.target_component,
        mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT,
        type_mask, lat, lon, float(alt_m),
        0, 0, 0, 0, 0, 0, 0, 0,
    )


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else "GUIDED"
    try:
        alt_m = float(argv[2]) if len(argv) > 2 else 30.0
    except ValueError:
        alt_m = 30.0

    master = _connect_signed()
    _wait_target(master)

    # (a) GUIDED로 권한을 되찾음(여기선 GUIDED만 배선; 다른 모드도 유사하게 매핑될 것)
    if mode.upper() == "GUIDED":
        _set_mode_guided(master, COPTER_GUIDED_CUSTOM_MODE)
    else:
        _set_mode_guided(master, COPTER_GUIDED_CUSTOM_MODE)
    time.sleep(SETTLE_S)

    # (b) 현재 위치 위로 ~30 m relative hover 고도로 물리적 복귀
    _return_to_alt(master, alt_m)
    time.sleep(SETTLE_S)
    # lossy UDP에 대한 신뢰성을 위해 한 번 재발행(둘 다 멱등 guided target)
    _return_to_alt(master, alt_m)

    print(f"gcs_signed_correct: signed GUIDED + return-to-{alt_m:.0f}m relative issued", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
